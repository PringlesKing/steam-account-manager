#include "core/steam_bans/private_ban.hpp"

#include <algorithm>
#include <cctype>
#include <map>
#include <string>
#include <utility>

#include "core/http/client.hpp"
#include "core/log.hpp"

namespace sam::steam_bans {
namespace {

const char* kUserAgent =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

std::string trim(std::string s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
    return s;
}

std::pair<std::string, std::string> parse_set_cookie(const std::string& sc) {
    const std::string first = sc.substr(0, sc.find(';'));
    const auto eq = first.find('=');
    if (eq == std::string::npos) return {};
    return {trim(first.substr(0, eq)), trim(first.substr(eq + 1))};
}

std::string origin_of(const std::string& url) {
    const auto p = url.find("://");
    if (p == std::string::npos) return {};
    const auto slash = url.find('/', p + 3);
    return slash == std::string::npos ? url : url.substr(0, slash);
}

std::string host_of(const std::string& url) {
    const auto p = url.find("://");
    const std::size_t start = (p == std::string::npos) ? 0 : p + 3;
    const auto slash = url.find('/', start);
    return url.substr(start, (slash == std::string::npos ? url.size() : slash) - start);
}

std::string resolve_location(const std::string& base, const std::string& loc) {
    if (loc.rfind("http://", 0) == 0 || loc.rfind("https://", 0) == 0) return loc;
    if (loc.rfind("//", 0) == 0) return "https:" + loc;
    if (!loc.empty() && loc.front() == '/') return origin_of(base) + loc;
    return loc;
}

bool is_steam_host(const std::string& host) {
    auto ends_with = [&](const char* suffix) {
        const std::string s(suffix);
        return host.size() >= s.size() &&
               host.compare(host.size() - s.size(), s.size(), s) == 0;
    };
    return ends_with("steampowered.com") || ends_with("steamcommunity.com");
}

std::string lower_ascii(std::string_view in) {
    std::string out;
    out.reserve(in.size());
    for (unsigned char c : in) out.push_back(static_cast<char>(std::tolower(c)));
    return out;
}

int count_occurrences(std::string_view hay, std::string_view needle) {
    if (needle.empty()) return 0;
    int n = 0;
    std::size_t pos = 0;
    while ((pos = hay.find(needle, pos)) != std::string_view::npos) {
        ++n;
        pos += needle.size();
    }
    return n;
}

std::string_view section_between(std::string_view hay, std::string_view begin,
                                 std::string_view end) {
    const auto b = hay.find(begin);
    if (b == std::string_view::npos) return {};
    const std::size_t start = b + begin.size();
    auto e = end.empty() ? std::string_view::npos : hay.find(end, start);
    if (e == std::string_view::npos) e = hay.size();
    return hay.substr(start, e - start);
}

bool looks_logged_out(std::string_view lower) {
    return lower.find("<title>sign in") != std::string_view::npos ||
           lower.find("g_steamid = false") != std::string_view::npos ||
           lower.find("login.steampowered.com") != std::string_view::npos &&
               lower.find("vac and game bans for your account") == std::string_view::npos;
}

}  // namespace

PrivateBanStatus parse_private_bans(std::string_view html) {
    PrivateBanStatus out;
    if (html.empty()) return out;

    const std::string lower = lower_ascii(html);
    if (looks_logged_out(lower)) return out;

    const std::string_view good1 = "account in good vac standing";
    const std::string_view good2 = "you don't currently have any vac or game bans associated";
    if (lower.find(good1) != std::string::npos || lower.find(good2) != std::string::npos) {
        out.ok = true;
        out.good_standing = true;
        return out;
    }

    const std::string_view vac_heading = "bans applied by vac or valve anti-cheat";
    const std::string_view game_heading = "bans applied by the game developer";
    const bool has_vac_heading = lower.find(vac_heading) != std::string::npos;
    const bool has_game_heading = lower.find(game_heading) != std::string::npos;

    // An authenticated ban page always contains the account heading. Requiring it keeps a
    // transient/help error page from being interpreted as a clean account.
    const bool has_account_heading =
        lower.find("vac and game bans for your account") != std::string::npos;
    if (!has_account_heading && !has_vac_heading && !has_game_heading) return out;

    out.ok = true;

    if (has_vac_heading) {
        const std::string_view vac_section = section_between(
            lower, vac_heading,
            has_game_heading ? game_heading : std::string_view("read our faq on being vac banned"));
        int rows = count_occurrences(vac_section, "view help page");
        // Steam has changed the exact link markup over time. Presence of the ban heading is
        // already positive evidence, so never turn it into a false negative just because the
        // current HTML stopped spelling the link text exactly this way.
        if (rows == 0) rows = 1;
        out.vac_banned = true;
        out.vac_entries = rows;
    }

    if (has_game_heading) {
        const std::string_view game_section = section_between(
            lower, game_heading, std::string_view("game bans are not vac bans"));
        int rows = count_occurrences(game_section, "view help page");
        if (rows == 0) rows = 1;
        out.game_ban_count = rows;
    }

    return out;
}

PrivateBanStatus fetch_private_bans(const core::Account& a) {
    PrivateBanStatus out;
    if (a.steam_id_64 == 0 || a.session_id.empty() || a.steam_login_secure.empty()) {
        SAM_LOG_INFO(
            "ban_private: skipped steam_id={} sessionid_set={} steam_login_secure_set={}",
            a.steam_id_64, !a.session_id.empty(), !a.steam_login_secure.empty());
        return out;
    }

    std::map<std::string, std::string> jar{
        {"sessionid", a.session_id},
        {"steamLoginSecure", std::string(a.steam_login_secure.begin(), a.steam_login_secure.end())},
        {"Steam_Language", "english"},
    };
    if (!a.refresh_token.empty()) {
        jar["steamRefresh_steam"] = std::to_string(a.steam_id_64) + "%7C%7C" +
            std::string(a.refresh_token.begin(), a.refresh_token.end());
    }

    std::string url = "https://help.steampowered.com/en/wizard/VacBans";
    constexpr int kMaxHops = 10;
    http::Response resp;

    for (int hop = 0; hop <= kMaxHops; ++hop) {
        http::Request req;
        req.method = http::Method::Get;
        req.url = url;
        req.follow_redirects = false;
        req.bypass_cache = true;
        req.user_agent = kUserAgent;
        req.headers["Accept-Language"] = "en-US,en;q=0.9";
        req.headers["Accept"] =
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        req.headers["Cache-Control"] = "no-cache";
        req.headers["Pragma"] = "no-cache";
        for (const auto& [name, value] : jar) {
            req.cookies.push_back({name, value, host_of(url), "/", true, true});
        }

        resp = http::request(req);
        SAM_LOG_INFO("ban_private: hop {} steam_id={} status={} body={} bytes", hop,
                     a.steam_id_64, resp.status, resp.body.size());
        if (resp.transport_error) {
            SAM_LOG_WARN("ban_private: transport error for steam_id={}: {}", a.steam_id_64,
                         resp.error_message);
            return out;
        }

        for (const auto& sc : resp.set_cookies) {
            auto [name, value] = parse_set_cookie(sc);
            if (!name.empty() && !value.empty() && value != "deleted") jar[name] = std::move(value);
        }

        const bool redirect = resp.status >= 300 && resp.status < 400;
        if (!redirect) break;
        const auto it = resp.headers.find("location");
        if (it == resp.headers.end() || it->second.empty()) break;
        const std::string next = resolve_location(url, trim(it->second));
        if (!is_steam_host(host_of(next))) {
            SAM_LOG_WARN("ban_private: refusing off-Steam redirect to '{}'", next);
            return out;
        }
        url = next;
    }

    if (resp.status != 200) {
        SAM_LOG_WARN("ban_private: steam_id={} final status={}", a.steam_id_64, resp.status);
        return out;
    }

    out = parse_private_bans(resp.body);
    if (!out.ok) {
        SAM_LOG_WARN("ban_private: steam_id={} page was not recognized/authenticated",
                     a.steam_id_64);
        return out;
    }

    SAM_LOG_INFO(
        "ban_private: steam_id={} good={} vac={} vac_entries={} game_bans={}",
        a.steam_id_64, out.good_standing, out.vac_banned, out.vac_entries,
        out.game_ban_count);
    return out;
}

}  // namespace sam::steam_bans
