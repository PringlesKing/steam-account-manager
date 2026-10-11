#include "core/steam_api/web_api.hpp"

#include <chrono>

#include "core/http/client.hpp"
#include "core/http/url.hpp"

namespace sam::steam_api {

http::Response get(const WebApiConfig& cfg,
                   const std::string& iface,
                   const std::string& method,
                   const std::string& version,
                   std::map<std::string, std::string> params,
                   bool api_key_required,
                   bool bypass_cache) {
    if (api_key_required && !cfg.api_key.empty()) {
        params["key"] = cfg.api_key;
    }
    params["format"] = "json";
    if (bypass_cache) {
        // A unique query also avoids stale intermediary/CDN objects that may ignore
        // request cache headers. Steam Web API ignores unknown query parameters.
        const auto nonce = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        params["_sam_nocache"] = std::to_string(nonce);
    }

    const std::string base =
        cfg.host + "/" + iface + "/" + method + "/" + version + "/";
    const std::string url = http::build_url(base, params);

    http::Request req;
    req.method = http::Method::Get;
    req.url = url;
    req.timeout_seconds = cfg.timeout_seconds;
    req.bypass_cache = bypass_cache;
    return http::request(req);
}

}  // namespace sam::steam_api
