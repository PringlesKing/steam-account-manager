#pragma once

#include <string_view>

#include "core/account_store/account.hpp"

namespace sam::steam_bans {

// Account-private ban state from Steam Support's VAC/Game Bans page. This page is tied to
// the authenticated account session and can reflect a newly-applied CS2 restriction before
// the public GetPlayerBans Web API catches up.
struct PrivateBanStatus {
    bool ok = false;             // page was authenticated and understood
    bool good_standing = false;  // page explicitly says there are no VAC/game bans
    bool vac_banned = false;
    int vac_entries = 0;         // affected-game rows in the VAC section (not a Web API count)
    int game_ban_count = 0;      // game-developer ban rows visible on the support page
};

// Fetches https://help.steampowered.com/en/wizard/VacBans with the account's authenticated
// Steam web session, following only Steam-owned redirects.
PrivateBanStatus fetch_private_bans(const core::Account& a);

// Exposed for deterministic tests / troubleshooting of saved HTML.
PrivateBanStatus parse_private_bans(std::string_view html);

}  // namespace sam::steam_bans
