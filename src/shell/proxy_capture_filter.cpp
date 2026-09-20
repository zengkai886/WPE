#include "proxy_capture_filter.h"

namespace wpe::shell {

bool CaptureFilterAllowed(const CaptureFilterMatches& matches) noexcept {
    const bool any_enabled = matches.check_socket || matches.check_ip ||
        matches.check_port || matches.check_head || matches.check_data ||
        matches.check_length || matches.check_type;
    if (!any_enabled) return true;

    const bool any_match =
        (matches.check_socket && matches.socket_match) ||
        (matches.check_ip && matches.ip_match) ||
        (matches.check_port && matches.port_match) ||
        (matches.check_head && matches.head_match) ||
        (matches.check_data && matches.data_match) ||
        (matches.check_length && matches.length_match) ||
        (matches.check_type && matches.type_match);
    const bool all_match =
        (!matches.check_socket || matches.socket_match) &&
        (!matches.check_ip || matches.ip_match) &&
        (!matches.check_port || matches.port_match) &&
        (!matches.check_head || matches.head_match) &&
        (!matches.check_data || matches.data_match) &&
        (!matches.check_length || matches.length_match) &&
        (!matches.check_type || matches.type_match);

    // CheckNotShow=true is the original "hide matches" mode.  In the
    // normal "show matches" mode every enabled condition group is required;
    // packet-type alternatives are resolved before this function is called.
    return matches.not_show ? !any_match : all_match;
}

} // namespace wpe::shell
