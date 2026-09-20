#pragma once

namespace wpe::shell {

// The native proxy computes each individual match (header, address, type,
// etc.) before applying this small, shared decision rule.  Keeping the rule
// independent from Winsock and WebView makes the original C# semantics
// regression-testable.
struct CaptureFilterMatches {
    bool not_show{};
    bool check_socket{};
    bool socket_match{};
    bool check_ip{};
    bool ip_match{};
    bool check_port{};
    bool port_match{};
    bool check_head{};
    bool head_match{};
    bool check_data{};
    bool data_match{};
    bool check_length{};
    bool length_match{};
    bool check_type{};
    bool type_match{};
};

[[nodiscard]] bool CaptureFilterAllowed(const CaptureFilterMatches& matches) noexcept;

} // namespace wpe::shell
