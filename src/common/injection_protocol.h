#pragma once

#include <cstdint>

namespace wpe {

inline constexpr std::uint32_t InjectionBootstrapMagic = 0x31455057U; // "WPE1"
inline constexpr std::uint16_t InjectionBootstrapVersion = 1;
inline constexpr std::uint32_t InjectionFlagSuspendedLaunch = 1U;

#pragma pack(push, 1)
struct InjectionBootstrapV1 {
    std::uint32_t magic{InjectionBootstrapMagic};
    std::uint16_t version{InjectionBootstrapVersion};
    std::uint16_t size{sizeof(InjectionBootstrapV1)};
    std::uint32_t connect_timeout_ms{5000};
    std::uint32_t flags{};
    // Original ShellLink uses Guid.ToString("N") (32 ASCII hex digits), while
    // diagnostics also accept the 36-character dashed form.
    char session[37]{};
};
#pragma pack(pop)

static_assert(sizeof(InjectionBootstrapV1) == 53);

enum class InjectionStartResult : std::uint32_t {
    Ok = 0,
    NullParameters = 1,
    InvalidMagic = 2,
    InvalidVersion = 3,
    InvalidSize = 4,
    InvalidSession = 5,
    InvalidTimeout = 6,
    WorkerStartFailed = 7,
    WorkerAlreadyRunning = 8,
};

} // namespace wpe
