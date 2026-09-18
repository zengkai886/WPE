#pragma once

#include "headless_core.h"
#include "common/ipc_codec.h"
#include <functional>
#include <memory>

namespace wpe {

// Production WinSock detour owner. Detours only copy immutable packet bytes,
// update atomics and enqueue into the bounded PacketRing. Address lookup,
// frame encoding and named-pipe writes run on the dedicated writer thread.
class WinsockHookController final : public IHookController {
public:
    using FrameSender = std::function<void(ByteBuffer)>;

    WinsockHookController(bool suspended_launch, FrameSender packet_sender,
                          FrameSender event_sender = {});
    ~WinsockHookController() override;
    WinsockHookController(const WinsockHookController&) = delete;
    WinsockHookController& operator=(const WinsockHookController&) = delete;

    WinsockSupport DetectWinsock(bool may_load) override;
    void ConfigureHookFlags(const std::array<bool, 12>& flags) override;
    void ConfigureSpeedMode(bool enabled) noexcept override;
    void ConfigureFilters(const std::vector<FilterSnapshot>& filters,
                          std::int32_t execute_mode, bool speed_mode) override;
    void StartHook() override;
    void StopHook() override;
    std::optional<std::array<std::int64_t, 11>> LivePacketCounters() const noexcept override;
    void ResetLivePacketCounters() noexcept override;
    std::optional<FilterRuntimeStats> LiveFilterStats() const noexcept override;
    void ResetLiveFilterStats() noexcept override;
    bool SendPacket(const ReplayPacketSnapshot& packet) override;
    SocketInfo GetSocketInfo(std::int32_t socket) override;

    [[nodiscard]] std::size_t RegisteredHookCount() const noexcept;
    [[nodiscard]] std::uint32_t InFlightDetourCount() const noexcept;
    [[nodiscard]] std::uint64_t DroppedPacketCount() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace wpe
