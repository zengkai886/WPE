#pragma once

#include "common/ipc_protocol.h"
#include "common/ipc_codec.h"
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <thread>
#include <utility>
#include <vector>

namespace wpe {

struct FilterSnapshot;
enum class FilterExecuteType : std::int32_t {
    Send = 0,
    Robot = 1,
    None = 2,
    Filter = 3,
    WareHouse = 4,
};
struct FilterRuntimeStats {
    std::vector<std::pair<Guid, std::int64_t>> filters;
    std::array<std::int64_t, 6> globals{};
};

// A filter can request a target-local send or an event-backed warehouse write.
// The trigger is produced on the detour thread and consumed without touching
// shell/database state. Robot triggers intentionally have no runtime callback
// in this build.
struct FilterTrigger {
    FilterExecuteType type{FilterExecuteType::None};
    Guid id{};
    ByteBuffer bytes;
};

struct WinsockSupport {
    bool ws1{};
    bool ws2{};
    bool msws{};
    bool operator==(const WinsockSupport&) const = default;
};

struct ReplayPacketSnapshot;

struct SocketInfo {
    Text from;
    Text to;
};

class IHookController {
public:
    using SendTrigger = std::function<void(const Guid&)>;
    using StoreTrigger = std::function<void(const Guid&, std::span<const std::uint8_t>)>;
    virtual ~IHookController() = default;
    virtual WinsockSupport DetectWinsock(bool may_load) = 0;
    // Configuration is published before StartHook. Production controllers
    // consume these without reaching back into HeadlessCore from a detour.
    virtual void ConfigureHookFlags(const std::array<bool, 12>&) {}
    virtual void ConfigureSpeedMode(bool) noexcept {}
    virtual void ConfigureFilters(const std::vector<FilterSnapshot>&,
                                  std::int32_t, bool) {}
    virtual void ConfigureFilterTriggers(SendTrigger, StoreTrigger) {}
    virtual void StartHook() = 0;
    virtual void StopHook() = 0;
    // A production controller owns lock-free packet counters because they are
    // incremented on arbitrary target Winsock threads. Test/future controllers
    // may keep using HeadlessCore's local counters by returning nullopt.
    virtual std::optional<std::array<std::int64_t, 11>> LivePacketCounters() const noexcept {
        return std::nullopt;
    }
    virtual void ResetLivePacketCounters() noexcept {}
    virtual std::optional<FilterRuntimeStats> LiveFilterStats() const noexcept {
        return std::nullopt;
    }
    virtual void ResetLiveFilterStats() noexcept {}
    // Active replay and endpoint lookup must execute in the target process:
    // SOCKET values are process-local handles. Implementations return the
    // original application's bool/empty-string semantics rather than throwing
    // for an invalid or already-closed socket.
    virtual bool SendPacket(const ReplayPacketSnapshot&) { return false; }
    virtual SocketInfo GetSocketInfo(std::int32_t) { return {Text{u""}, Text{u""}}; }
};

struct FilterSnapshot {
    bool enabled{};
    Guid id{};
    Text name;
    bool appoint_header{}; Text header;
    bool appoint_socket{}; Text socket;
    bool appoint_length{}; Text length;
    bool appoint_port{}; Text port;
    std::int32_t mode{};
    std::int32_t action{};
    bool execute{};
    std::int32_t execute_type{};
    Guid execute_id{};
    std::array<bool, 12> functions{};
    std::int32_t start_from{};
    bool progression_done{};
    bool progression_continuous{};
    std::int32_t progression_step{};
    bool progression_carry{};
    std::int32_t progression_carry_number{};
    Text progression_position;
    std::int32_t progression_count{};
    Text exclude_position;
    Text random_position;
    Text search;
    Text modify;
    std::int64_t execution_count{};
};

struct ReplayPacketSnapshot {
    std::int32_t socket{};
    std::int32_t packet_type{};
    Text from;
    Text to;
    Bytes bytes;
};

struct SendSnapshot {
    bool enabled{};
    Guid id{};
    Text name;
    bool system_socket{};
    std::int32_t loop_count{};
    std::int32_t loop_interval{};
    Text notes;
    std::vector<ReplayPacketSnapshot> packets;
    std::int64_t execution_count{};
    std::int64_t success_count{};
    std::int64_t fail_count{};
};

struct RobotInstructionSnapshot {
    std::int32_t type{};
    Text content;
};

struct RobotSnapshot {
    bool enabled{};
    Guid id{};
    Text name;
    std::vector<RobotInstructionSnapshot> instructions;
    std::int64_t execution_count{};
};

struct RuntimeSnapshot {
    bool speed_mode{};
    std::int32_t system_socket{};
    std::int32_t list_execute{};
    std::int32_t filter_execute{};
    std::optional<ReplayPacketSnapshot> selected_packet;
};

struct TargetConfigurationSnapshot {
    std::array<bool, 12> hook_flags{};
    std::vector<FilterSnapshot> filters;
    RuntimeSnapshot runtime;
    std::vector<SendSnapshot> sends;
    std::vector<RobotSnapshot> robots;
};

struct TargetCounters {
    bool send_list_running{};
    bool robot_list_running{};
    std::array<std::int64_t, 6> filter_globals{};
    std::array<std::int64_t, 11> packets{};
};

struct HeadlessCoreOptions {
    std::chrono::milliseconds stats_interval{1000};
};

// Target-side owner for protocol state. It performs no file, UI or network I/O;
// all target-specific hook operations are isolated behind IHookController.
class HeadlessCore final {
public:
    using EventSender = std::function<void(ByteBuffer)>;

    HeadlessCore(IHookController& hooks, EventSender event_sender,
                 HeadlessCoreOptions options = {});
    ~HeadlessCore();
    HeadlessCore(const HeadlessCore&) = delete;
    HeadlessCore& operator=(const HeadlessCore&) = delete;

    void OnHello();
    ByteBuffer HandleCommand(IpcCommand command, IpcReader& reader);
    void Shutdown() noexcept;

    [[nodiscard]] bool HookInstalled() const;
    [[nodiscard]] WinsockSupport Support() const;
    [[nodiscard]] TargetConfigurationSnapshot Configuration() const;
    [[nodiscard]] TargetCounters Counters() const;

    // Execution engines use these methods to publish their actual target-side
    // counts. Snapshot replacement preserves per-item counts by GUID.
    void SetFilterExecutionCount(const Guid& id, std::int64_t count);
    void SetSendCounts(const Guid& id, std::int64_t executed,
                       std::int64_t succeeded, std::int64_t failed);
    void SetRobotExecutionCount(const Guid& id, std::int64_t count);
    void SetFilterGlobal(std::size_t index, std::int64_t count);
    void SetPacketCounter(std::size_t index, std::int64_t count);
    void SetListRunning(bool sends, bool robots);
    ByteBuffer EncodeStatsEvent() const;

private:
    void ApplyConfig(ConfigKind kind, std::span<const std::uint8_t> payload);
    void StartHook(IpcReader& reader);
    void StopHook(IpcReader& reader);
    void StartSend(IpcReader& reader);
    void StartSendById(const Guid& id) noexcept;
    void StartSendList();
    bool LaunchSendWorker(std::vector<SendSnapshot> sends, RuntimeSnapshot runtime) noexcept;
    void StartSendWorker(std::vector<SendSnapshot> sends, RuntimeSnapshot runtime);
    void StopSendList(IpcReader& reader);
    void AddSendCount(const Guid& id, bool succeeded) noexcept;
    void ResetStats(IpcReader& reader);
    void Emit(ByteBuffer event) noexcept;
    // Publish a low-latency snapshot whenever an execution lifecycle changes.
    // The periodic stats loop remains as a heartbeat, but UI state must not
    // wait for that interval after a start/stop or a completed send list.
    void EmitStatsSnapshot() noexcept;
    void EmitStoreAdded(const Guid& id, std::span<const std::uint8_t> bytes) noexcept;
    void EmitHookState(bool on) noexcept;
    void EmitFatal(std::string_view message) noexcept;
    void StatsLoop() noexcept;

    IHookController& hooks_;
    EventSender event_sender_;
    HeadlessCoreOptions options_;
    mutable std::mutex mutex_;
    // Serializes send-thread ownership transitions with Shutdown/Stop. The
    // worker itself never takes this lock, so joining while it is held is safe.
    mutable std::mutex send_lifecycle_mutex_;
    std::condition_variable stop_wait_;
    TargetConfigurationSnapshot config_;
    TargetCounters counters_;
    WinsockSupport support_;
    bool hook_installed_{};
    bool started_{};
    bool stopping_{};
    std::atomic<bool> send_stop_{};
    std::condition_variable send_wait_;
    std::thread send_thread_;
    std::thread stats_thread_;
};

} // namespace wpe
