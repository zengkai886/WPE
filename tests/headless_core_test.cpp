#include "target/headless_core.h"
#include "common/ipc_session.h"
#include <Windows.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <iostream>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

namespace {
std::atomic<std::size_t> checks{0};
void Check(bool value, const char* message) {
    ++checks;
    if (!value) throw std::runtime_error(message);
}
template<class F> void Throws(F&& operation, const char* message) {
    bool threw = false;
    try { operation(); } catch (const wpe::ProtocolError&) { threw = true; }
    Check(threw, message);
}

class Cleanup final {
public:
    explicit Cleanup(std::function<void()> action) : action_(std::move(action)) {}
    ~Cleanup() { action_(); }
    Cleanup(const Cleanup&) = delete;
    Cleanup& operator=(const Cleanup&) = delete;
private:
    std::function<void()> action_;
};

wpe::Text T(const char16_t* text) { return std::u16string(text); }

class FakeHooks final : public wpe::IHookController {
public:
    wpe::WinsockSupport DetectWinsock(bool may_load) override {
        if (fail_detect) throw std::runtime_error("detect failed");
        if (may_load) ++load_detects; else ++passive_detects;
        return may_load ? wpe::WinsockSupport{true, true, true}
                        : wpe::WinsockSupport{false, true, false};
    }
    void ConfigureHookFlags(const std::array<bool, 12>& value) override {
        configured_flags = value;
        ++flag_updates;
    }
    void ConfigureSpeedMode(bool value) noexcept override {
        configured_speed = value;
        ++speed_updates;
    }
    void StartHook() override { ++starts; if (fail_start) throw std::runtime_error("start failed"); }
    void StopHook() override { ++stops; }
    std::optional<std::array<std::int64_t, 11>> LivePacketCounters() const noexcept override {
        if (!expose_live) return std::nullopt;
        return live_counters;
    }
    void ResetLivePacketCounters() noexcept override {
        live_counters.fill(0);
        ++live_resets;
    }
    std::atomic<int> passive_detects{0}, load_detects{0}, starts{0}, stops{0};
    std::atomic<int> flag_updates{0}, speed_updates{0}, live_resets{0};
    std::array<bool, 12> configured_flags{};
    std::array<std::int64_t, 11> live_counters{};
    bool configured_speed{};
    bool expose_live{};
    bool fail_detect{};
    bool fail_start{};
};

void ExpectOk(const wpe::ByteBuffer& response) {
    wpe::IpcReader reader(response);
    Check(reader.U8() == static_cast<std::uint8_t>(wpe::IpcStatus::Ok), "command status Ok");
    Check(reader.Remaining() == 0, "Ok response has no trailing bytes");
}

wpe::ByteBuffer SetConfig(wpe::HeadlessCore& core, wpe::ConfigKind kind,
                          const wpe::ByteBuffer& payload) {
    wpe::IpcWriter request;
    request.U8(static_cast<std::uint8_t>(kind));
    request.Bytes(payload);
    const auto bytes = request.ToArray();
    wpe::IpcReader reader(bytes);
    return core.HandleCommand(wpe::IpcCommand::SetConfig, reader);
}

wpe::ByteBuffer EmptyCommand(wpe::HeadlessCore& core, wpe::IpcCommand command) {
    const wpe::ByteBuffer empty;
    wpe::IpcReader reader(empty);
    return core.HandleCommand(command, reader);
}

void ConfigurationAndStats() {
    FakeHooks hooks;
    std::vector<wpe::ByteBuffer> events;
    wpe::HeadlessCore core(hooks, [&](wpe::ByteBuffer frame) { events.push_back(std::move(frame)); });

    wpe::IpcWriter hook_flags;
    for (int i = 0; i < 12; ++i) hook_flags.Bool((i % 2) == 0);
    ExpectOk(SetConfig(core, wpe::ConfigKind::HookFlags, hook_flags.ToArray()));
    auto config = core.Configuration();
    for (int i = 0; i < 12; ++i)
        Check(config.hook_flags[static_cast<std::size_t>(i)] == ((i % 2) == 0), "all hook flags decoded");
    Check(hooks.flag_updates == 1 && hooks.configured_flags == config.hook_flags,
          "hook flags published to production controller boundary");

    auto bad_flags = hook_flags.ToArray();
    bad_flags.push_back(9);
    Throws([&] { SetConfig(core, wpe::ConfigKind::HookFlags, bad_flags); },
           "configuration rejects trailing bytes");
    Check(core.Configuration().hook_flags == config.hook_flags,
          "rejected configuration does not partially mutate state");

    const auto filter_id = wpe::Guid::Parse("00112233-4455-6677-8899-aabbccddeeff");
    const auto execute_id = wpe::Guid::Parse("10213243-5465-7687-98a9-bacbdcedfe0f");
    wpe::IpcWriter filters;
    filters.I32(1); filters.Bool(true); filters.Guid_(filter_id); filters.Str(T(u"filter"));
    filters.Bool(true); filters.Str(T(u"AA")); filters.Bool(false); filters.Str(std::nullopt);
    filters.Bool(true); filters.Str(T(u"4-16")); filters.Bool(true); filters.Str(T(u"443"));
    filters.I32(2); filters.I32(3); filters.Bool(true); filters.I32(4); filters.Guid_(execute_id);
    for (int i = 0; i < 12; ++i) filters.Bool(i < 3);
    filters.I32(5); filters.Bool(true); filters.Bool(false); filters.I32(6);
    filters.Bool(true); filters.I32(7); filters.Str(T(u"1,2")); filters.I32(8);
    filters.Str(T(u"9")); filters.Str(T(u"10")); filters.Str(T(u"AB")); filters.Str(T(u"CD"));
    ExpectOk(SetConfig(core, wpe::ConfigKind::Filters, filters.ToArray()));
    config = core.Configuration();
    Check(config.filters.size() == 1, "filter snapshot row count");
    Check(config.filters[0].id == filter_id && config.filters[0].execute_id == execute_id,
          "filter GUID fields");
    Check(config.filters[0].functions[0] && config.filters[0].functions[2] &&
          !config.filters[0].functions[3], "filter function order");
    Check(config.filters[0].progression_count == 8 && config.filters[0].modify == T(u"CD"),
          "filter tail fields");

    const auto send_id = wpe::Guid::Parse("11111111-2222-3333-4444-555555555555");
    wpe::IpcWriter sends;
    sends.I32(1); sends.Bool(true); sends.Guid_(send_id); sends.Str(T(u"send"));
    sends.Bool(false); sends.I32(0); sends.I32(-9); sends.Str(T(u"notes"));
    sends.I32(1); sends.I32(77); sends.I32(9); sends.Str(T(u"from")); sends.Str(T(u"to"));
    sends.Bytes(wpe::ByteBuffer{0, 1, 255});
    ExpectOk(SetConfig(core, wpe::ConfigKind::Sends, sends.ToArray()));
    config = core.Configuration();
    Check(config.sends.size() == 1 && config.sends[0].packets.size() == 1, "send snapshot rows");
    Check(config.sends[0].loop_count == 1 && config.sends[0].loop_interval == 0,
          "send loop values normalized like original");
    Check(config.sends[0].packets[0].bytes == wpe::Bytes(wpe::ByteBuffer{0,1,255}),
          "send packet bytes retained");

    const auto robot_id = wpe::Guid::Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    wpe::IpcWriter robots;
    robots.I32(1); robots.Bool(true); robots.Guid_(robot_id); robots.Str(T(u"robot"));
    robots.I32(2); robots.I32(6); robots.Str(T(u"first")); robots.I32(7); robots.Str(std::nullopt);
    ExpectOk(SetConfig(core, wpe::ConfigKind::Robots, robots.ToArray()));
    config = core.Configuration();
    Check(config.robots.size() == 1 && config.robots[0].instructions.size() == 2,
          "robot snapshot instructions");
    Check(config.robots[0].instructions[1].content == std::nullopt, "robot null instruction preserved");

    wpe::IpcWriter runtime;
    runtime.Bool(true); runtime.I32(88); runtime.I32(2); runtime.I32(1); runtime.Bool(true);
    runtime.I32(99); runtime.I32(10); runtime.Str(T(u"a")); runtime.Str(T(u"b"));
    runtime.Bytes(wpe::ByteBuffer{4,5,6});
    ExpectOk(SetConfig(core, wpe::ConfigKind::Runtime, runtime.ToArray()));
    config = core.Configuration();
    Check(config.runtime.speed_mode && config.runtime.system_socket == 88, "runtime scalar fields");
    Check(config.runtime.selected_packet && config.runtime.selected_packet->socket == 99 &&
          config.runtime.selected_packet->bytes == wpe::Bytes(wpe::ByteBuffer{4,5,6}),
          "runtime selected packet");
    Check(hooks.speed_updates == 1 && hooks.configured_speed,
          "speed mode published to production controller boundary");

    core.SetFilterExecutionCount(filter_id, 101);
    core.SetSendCounts(send_id, 102, 103, 104);
    core.SetRobotExecutionCount(robot_id, 105);
    for (std::size_t i = 0; i < 6; ++i) core.SetFilterGlobal(i, 200 + static_cast<std::int64_t>(i));
    for (std::size_t i = 0; i < 11; ++i) core.SetPacketCounter(i, 300 + static_cast<std::int64_t>(i));
    core.SetListRunning(true, false);

    const auto stats = core.EncodeStatsEvent();
    wpe::IpcReader stats_reader(stats);
    Check(stats_reader.U8() == static_cast<std::uint8_t>(wpe::IpcEvent::Stats), "Stats event identity");
    Check(stats_reader.Bool() && !stats_reader.Bool(), "Stats running flags");
    Check(stats_reader.I32() == 1 && stats_reader.Guid_() == filter_id && stats_reader.I64() == 101,
          "Stats filter row");
    Check(stats_reader.I32() == 1 && stats_reader.Guid_() == send_id &&
          stats_reader.I64() == 102 && stats_reader.I64() == 103 && stats_reader.I64() == 104,
          "Stats send row");
    for (std::int64_t i = 0; i < 6; ++i) Check(stats_reader.I64() == 200 + i, "Stats filter globals order");
    Check(stats_reader.I32() == 1 && stats_reader.Guid_() == robot_id && stats_reader.I64() == 105,
          "Stats robot row");
    for (std::int64_t i = 0; i < 11; ++i) Check(stats_reader.I64() == 300 + i, "Stats packet counters order");
    Check(stats_reader.Remaining() == 0, "Stats exact v4 payload length");

    // Replacing snapshots carries target-owned execution counts by GUID.
    ExpectOk(SetConfig(core, wpe::ConfigKind::Filters, filters.ToArray()));
    ExpectOk(SetConfig(core, wpe::ConfigKind::Sends, sends.ToArray()));
    ExpectOk(SetConfig(core, wpe::ConfigKind::Robots, robots.ToArray()));
    config = core.Configuration();
    Check(config.filters[0].execution_count == 101, "filter count migrates by GUID");
    Check(config.sends[0].success_count == 103, "send counts migrate by GUID");
    Check(config.robots[0].execution_count == 105, "robot count migrates by GUID");

    wpe::IpcWriter reset;
    reset.U8(static_cast<std::uint8_t>(wpe::ResetWhat::FilterStats) |
             static_cast<std::uint8_t>(wpe::ResetWhat::SendCounts));
    auto reset_bytes = reset.ToArray();
    wpe::IpcReader reset_reader(reset_bytes);
    ExpectOk(core.HandleCommand(wpe::IpcCommand::ResetStats, reset_reader));
    config = core.Configuration();
    Check(config.filters[0].execution_count == 0 && config.sends[0].execution_count == 0 &&
          config.sends[0].success_count == 0 && config.robots[0].execution_count == 105,
          "ResetStats mask isolates item groups");
    const auto counters = core.Counters();
    Check(counters.filter_globals[5] == 0 && counters.packets[10] == 310,
          "ResetStats mask isolates global groups");

    hooks.expose_live = true;
    for (std::size_t i = 0; i < hooks.live_counters.size(); ++i)
        hooks.live_counters[i] = 400 + static_cast<std::int64_t>(i);
    Check(core.Counters().packets[10] == 410,
          "production live packet counters override test-local mirror");
    wpe::IpcWriter reset_packets;
    reset_packets.U8(static_cast<std::uint8_t>(wpe::ResetWhat::PacketCounters));
    const auto reset_packet_bytes = reset_packets.ToArray();
    wpe::IpcReader reset_packet_reader(reset_packet_bytes);
    ExpectOk(core.HandleCommand(wpe::IpcCommand::ResetStats, reset_packet_reader));
    Check(hooks.live_resets == 1 && core.Counters().packets[10] == 0,
          "packet reset is executed by the live hook counter owner");

    wpe::IpcWriter bad_reset; bad_reset.U8(16);
    auto bad_reset_bytes = bad_reset.ToArray();
    wpe::IpcReader bad_reset_reader(bad_reset_bytes);
    Throws([&] { core.HandleCommand(wpe::IpcCommand::ResetStats, bad_reset_reader); },
           "ResetStats rejects unknown bits");
}

void LifecycleOverRealPipes() {
    std::ostringstream session;
    session << "e123456789abcdef01234567" << std::hex << std::setw(8)
            << std::setfill('0') << GetCurrentProcessId();
    const auto id = session.str();
    Check(id.size() == 32, "generated pipe session length");
    std::mutex event_mutex;
    std::condition_variable event_ready;
    std::vector<wpe::ByteBuffer> events;
    wpe::ShellSessionOptions shell_options;
    shell_options.heartbeat_interval = 20ms;
    wpe::ShellIpcSession shell(id, {}, [&](wpe::ByteBuffer event) {
        {
            std::lock_guard lock(event_mutex);
            events.push_back(std::move(event));
        }
        event_ready.notify_all();
    }, {}, shell_options);
    wpe::TargetSessionOptions target_options;
    target_options.heartbeat_timeout = 200ms;
    target_options.watchdog_poll = 5ms;
    wpe::TargetIpcSession target(id, 2000, target_options);
    shell.Accept(2000);

    FakeHooks hooks;
    wpe::HeadlessCoreOptions core_options;
    core_options.stats_interval = 25ms;
    wpe::HeadlessCore core(hooks, [&](wpe::ByteBuffer event) { target.SendEventFrame(event); }, core_options);
    std::thread target_thread([&] {
        target.Run([&](wpe::IpcCommand command, wpe::IpcReader& reader) {
            return core.HandleCommand(command, reader);
        }, [&] { core.Shutdown(); }, [&] { core.OnHello(); }, [&] { core.Shutdown(); });
    });
    Cleanup cleanup([&] {
        shell.Stop();
        if (target_thread.joinable()) target_thread.join();
        core.Shutdown();
        target.Stop();
    });
    shell.Start();
    Check(hooks.passive_detects.load() == 1, "Hello passively detects loaded Winsock modules");
    {
        std::unique_lock lock(event_mutex);
        event_ready.wait_for(lock, 2s, [&] { return !events.empty(); });
        Check(!events.empty(), "Hello emitted HookState through real event pipe");
        wpe::IpcReader reader(events.front());
        Check(reader.U8() == static_cast<std::uint8_t>(wpe::IpcEvent::HookState) &&
              !reader.Bool() && !reader.Bool() && reader.Bool() && !reader.Bool(),
              "Hello HookState carries passive support flags");
        Check(reader.Remaining() == 0, "HookState exact payload length");
    }

    wpe::IpcWriter start; start.U8(static_cast<std::uint8_t>(wpe::IpcCommand::StartHook));
    shell.CallVoid(start.ToArray());
    Check(core.HookInstalled() && hooks.starts.load() == 1 && hooks.load_detects.load() == 1,
          "StartHook runs controller after load-capable detection");
    shell.CallVoid(start.ToArray());
    Check(hooks.starts.load() == 1, "StartHook is idempotent");

    {
        std::unique_lock lock(event_mutex);
        event_ready.wait_for(lock, 2s, [&] {
            bool saw_stats = false;
            bool saw_on = false;
            for (const auto& event : events) {
                wpe::IpcReader reader(event);
                const auto type = static_cast<wpe::IpcEvent>(reader.U8());
                if (type == wpe::IpcEvent::Stats) saw_stats = true;
                if (type == wpe::IpcEvent::HookState && reader.Bool()) saw_on = true;
            }
            return saw_stats && saw_on;
        });
    }

    // Detach must acknowledge first; target exit cleanup then stops the installed hook once.
    shell.Detach();
    target_thread.join();
    Check(target.Detached(), "real target session observed Detach");
    Check(!core.HookInstalled() && hooks.stops.load() == 1,
          "Detach exit cleanup stops installed hook exactly once");
    Check(hooks.load_detects.load() == 1, "idempotent StartHook does not re-detect");

    std::lock_guard lock(event_mutex);
    bool saw_stats = false, saw_on = false, saw_off = false;
    for (const auto& event : events) {
        wpe::IpcReader reader(event);
        const auto type = static_cast<wpe::IpcEvent>(reader.U8());
        if (type == wpe::IpcEvent::Stats) saw_stats = true;
        if (type == wpe::IpcEvent::HookState) {
            const auto on = reader.Bool();
            saw_on = saw_on || on;
            saw_off = saw_off || !on;
        }
    }
    Check(saw_stats, "1 Hz-equivalent stats ticker emitted over real event pipe");
    Check(saw_on && saw_off, "start and detach cleanup emitted both hook states");
}

void FatalDetectionEvent() {
    FakeHooks hooks;
    hooks.fail_detect = true;
    std::vector<wpe::ByteBuffer> events;
    wpe::HeadlessCoreOptions options;
    options.stats_interval = 1s;
    wpe::HeadlessCore core(hooks, [&](wpe::ByteBuffer event) { events.push_back(std::move(event)); }, options);
    core.OnHello();
    Check(events.size() >= 2, "failed detection emits Fatal and HookState");
    wpe::IpcReader fatal(events[0]);
    Check(fatal.U8() == static_cast<std::uint8_t>(wpe::IpcEvent::Fatal), "Fatal event identity");
    Check(fatal.Str().has_value() && fatal.Remaining() == 0, "Fatal event text payload");
    core.Shutdown();
}
} // namespace

int main() {
    try {
        ConfigurationAndStats();
        LifecycleOverRealPipes();
        FatalDetectionEvent();
        std::cout << "PASS: " << checks.load()
                  << " target-core checks; all snapshots, stats/reset, hook states, fatal and detach cleanup\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
