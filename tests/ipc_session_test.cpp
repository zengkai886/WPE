#include "common/ipc_session.h"
#include <Windows.h>
#include <atomic>
#include <chrono>
#include <iostream>
#include <mutex>
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

void HappyLifecycle() {
    const std::string id = "a123456789abcdef0123456789abcdef";
    std::atomic<int> packets{0}, events{0}, commands{0};
    std::atomic<wpe::IpcLinkState> last_state{wpe::IpcLinkState::Idle};
    wpe::ShellSessionOptions shell_options;
    shell_options.heartbeat_interval = 20ms;
    wpe::ShellIpcSession shell(id,
        [&](wpe::ByteBuffer frame) { Check(frame == wpe::ByteBuffer({1,2,3,4}), "packet callback bytes"); ++packets; },
        [&](wpe::ByteBuffer frame) { Check(frame == wpe::ByteBuffer({7,8,9}), "event callback bytes"); ++events; },
        [&](wpe::IpcLinkState state) { last_state.store(state); }, shell_options);

    wpe::TargetSessionOptions target_options;
    target_options.heartbeat_timeout = 120ms;
    target_options.watchdog_poll = 5ms;
    wpe::TargetIpcSession target(id, 2000, target_options);
    shell.Accept(2000);
    std::thread target_thread([&] {
        target.Run([&](wpe::IpcCommand command, wpe::IpcReader& reader) {
            ++commands;
            Check(command == wpe::IpcCommand::StopHook, "custom command identity");
            Check(reader.Remaining() == 0, "custom command consumed");
            return wpe::IpcOk();
        });
    });
    shell.Start();
    Check(shell.State() == wpe::IpcLinkState::Attached, "shell attached after Hello");
    Check(shell.TargetPid() == static_cast<std::int32_t>(GetCurrentProcessId()), "Hello target PID");
    Check(shell.TargetIs64() == (sizeof(void*) == 8), "Hello target architecture");
    Check(last_state.load() == wpe::IpcLinkState::Attached, "attached state callback");

    target.SendPacketFrame(wpe::ByteBuffer{1,2,3,4});
    target.SendEventFrame(wpe::ByteBuffer{7,8,9});
    for (int i = 0; i < 200 && (packets.load() != 1 || events.load() != 1); ++i) Sleep(1);
    Check(packets.load() == 1 && events.load() == 1, "packet and event receiver threads delivered frames");

    wpe::IpcWriter command;
    command.U8(static_cast<std::uint8_t>(wpe::IpcCommand::StopHook));
    std::vector<std::thread> callers;
    for (int i = 0; i < 8; ++i) callers.emplace_back([&] { shell.CallVoid(command.ToArray()); });
    for (auto& caller : callers) caller.join();
    Check(commands.load() == 8, "control requests serialized without crossed replies");
    Sleep(160); // regular Ping commands must keep the target watchdog alive
    Check(!target.TimedOut(), "shell heartbeat keeps target alive");

    shell.Detach();
    target_thread.join();
    Check(target.Detached(), "target observed Detach");
    Check(!target.TimedOut(), "Detach is not a heartbeat timeout");
    Check(shell.State() == wpe::IpcLinkState::Disconnected, "shell stopped after acknowledged Detach");
}

void VersionMismatch() {
    const std::string id = "b123456789abcdef0123456789abcdef";
    wpe::ShellIpcSession shell(id, {}, {});
    wpe::TargetSessionOptions options;
    options.protocol_version = 3;
    options.heartbeat_timeout = 500ms;
    options.watchdog_poll = 5ms;
    wpe::TargetIpcSession target(id, 2000, options);
    shell.Accept(2000);
    std::thread target_thread([&] { target.Run({}); });
    Throws([&] { shell.Start(); }, "Hello rejects a different protocol version");
    shell.Stop();
    target_thread.join();
    Check(shell.State() == wpe::IpcLinkState::Disconnected, "version failure disconnects shell");
}

void AnyCommandRefreshesHeartbeat() {
    const std::string id = "c123456789abcdef0123456789abcdef";
    wpe::ShellSessionOptions shell_options;
    shell_options.heartbeat_interval = 2s; // do not let Ping mask the test
    wpe::ShellIpcSession shell(id, {}, {}, {}, shell_options);
    wpe::TargetSessionOptions target_options;
    target_options.heartbeat_timeout = 90ms;
    target_options.watchdog_poll = 5ms;
    wpe::TargetIpcSession target(id, 2000, target_options);
    shell.Accept(2000);
    std::atomic<int> timeout_callbacks{0};
    std::thread target_thread([&] {
        target.Run([](wpe::IpcCommand, wpe::IpcReader&) { return wpe::IpcOk(); },
                   [&] { ++timeout_callbacks; });
    });
    shell.Start();
    wpe::IpcWriter request;
    request.U8(static_cast<std::uint8_t>(wpe::IpcCommand::StopHook));
    for (int i = 0; i < 4; ++i) {
        Sleep(45);
        shell.CallVoid(request.ToArray());
        Check(!target.TimedOut(), "ordinary command refreshed heartbeat deadline");
    }
    for (int i = 0; i < 300 && !target.TimedOut(); ++i) Sleep(1);
    Check(target.TimedOut(), "target times out after all shell commands stop");
    Check(timeout_callbacks.load() == 1, "timeout cleanup callback runs exactly once");
    target_thread.join();
    shell.Stop();
}

void ErrorReply() {
    const std::string id = "d123456789abcdef0123456789abcdef";
    wpe::ShellSessionOptions shell_options;
    shell_options.heartbeat_interval = 1s;
    wpe::ShellIpcSession shell(id, {}, {}, {}, shell_options);
    wpe::TargetSessionOptions target_options;
    target_options.heartbeat_timeout = 500ms;
    target_options.watchdog_poll = 5ms;
    wpe::TargetIpcSession target(id, 2000, target_options);
    shell.Accept(2000);
    std::thread target_thread([&] {
        target.Run([](wpe::IpcCommand, wpe::IpcReader&) { return wpe::IpcError("deliberate"); });
    });
    shell.Start();
    wpe::IpcWriter request;
    request.U8(static_cast<std::uint8_t>(wpe::IpcCommand::StartHook));
    Throws([&] { shell.CallVoid(request.ToArray()); }, "target Error response becomes command failure");
    shell.Detach();
    target_thread.join();
}
} // namespace

int main() {
    try {
        HappyLifecycle();
        VersionMismatch();
        AnyCommandRefreshesHeartbeat();
        ErrorReply();
        std::cout << "PASS: " << checks.load()
                  << " real IPC session checks; Hello/version, serialized calls, pkt/evt, heartbeat, timeout, error and Detach lifecycle\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
