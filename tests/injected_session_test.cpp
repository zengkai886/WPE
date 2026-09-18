#include "shell/process_injector.h"
#include "common/ipc_codec.h"
#include "common/ipc_session.h"
#include "common/packet_frame.h"
#include <Windows.h>
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <vector>

using namespace std::chrono_literals;

namespace {
std::size_t checks{};
void Check(bool value, const char* message) {
    ++checks;
    if (!value) throw std::runtime_error(message);
}
template<class F> void Throws(F&& action, const char* message) {
    bool threw = false;
    try { action(); } catch (const wpe::ProtocolError&) { threw = true; }
    Check(threw, message);
}

std::string SessionId() {
    std::ostringstream out;
    out << std::hex << std::setfill('0')
        << std::setw(8) << GetCurrentProcessId()
        << std::setw(8) << GetTickCount()
        << std::setw(8) << GetCurrentThreadId()
        << std::setw(8) << (GetTickCount() ^ 0x5a17c3e9U);
    return out.str();
}

struct ProcessCleanup final {
    HANDLE handle{};
    ~ProcessCleanup() {
        if (!handle) return;
        (void)TerminateProcess(handle, ERROR_CANCELLED);
        (void)WaitForSingleObject(handle, 3000);
    }
};

struct HandleCleanup final {
    HANDLE value{};
    ~HandleCleanup() { if (value) CloseHandle(value); }
};

bool ContainsHookState(const std::vector<wpe::ByteBuffer>& events, bool wanted) {
    for (const auto& bytes : events) {
        try {
            wpe::IpcReader event(bytes);
            if (event.U8() == static_cast<std::uint8_t>(wpe::IpcEvent::HookState) &&
                event.Bool() == wanted) return true;
        } catch (...) {}
    }
    return false;
}

bool ContainsPacket(const std::vector<wpe::ByteBuffer>& frames, std::uint8_t type,
                    std::string_view expected) {
    for (const auto& frame : frames) {
        try {
            const auto packet = wpe::PacketFrame::Decode(frame);
            if (packet.packet_type != type || !packet.raw || packet.raw->size() != expected.size())
                continue;
            if (std::equal(packet.raw->begin(), packet.raw->end(), expected.begin()) &&
                packet.modified == packet.raw && packet.from && packet.to &&
                !packet.from->empty() && !packet.to->empty()) return true;
        } catch (...) {}
    }
    return false;
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc != 4) throw std::runtime_error("target, production hook and probe DLL paths required");
        const std::filesystem::path target = argv[1];
        const std::filesystem::path hook = argv[2];
        const std::filesystem::path probe = argv[3];
        const auto session_id = SessionId();

        const std::wstring event_suffix = std::to_wstring(GetCurrentProcessId()) + L"-" +
                                          std::to_wstring(GetTickCount64());
        const std::wstring start_name = L"Local\\WPE64-NetworkStart-" + event_suffix;
        const std::wstring done_name = L"Local\\WPE64-NetworkDone-" + event_suffix;
        HandleCleanup start_event{CreateEventW(nullptr, TRUE, FALSE, start_name.c_str())};
        HandleCleanup done_event{CreateEventW(nullptr, TRUE, FALSE, done_name.c_str())};
        if (!start_event.value || !done_event.value)
            throw std::runtime_error("network test events could not be created");

        std::mutex event_mutex;
        std::condition_variable event_ready;
        std::vector<wpe::ByteBuffer> events;
        std::mutex packet_mutex;
        std::condition_variable packet_ready;
        std::vector<wpe::ByteBuffer> packets;
        wpe::ShellIpcSession shell(session_id, [&](wpe::ByteBuffer packet) {
            {
                std::lock_guard lock(packet_mutex);
                packets.push_back(std::move(packet));
            }
            packet_ready.notify_all();
        }, [&](wpe::ByteBuffer event) {
            {
                std::lock_guard lock(event_mutex);
                events.push_back(std::move(event));
            }
            event_ready.notify_all();
        }, {}, wpe::ShellSessionOptions{50ms});

        const std::wstring target_arguments = L"\"" + start_name + L"\" \"" + done_name + L"\"";
        auto child = wpe::shell::ProcessInjector::LaunchSuspended(target, target_arguments);
        ProcessCleanup cleanup{child.ProcessHandle()};
        child.Resume();
        Check(WaitForSingleObject(child.ProcessHandle(), 0) == WAIT_TIMEOUT,
              "session target is running");

        wpe::shell::InjectionOptions options{session_id, 5000, false};
        auto missing_shell = options;
        missing_shell.session = "11111111222222223333333344444444";
        missing_shell.connect_timeout_ms = 100;
        wpe::shell::ProcessInjector::InjectAndStart(child.Pid(), hook, missing_shell, 2s);
        ++checks;
        Sleep(300); // the target worker must self-shutdown when no shell owns those pipes
        Throws([&] {
            auto invalid = options;
            invalid.session = "not-a-guid";
            wpe::shell::ProcessInjector::InjectAndStart(child.Pid(), hook, invalid, 2s);
        }, "invalid session rejected before bootstrap");
        Throws([&] {
            wpe::shell::ProcessInjector::InjectAndStart(child.Pid(), probe, options, 2s);
        }, "DLL without WpeStart export rejected");

        wpe::shell::ProcessInjector::InjectAndStart(child.Pid(), hook, options, 5s);
        shell.Accept(5000);
        shell.Start();
        Check(shell.State() == wpe::IpcLinkState::Attached, "injected target session attached");
        Check(shell.TargetPid() == static_cast<std::int32_t>(child.Pid()),
              "Hello reports injected target PID");
        Check(shell.TargetIs64() == (sizeof(void*) == 8), "Hello reports target architecture");

        {
            std::unique_lock lock(event_mutex);
            Check(event_ready.wait_for(lock, 2s, [&] { return !events.empty(); }),
                  "injected target emitted initial HookState");
            wpe::IpcReader event(events.front());
            Check(event.U8() == static_cast<std::uint8_t>(wpe::IpcEvent::HookState),
                  "initial injected event type");
            Check(!event.Bool(), "hook state is off before StartHook");
            (void)event.Bool(); (void)event.Bool(); (void)event.Bool();
            Check(event.Remaining() == 0, "initial HookState has exact v4 fields");
        }

        wpe::IpcWriter flags;
        for (int i = 0; i < 12; ++i) flags.Bool((i % 2) == 0);
        wpe::IpcWriter set_config;
        set_config.U8(static_cast<std::uint8_t>(wpe::IpcCommand::SetConfig));
        set_config.U8(static_cast<std::uint8_t>(wpe::ConfigKind::HookFlags));
        set_config.Bytes(flags.ToArray());
        shell.CallVoid(set_config.ToArray());
        ++checks;

        wpe::IpcWriter start_hook;
        start_hook.U8(static_cast<std::uint8_t>(wpe::IpcCommand::StartHook));
        shell.CallVoid(start_hook.ToArray());
        ++checks;
        {
            std::unique_lock lock(event_mutex);
            Check(event_ready.wait_for(lock, 2s, [&] { return ContainsHookState(events, true); }),
                  "production target emitted HookState(true)");
        }
        Check(SetEvent(start_event.value) != FALSE, "target network scenario released");
        Check(WaitForSingleObject(done_event.value, 3000) == WAIT_OBJECT_0,
              "target completed real network round trip");
        {
            std::unique_lock lock(packet_mutex);
            Check(packet_ready.wait_for(lock, 3s, [&] {
                return ContainsPacket(packets, 1, "cross-process") &&
                       ContainsPacket(packets, 5, "cross-process");
            }), "injected DLL returned real send/recv frames through pkt pipe");
        }
        Throws([&] {
            wpe::shell::ProcessInjector::InjectAndStart(child.Pid(), hook, options, 2s);
        }, "second target worker rejected while the first session is active");

        shell.Detach();
        Check(shell.State() == wpe::IpcLinkState::Disconnected,
              "injected target detached cleanly");
        Check(WaitForSingleObject(child.ProcessHandle(), 0) == WAIT_TIMEOUT,
              "detaching DLL session does not terminate host process");

        std::cout << "PASS: " << checks
                  << " injected-session checks; production DLL, MinHook Winsock capture, real pkt IPC and detach\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
