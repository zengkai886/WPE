#include "shell/target_link.h"
#include "common/ipc_codec.h"
#include <Windows.h>
#include <condition_variable>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std::chrono_literals;

namespace {
std::size_t checks{};

void Check(bool value, const char* message) {
    ++checks;
    if (!value) throw std::runtime_error(message);
}

class Handle final {
public:
    explicit Handle(HANDLE value = nullptr) noexcept : value_(value) {}
    ~Handle() { if (value_) CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    [[nodiscard]] HANDLE get() const noexcept { return value_; }

private:
    HANDLE value_{};
};

struct Completion final {
    std::mutex mutex;
    std::condition_variable changed;
    bool done{};
    bool ok{};
    std::string error;

    wpe::shell::TargetLink::Completion Callback() {
        return [this](bool value, std::string message) {
            {
                std::lock_guard lock(mutex);
                done = true;
                ok = value;
                error = std::move(message);
            }
            changed.notify_all();
        };
    }

    void Wait(const char* failure) {
        std::unique_lock lock(mutex);
        Check(changed.wait_for(lock, 15s, [&] { return done; }), failure);
        Check(ok, error.empty() ? failure : error.c_str());
    }
};

std::wstring EventName(const wchar_t* suffix) {
    return std::wstring(L"Local\\WPE64-TargetLink-") +
           std::to_wstring(GetCurrentProcessId()) + L"-" +
           std::to_wstring(GetTickCount64()) + L"-" + suffix;
}

void SetEventChecked(HANDLE event, const char* message) {
    Check(event && SetEvent(event) != FALSE, message);
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc != 3 && argc != 5)
            throw std::runtime_error("launch target and hook DLL paths required");
        const std::filesystem::path launch_target = argv[1];
        const std::filesystem::path hook = argv[2];
        const std::filesystem::path x86_hook = argc == 5 ? argv[3] : std::filesystem::path{};
        const std::filesystem::path x86_helper = argc == 5 ? argv[4] : std::filesystem::path{};

        const auto entered_name = EventName(L"entered");
        const auto release_name = EventName(L"release");
        const auto exited_name = EventName(L"exited");
        Handle entered(CreateEventW(nullptr, TRUE, FALSE, entered_name.c_str()));
        Handle release(CreateEventW(nullptr, TRUE, FALSE, release_name.c_str()));
        Handle exited(CreateEventW(nullptr, TRUE, FALSE, exited_name.c_str()));
        Check(entered.get() && release.get() && exited.get(), "launch test events created");

        std::mutex state_mutex;
        std::condition_variable state_changed;
        std::vector<wpe::IpcLinkState> states;
        wpe::shell::TargetLink link(
            [](wpe::ByteBuffer, bool) {},
            [&](wpe::IpcLinkState state) {
                {
                    std::lock_guard lock(state_mutex);
                    states.push_back(state);
                }
                state_changed.notify_all();
            }, x86_hook, x86_helper);

        const std::wstring arguments = L"\"" + entered_name + L"\" \"" +
            release_name + L"\" \"" + exited_name + L"\"";
        Completion attach;
        link.AttachLaunched(launch_target, arguments, hook, attach.Callback());
        attach.Wait("suspended target injection did not attach");
        Check(link.State() == wpe::IpcLinkState::Attached,
              "target link is attached before primary thread resume");
        Check(WaitForSingleObject(entered.get(), 0) == WAIT_TIMEOUT,
              "primary thread remains suspended after IPC attach");

        // StartHook must be sent while the primary thread is still stopped.
        // This catches an early-resume regression that can miss the first
        // Winsock initialization in a real target.
        wpe::IpcWriter start_hook;
        start_hook.U8(static_cast<std::uint8_t>(wpe::IpcCommand::StartHook));
        Completion start;
        link.CallVoid(start_hook.ToArray(), start.Callback());
        start.Wait("StartHook failed before resume");
        Check(WaitForSingleObject(entered.get(), 0) == WAIT_TIMEOUT,
              "StartHook completed while primary thread remained suspended");

        Completion resume;
        link.ResumeLaunched(resume.Callback());
        resume.Wait("suspended target did not resume");
        Check(WaitForSingleObject(entered.get(), 5000) == WAIT_OBJECT_0,
              "primary thread resumed only after StartHook completion");

        SetEventChecked(release.get(), "release launch target");
        Check(WaitForSingleObject(exited.get(), 5000) == WAIT_OBJECT_0,
              "launch target exited after resume");
        Completion detach;
        link.Detach(detach.Callback());
        detach.Wait("target link detach failed after resumed target exit");
        Check(link.State() == wpe::IpcLinkState::Idle,
              "target link returned to idle after detach");

        std::wcout << L"PASS: " << checks
                   << L" target-link suspended launch checks; inject -> StartHook -> resume order\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
