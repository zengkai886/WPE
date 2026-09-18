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

    void Wait(const char* failure, bool expected_ok) {
        std::unique_lock lock(mutex);
        Check(changed.wait_for(lock, 15s, [&] { return done; }), failure);
        Check(ok == expected_ok, error.empty() ? failure : error.c_str());
    }
};

std::wstring EventName(const wchar_t* suffix) {
    return std::wstring(L"Local\\WPE64-TargetLink-Error-") +
           std::to_wstring(GetCurrentProcessId()) + L"-" +
           std::to_wstring(GetTickCount64()) + L"-" + suffix;
}

void ExpectAttachFailure(const std::filesystem::path& executable,
                         const std::filesystem::path& hook,
                         const std::filesystem::path& x86_hook = {},
                         const std::filesystem::path& x86_helper = {}) {
    wpe::shell::TargetLink link({}, {} , x86_hook, x86_helper);
    Completion attach;
    link.AttachLaunched(executable, {}, hook, attach.Callback());
    attach.Wait("expected AttachLaunched failure did not complete", false);
    Check(link.State() == wpe::IpcLinkState::Disconnected,
          "failed AttachLaunched did not disconnect");
}

void ExpectProcessGone(DWORD pid, const char* message) {
    Handle process(OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!process.get()) {
        Check(GetLastError() == ERROR_INVALID_PARAMETER || GetLastError() == ERROR_NOT_FOUND,
              message);
        return;
    }
    Check(WaitForSingleObject(process.get(), 5000) == WAIT_OBJECT_0, message);
}

struct Child final {
    PROCESS_INFORMATION info{};
    Child() = default;
    Child(const Child&) = delete;
    Child& operator=(const Child&) = delete;
    Child(Child&& other) noexcept : info(other.info) { other.info = {}; }
    Child& operator=(Child&&) = delete;
    ~Child() {
        if (info.hThread) CloseHandle(info.hThread);
        if (info.hProcess) {
            (void)TerminateProcess(info.hProcess, ERROR_CANCELLED);
            (void)WaitForSingleObject(info.hProcess, 5000);
            CloseHandle(info.hProcess);
        }
    }
};

Child StartChild(const std::filesystem::path& executable) {
    std::wstring command = L"\"" + executable.wstring() + L"\"";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    Child child;
    std::vector<wchar_t> mutable_command(command.begin(), command.end());
    mutable_command.push_back(L'\0');
    Check(CreateProcessW(nullptr, mutable_command.data(), nullptr, nullptr, FALSE,
                         CREATE_NO_WINDOW, nullptr, nullptr, &startup, &child.info) != FALSE,
          "x86 attach fixture could not start");
    CloseHandle(child.info.hThread);
    child.info.hThread = nullptr;
    return child;
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc != 5 && argc != 8)
            throw std::runtime_error("x64 target, production hook, failure hook and helper stub required");

        const std::filesystem::path target = argv[1];
        const std::filesystem::path production_hook = argv[2];
        const std::filesystem::path failure_hook = argv[3];
        const std::filesystem::path helper_stub = argv[4];

        // A missing production DLL must fail before a suspended child escapes.
        ExpectAttachFailure(target, target.parent_path() / L"missing-wpe64-hook.dll");

        // A target-side StartHook error must be observable and detachable while
        // the primary thread is still suspended.
        const auto entered_name = EventName(L"entered");
        const auto release_name = EventName(L"release");
        const auto exited_name = EventName(L"exited");
        Handle entered(CreateEventW(nullptr, TRUE, FALSE, entered_name.c_str()));
        Handle release(CreateEventW(nullptr, TRUE, FALSE, release_name.c_str()));
        Handle exited(CreateEventW(nullptr, TRUE, FALSE, exited_name.c_str()));
        Check(entered.get() && release.get() && exited.get(), "error-matrix events created");

        wpe::shell::TargetLink failing_link({}, {});
        Completion attach;
        const std::wstring arguments = L"\"" + entered_name + L"\" \"" +
            release_name + L"\" \"" + exited_name + L"\"";
        failing_link.AttachLaunched(target, arguments, failure_hook, attach.Callback());
        attach.Wait("StartHook failure fixture did not attach", true);
        const auto pid = failing_link.TargetPid();
        Check(pid != 0, "StartHook failure fixture has no target pid");
        Check(WaitForSingleObject(entered.get(), 0) == WAIT_TIMEOUT,
              "target entered before StartHook failure was handled");

        wpe::IpcWriter start;
        start.U8(static_cast<std::uint8_t>(wpe::IpcCommand::StartHook));
        Completion start_result;
        failing_link.CallVoid(start.ToArray(), start_result.Callback());
        start_result.Wait("StartHook failure did not return", false);
        Check(start_result.error.find("forced StartHook failure") != std::string::npos,
              "StartHook failure message was not propagated");

        Completion detach_after_start_failure;
        failing_link.Detach(detach_after_start_failure.Callback());
        detach_after_start_failure.Wait("Detach after StartHook failure failed", true);
        Check(failing_link.State() == wpe::IpcLinkState::Idle,
              "Detach after StartHook failure did not return to idle");
        ExpectProcessGone(pid, "StartHook failure left a suspended target behind");

        // Detach is also valid before StartHook and must terminate the held
        // suspended child without ever running its primary entry point.
        wpe::shell::TargetLink detached_link({}, {});
        Completion detached_attach;
        detached_link.AttachLaunched(target, arguments, production_hook, detached_attach.Callback());
        detached_attach.Wait("detach-before-resume fixture did not attach", true);
        const auto detached_pid = detached_link.TargetPid();
        Check(WaitForSingleObject(entered.get(), 0) == WAIT_TIMEOUT,
              "target entered before detach-before-resume");
        Completion detached;
        detached_link.Detach(detached.Callback());
        detached.Wait("detach-before-resume failed", true);
        ExpectProcessGone(detached_pid, "detach-before-resume left a target process behind");

#if defined(_WIN64)
        if (argc == 8) {
            const std::filesystem::path x86_target = argv[5];
            const std::filesystem::path x86_hook = argv[6];
            const std::filesystem::path x86_helper = argv[7];

            // The x86 path is only dispatched by a 64-bit shell.  A missing
            // helper must be rejected before the child is launched.
            ExpectAttachFailure(x86_target, production_hook, x86_hook,
                                x86_helper.parent_path() / L"missing-wpe64-x86-helper.exe");

            // The bounded helper wait is shortened for this test target via
            // compile definitions; the production default remains 10 seconds.
            ExpectAttachFailure(x86_target, production_hook, x86_hook, helper_stub);

            // Running-target injection uses the same helper but has no resume
            // phase.  The helper must signal ready after InjectAndStart or the
            // shell would wait forever before accepting the IPC channels.
            auto child = StartChild(x86_target);
            wpe::shell::TargetLink attach_link({}, {}, x86_hook, x86_helper);
            Completion running_attach;
            attach_link.AttachPid(child.info.dwProcessId, x86_hook, running_attach.Callback());
            running_attach.Wait("x86 helper attach path did not complete", true);
            Check(!attach_link.TargetIs64(), "x86 helper attach reported a 64-bit target");
            Completion running_detach;
            attach_link.Detach(running_detach.Callback());
            running_detach.Wait("x86 helper attach detach failed", true);
        }
#endif

        std::wcout << L"PASS: " << checks
                   << L" target-link error-matrix checks; failure cleanup and detach ordering\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
