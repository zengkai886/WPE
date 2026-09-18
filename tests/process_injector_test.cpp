#include "shell/process_injector.h"
#include "common/ipc_codec.h"
#include <Windows.h>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <stdexcept>

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

DWORD WaitExit(HANDLE process) {
    Check(WaitForSingleObject(process, 8000) == WAIT_OBJECT_0, "test target exited in time");
    DWORD code = 0;
    Check(GetExitCodeProcess(process, &code) != FALSE, "read test target exit code");
    return code;
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc != 3 && argc != 4)
            throw std::runtime_error("target and probe paths, plus optional cross-architecture target, required");
        const std::filesystem::path target = argv[1];
        const std::filesystem::path probe = argv[2];
        const auto machine = wpe::shell::QueryProcessMachine(GetCurrentProcess());
        Check(machine == (sizeof(void*) == 8 ? wpe::shell::ProcessMachine::X64
                                             : wpe::shell::ProcessMachine::X86),
              "current process architecture detected");
        Throws([&] { wpe::shell::ProcessInjector::Inject(0xffffffffU, probe, 100ms); },
               "missing target rejected");
        Throws([&] { wpe::shell::ProcessInjector::Inject(GetCurrentProcessId(), target, 100ms); },
               "non-DLL injection file rejected");
        Throws([&] { wpe::shell::ProcessInjector::Inject(GetCurrentProcessId(), probe, 0ms); },
               "zero injection timeout rejected");
        Throws([&] { (void)wpe::shell::ProcessInjector::LaunchSuspended(
                         target.parent_path() / L"missing-inject-target.exe"); },
               "missing launch executable rejected");

        // Running-target attach path: the launched target waits until it sees
        // the probe module in its own loader list.
        auto running = wpe::shell::ProcessInjector::LaunchSuspended(
            target, L"wpe64-inject-probe.dll", target.parent_path());
        Check(running.Pid() != 0 && running.ProcessHandle() != nullptr, "suspended target created");
        const HANDLE running_handle = running.ProcessHandle();
        running.Resume();
        Sleep(25);
        wpe::shell::ProcessInjector::Inject(running.Pid(), probe, 5s);
        Check(WaitExit(running_handle) == 0, "running target observed injected DLL");

        // The launch object must not leak an abandoned suspended process.
        DWORD abandoned_pid = 0;
        HANDLE abandoned_wait = nullptr;
        {
            auto abandoned = wpe::shell::ProcessInjector::LaunchSuspended(
                target, L"wpe64-inject-probe.dll", target.parent_path());
            abandoned_pid = abandoned.Pid();
            Check(DuplicateHandle(GetCurrentProcess(), abandoned.ProcessHandle(), GetCurrentProcess(),
                                  &abandoned_wait, SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                                  FALSE, 0) != FALSE, "duplicate abandoned process handle");
        }
        Check(WaitForSingleObject(abandoned_wait, 3000) == WAIT_OBJECT_0,
              "abandoned suspended target was terminated");
        DWORD abandoned_code = 0;
        Check(GetExitCodeProcess(abandoned_wait, &abandoned_code) != FALSE &&
              abandoned_code == ERROR_CANCELLED, "abandoned target cleanup exit code");
        CloseHandle(abandoned_wait);
        Check(abandoned_pid != 0, "abandoned target had a PID");

        if (argc == 4) {
            auto cross_architecture = wpe::shell::ProcessInjector::LaunchSuspended(argv[3]);
            Throws([&] { wpe::shell::ProcessInjector::Inject(
                             cross_architecture.Pid(), probe, 1s); },
                   "cross-architecture injection rejected before remote execution");
        }

        std::wcout << L"PASS: " << checks
                   << L" process-injector checks; architecture, suspended launch, real remote LoadLibraryW and cleanup\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
