#include "target/hook_manager.h"
#include "common/ipc_codec.h"
#include <Windows.h>
#include <iostream>
#include <stdexcept>

namespace {
std::size_t checks{};
using TickFn = ULONGLONG(WINAPI*)();
TickFn original_tick{};
ULONGLONG WINAPI TickDetour() { return original_tick() + 1000; }
using PidFn = DWORD(WINAPI*)();
PidFn original_pid{};
DWORD WINAPI PidDetour() { return original_pid() + 1; }

void Check(bool value, const char* message) {
    ++checks;
    if (!value) throw std::runtime_error(message);
}
template<class F> void Throws(F&& action, const char* message) {
    bool threw = false;
    try { action(); } catch (const wpe::ProtocolError&) { threw = true; }
    Check(threw, message);
}
} // namespace

int main() {
    try {
        wpe::HookManager manager;
        Throws([&] { manager.Enable(reinterpret_cast<void*>(&TickDetour)); },
               "enable before initialization rejected");
        manager.Initialize();
        manager.Initialize();
        Check(manager.Initialized(), "MinHook initialized idempotently");
        wpe::HookManager second_manager;
        second_manager.Initialize();
        Check(second_manager.Initialized(), "second owner shares the process-global runtime");
        Throws([&] { (void)manager.Create("missing-module.dll", "none",
                                           reinterpret_cast<void*>(&TickDetour),
                                           reinterpret_cast<void**>(&original_tick)); },
               "missing module rejected");
        const auto tick_target = manager.Create("kernel32.dll", "GetTickCount64",
            reinterpret_cast<void*>(&TickDetour),
            reinterpret_cast<void**>(&original_tick));
        const auto before = original_tick();
        manager.Enable(tick_target);
        const auto hooked = GetTickCount64();
        Check(hooked >= before + 1000, "enabled trampoline routes through detour");
        Throws([&] { (void)manager.Create("kernel32.dll", "GetTickCount64",
                                           reinterpret_cast<void*>(&TickDetour),
                                           reinterpret_cast<void**>(&original_tick)); },
               "duplicate hook rejected");
        Check(manager.Disable(tick_target), "owned hook disables cleanly");
        const auto unhooked = GetTickCount64();
        Check(unhooked < hooked, "disabled target bypasses detour");
        Check(manager.HookCount() == 1, "registered hook tracked until shutdown");
        Check(manager.Shutdown(), "first owner shutdown succeeds");
        Check(!manager.Initialized() && manager.HookCount() == 0,
              "first owner shutdown removes only its hooks");
        const auto pid_target = second_manager.Create("kernel32.dll", "GetCurrentProcessId",
            reinterpret_cast<void*>(&PidDetour), reinterpret_cast<void**>(&original_pid));
        const auto actual_pid = original_pid();
        second_manager.Enable(pid_target);
        Check(GetCurrentProcessId() == actual_pid + 1,
              "remaining owner keeps MinHook runtime usable");
        Check(second_manager.Shutdown(), "last owner shutdown succeeds");
        Check(!second_manager.Initialized() && second_manager.HookCount() == 0,
              "last owner removes its hooks and releases MinHook runtime");
        std::cout << "PASS: " << checks
                  << " MinHook manager checks; resolve/create/enable/disable/remove lifecycle\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
