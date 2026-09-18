#include "injected_runtime.h"
#include "headless_core.h"
#include "hook_manager.h"
#include "common/ipc_session.h"
#include <Windows.h>
#include <string>

namespace wpe {
namespace {

class BootstrapHookController final : public IHookController {
public:
    explicit BootstrapHookController(bool suspended_launch) noexcept
        : suspended_launch_(suspended_launch) {}

    WinsockSupport DetectWinsock(bool may_load) override {
        if (may_load && suspended_launch_) {
            // A natively suspended process has not run its ordinary imports.
            // Load the same three modules as the original before a future hook
            // backend resolves their exports.
            (void)LoadLibraryW(L"wsock32.dll");
            (void)LoadLibraryW(L"ws2_32.dll");
            (void)LoadLibraryW(L"mswsock.dll");
        }
        return WinsockSupport{
            GetModuleHandleW(L"wsock32.dll") != nullptr,
            GetModuleHandleW(L"ws2_32.dll") != nullptr,
            GetModuleHandleW(L"mswsock.dll") != nullptr,
        };
    }

    void StartHook() override {
        // Deliberately fail instead of reporting a fictitious HookState. This
        // bootstrap slice establishes the real injected DLL/session lifetime;
        // the production MinHook backend replaces this controller next.
        manager_.Initialize();
        throw ProtocolError("Winsock detours are not configured");
    }

    void StopHook() override {}

private:
    bool suspended_launch_{};
    HookManager manager_;
};

} // namespace

void RunInjectedTarget(const InjectionBootstrapV1& bootstrap) noexcept {
    try {
        const std::string session_name(bootstrap.session);
        TargetIpcSession session(session_name, bootstrap.connect_timeout_ms);
        BootstrapHookController hooks(
            (bootstrap.flags & InjectionFlagSuspendedLaunch) != 0);
        HeadlessCore core(hooks, [&](ByteBuffer event) {
            session.SendEventFrame(event);
        });
        session.Run(
            [&](IpcCommand command, IpcReader& reader) {
                return core.HandleCommand(command, reader);
            },
            [&] { core.Shutdown(); },
            [&] { core.OnHello(); },
            [&] { core.Shutdown(); });
        core.Shutdown();
    } catch (...) {
        // No file/UI fallback is allowed in a foreign target process. The
        // shell observes a missing Hello or a disconnected session.
    }
}

} // namespace wpe
