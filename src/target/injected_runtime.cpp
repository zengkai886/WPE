#include "injected_runtime.h"
#include "headless_core.h"
#include "winsock_hook.h"
#include "common/ipc_session.h"
#include <string>

namespace wpe {
void RunInjectedTarget(const InjectionBootstrapV1& bootstrap) noexcept {
    try {
        const std::string session_name(bootstrap.session);
        TargetIpcSession session(session_name, bootstrap.connect_timeout_ms);
        WinsockHookController hooks(
            (bootstrap.flags & InjectionFlagSuspendedLaunch) != 0,
            [&](ByteBuffer packet) { session.SendPacketFrame(packet); },
            [&](ByteBuffer event) { session.SendEventFrame(event); });
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
