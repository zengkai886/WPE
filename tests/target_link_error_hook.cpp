#include "common/injection_protocol.h"
#include "common/ipc_session.h"
#include <Windows.h>
#include <cstring>
#include <thread>

#if defined(_M_IX86)
#pragma comment(linker, "/EXPORT:WpeStart=_WpeStart@4")
#else
#pragma comment(linker, "/EXPORT:WpeStart")
#endif

namespace {
void RunFailureSession(wpe::InjectionBootstrapV1 bootstrap) noexcept {
    try {
        wpe::TargetIpcSession session(std::string(bootstrap.session), bootstrap.connect_timeout_ms);
        session.Run(
            [](wpe::IpcCommand command, wpe::IpcReader&) {
                if (command == wpe::IpcCommand::StartHook)
                    return wpe::IpcError("forced StartHook failure");
                return wpe::IpcError("error-matrix command is not implemented");
            },
            {}, {}, {});
    } catch (...) {
        // The test observes the shell-side command result and cleanup state.
    }
}
} // namespace

extern "C" DWORD WINAPI WpeStart(void* parameters) {
    if (!parameters) return ERROR_INVALID_PARAMETER;
    wpe::InjectionBootstrapV1 bootstrap{};
    std::memcpy(&bootstrap, parameters, sizeof(bootstrap));
    try {
        std::thread(RunFailureSession, bootstrap).detach();
        return ERROR_SUCCESS;
    } catch (...) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
