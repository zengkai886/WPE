#include "injected_runtime.h"
#include "common/ipc_pipe.h"
#include <Windows.h>
#include <atomic>
#include <cstring>
#include <thread>

#if defined(_M_IX86)
#pragma comment(linker, "/EXPORT:WpeStart=_WpeStart@4")
#else
#pragma comment(linker, "/EXPORT:WpeStart")
#endif

namespace {
std::atomic_bool worker_running{};

wpe::InjectionStartResult Validate(const wpe::InjectionBootstrapV1& value) {
    if (value.magic != wpe::InjectionBootstrapMagic)
        return wpe::InjectionStartResult::InvalidMagic;
    if (value.version != wpe::InjectionBootstrapVersion)
        return wpe::InjectionStartResult::InvalidVersion;
    if (value.size != sizeof(wpe::InjectionBootstrapV1))
        return wpe::InjectionStartResult::InvalidSize;
    if (value.connect_timeout_ms == 0 || value.connect_timeout_ms == INFINITE)
        return wpe::InjectionStartResult::InvalidTimeout;
    if (!std::memchr(value.session, '\0', sizeof(value.session)))
        return wpe::InjectionStartResult::InvalidSession;
    try {
        (void)wpe::PipeEndpoint::FullName(value.session, wpe::PipeChannel::Control);
    } catch (...) {
        return wpe::InjectionStartResult::InvalidSession;
    }
    return wpe::InjectionStartResult::Ok;
}
} // namespace

extern "C" DWORD WINAPI WpeStart(void* parameters) {
    if (!parameters)
        return static_cast<DWORD>(wpe::InjectionStartResult::NullParameters);
    wpe::InjectionBootstrapV1 bootstrap{};
    std::memcpy(&bootstrap, parameters, sizeof(bootstrap));
    const auto validation = Validate(bootstrap);
    if (validation != wpe::InjectionStartResult::Ok)
        return static_cast<DWORD>(validation);
    bool expected = false;
    if (!worker_running.compare_exchange_strong(expected, true))
        return static_cast<DWORD>(wpe::InjectionStartResult::WorkerAlreadyRunning);
    try {
        std::thread([bootstrap] {
            wpe::RunInjectedTarget(bootstrap);
            worker_running.store(false);
        }).detach();
    } catch (...) {
        worker_running.store(false);
        return static_cast<DWORD>(wpe::InjectionStartResult::WorkerStartFailed);
    }
    return static_cast<DWORD>(wpe::InjectionStartResult::Ok);
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) {
    // Loader-lock safe by construction: all work starts from WpeStart on a
    // remote thread after LoadLibraryW has returned.
    return TRUE;
}
