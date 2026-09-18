#pragma once

#include "common/injection_protocol.h"

namespace wpe {

// Runs the target-side IPC owner on the caller's dedicated worker thread.
// All failures are contained in the injected process and are reported to the
// shell by the absence/loss of the expected IPC handshake.
void RunInjectedTarget(const InjectionBootstrapV1& bootstrap) noexcept;

} // namespace wpe
