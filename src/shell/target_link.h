#pragma once

#include "common/ipc_protocol.h"
#include "common/ipc_session.h"
#include <Windows.h>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

namespace wpe::shell {

class SuspendedProcess;

// Serializes injection, named-pipe lifecycle and target commands on one
// worker.  The UI thread only queues operations; target event frames are
// forwarded to the host for UI-thread dispatch.
class TargetLink final {
public:
    using Completion = std::function<void(bool, std::string)>;
    using ResponseCompletion = std::function<void(bool, std::string, ByteBuffer)>;
    using EventHandler = std::function<void(ByteBuffer, bool packet_channel)>;
    using StateHandler = std::function<void(IpcLinkState)>;

    TargetLink(EventHandler event_handler, StateHandler state_handler,
               std::filesystem::path x86_hook = {},
               std::filesystem::path x86_helper = {});
    ~TargetLink();
    TargetLink(const TargetLink&) = delete;
    TargetLink& operator=(const TargetLink&) = delete;

    void AttachPid(DWORD pid, std::filesystem::path dll, Completion done);
    void AttachLaunched(std::filesystem::path executable, std::wstring arguments,
                        std::filesystem::path dll, Completion done);
    // A launched target remains suspended until configuration and StartHook
    // have succeeded. AttachPid targets are already running, so this is a
    // successful no-op for them.
    void ResumeLaunched(Completion done);
    void CallVoid(ByteBuffer request, Completion done);
    // Send a request and return the target's full IPC response.  This is used
    // by the packet editor's one-shot replay path; void calls intentionally
    // keep their smaller callback contract.
    void Call(ByteBuffer request, ResponseCompletion done);
    void Detach(Completion done);
    void Stop() noexcept;

    [[nodiscard]] IpcLinkState State() const noexcept { return state_.load(); }
    [[nodiscard]] DWORD TargetPid() const noexcept { return target_pid_.load(); }
    [[nodiscard]] bool TargetIs64() const noexcept { return target_is_64_.load(); }

private:
    struct Job {
        enum class Kind { AttachPid, AttachLaunch, Resume, CallVoid, Call, Detach, Stop } kind;
        DWORD pid{};
        std::filesystem::path path;
        std::filesystem::path dll;
        std::wstring arguments;
        ByteBuffer request;
        Completion done;
        ResponseCompletion response_done;
    };

    void Submit(Job job);
    void Run();
    void Attach(Job& job, bool launch);
    void Complete(Completion& done, bool ok, std::string error) noexcept;
    void Complete(ResponseCompletion& done, bool ok, std::string error,
                  ByteBuffer response = {}) noexcept;
    void SetState(IpcLinkState state) noexcept;
    void CleanupX86Helper(bool abort) noexcept;
    bool TargetIsX86(const Job& job, bool launch) const;
    void StartX86Helper(const Job& job, bool launch, const std::string& session_name);
    static std::string NewSession();

    EventHandler event_handler_;
    StateHandler state_handler_;
    mutable std::mutex mutex_;
    std::condition_variable wake_;
    std::deque<Job> jobs_;
    bool stopping_{};
    std::thread worker_;
    std::unique_ptr<ShellIpcSession> session_;
    // Kept across AttachLaunched until StartHook succeeds. Destroying an
    // unresumed SuspendedProcess terminates the child for deterministic
    // rollback instead of leaving a frozen target behind.
    std::unique_ptr<SuspendedProcess> suspended_;
    // A 64-bit shell cannot create a remote thread in a WOW64 target.  The
    // optional 32-bit helper owns that injection and, for launched targets,
    // keeps the child suspended until ResumeLaunched signals it.
    std::filesystem::path x86_hook_;
    std::filesystem::path x86_helper_;
    HANDLE x86_helper_process_{};
    HANDLE x86_helper_resume_{};
    HANDLE x86_helper_abort_{};
    bool x86_helper_launch_{};
    std::atomic<IpcLinkState> state_{IpcLinkState::Idle};
    std::atomic<DWORD> target_pid_{};
    std::atomic_bool target_is_64_{};
};

} // namespace wpe::shell
