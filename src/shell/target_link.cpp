#include "target_link.h"
#include "process_injector.h"
#include "common/ipc_codec.h"
#include <objbase.h>
#include <stdexcept>

namespace wpe::shell {

TargetLink::TargetLink(EventHandler event_handler, StateHandler state_handler)
    : event_handler_(std::move(event_handler)), state_handler_(std::move(state_handler)),
      worker_(&TargetLink::Run, this) {}

TargetLink::~TargetLink() { Stop(); }

void TargetLink::Complete(Completion& done, bool ok, std::string error) noexcept {
    if (!done) return;
    try { done(ok, std::move(error)); } catch (...) {}
}

void TargetLink::Submit(Job job) {
    bool reject = false;
    {
        std::lock_guard lock(mutex_);
        reject = stopping_ || jobs_.size() >= 128;
        if (!reject) jobs_.push_back(std::move(job));
    }
    if (reject) Complete(job.done, false, "目标连接正在退出或操作队列已满");
    else wake_.notify_one();
}

void TargetLink::AttachPid(DWORD pid, std::filesystem::path dll, Completion done) {
    Submit({Job::Kind::AttachPid, pid, {}, std::move(dll), {}, {}, std::move(done)});
}

void TargetLink::AttachLaunched(std::filesystem::path executable, std::wstring arguments,
                                std::filesystem::path dll, Completion done) {
    Submit({Job::Kind::AttachLaunch, 0, std::move(executable), std::move(dll),
            std::move(arguments), {}, std::move(done)});
}

void TargetLink::CallVoid(ByteBuffer request, Completion done) {
    Submit({Job::Kind::CallVoid, 0, {}, {}, {}, std::move(request), std::move(done)});
}

void TargetLink::Detach(Completion done) {
    Submit({Job::Kind::Detach, 0, {}, {}, {}, {}, std::move(done)});
}

void TargetLink::SetState(IpcLinkState state) noexcept {
    state_.store(state);
    if (state_handler_) {
        try { state_handler_(state); } catch (...) {}
    }
}

std::string TargetLink::NewSession() {
    GUID guid{};
    if (FAILED(CoCreateGuid(&guid))) throw std::runtime_error("无法生成目标 IPC 会话");
    wchar_t text[64]{};
    if (!StringFromGUID2(guid, text, static_cast<int>(std::size(text))))
        throw std::runtime_error("无法格式化目标 IPC 会话");
    std::string result;
    for (const wchar_t c : std::wstring(text)) {
        if (c == L'{' || c == L'}') continue;
        result.push_back(c <= 0x7f ? static_cast<char>(c) : '_');
    }
    // Named-pipe validation permits this canonical GUID and it is short enough
    // for the bootstrap record.  Keep the braces out of the pipe name.
    return result;
}

void TargetLink::Attach(Job& job, bool launch) {
    if (session_) {
        try { session_->Detach(); } catch (...) { session_->Stop(); }
        session_.reset();
    }
    target_pid_.store(0);
    target_is_64_.store(false);
    SetState(IpcLinkState::Attaching);

    const auto session_name = NewSession();
    session_ = std::make_unique<ShellIpcSession>(
        session_name,
        [this](ByteBuffer frame) { if (event_handler_) event_handler_(std::move(frame), true); },
        [this](ByteBuffer frame) { if (event_handler_) event_handler_(std::move(frame), false); },
        [this](IpcLinkState state) { SetState(state); });

    std::optional<SuspendedProcess> suspended;
    DWORD pid = job.pid;
    if (launch) {
        suspended.emplace(ProcessInjector::LaunchSuspended(job.path, job.arguments,
                                                            job.path.parent_path()));
        pid = suspended->Pid();
    }
    InjectionOptions options;
    options.session = session_name;
    options.connect_timeout_ms = 5000;
    options.suspended_launch = launch;
    ProcessInjector::InjectAndStart(pid, job.dll, options);
    if (suspended) suspended->Resume();
    session_->Accept(options.connect_timeout_ms);
    session_->Start();
    target_pid_.store(static_cast<DWORD>(session_->TargetPid()));
    target_is_64_.store(session_->TargetIs64());
}

void TargetLink::Run() {
    for (;;) {
        Job job;
        {
            std::unique_lock lock(mutex_);
            wake_.wait(lock, [&] { return stopping_ || !jobs_.empty(); });
            if (jobs_.empty() && stopping_) break;
            job = std::move(jobs_.front()); jobs_.pop_front();
        }
        if (job.kind == Job::Kind::Stop) break;
        try {
            if (job.kind == Job::Kind::AttachPid || job.kind == Job::Kind::AttachLaunch) {
                Attach(job, job.kind == Job::Kind::AttachLaunch);
                Complete(job.done, true, {});
            } else if (job.kind == Job::Kind::CallVoid) {
                if (!session_ || State() != IpcLinkState::Attached)
                    throw std::runtime_error("尚未连接目标进程");
                session_->CallVoid(job.request);
                Complete(job.done, true, {});
            } else if (job.kind == Job::Kind::Detach) {
                if (session_) { session_->Detach(); session_.reset(); }
                target_pid_.store(0); target_is_64_.store(false);
                SetState(IpcLinkState::Idle);
                Complete(job.done, true, {});
            }
        } catch (const std::exception& error) {
            if (job.kind == Job::Kind::AttachPid || job.kind == Job::Kind::AttachLaunch) {
                if (session_) { session_->Stop(); session_.reset(); }
                target_pid_.store(0); target_is_64_.store(false);
                SetState(IpcLinkState::Disconnected);
            }
            Complete(job.done, false, error.what());
        } catch (...) {
            Complete(job.done, false, "目标连接操作失败");
        }
    }
    if (session_) session_->Stop();
    session_.reset();
    target_pid_.store(0); target_is_64_.store(false);
    SetState(IpcLinkState::Disconnected);
}

void TargetLink::Stop() noexcept {
    {
        std::lock_guard lock(mutex_);
        if (stopping_) return;
        stopping_ = true;
        jobs_.push_back({Job::Kind::Stop});
    }
    wake_.notify_one();
    if (worker_.joinable()) worker_.join();
}

} // namespace wpe::shell
