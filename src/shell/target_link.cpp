#include "target_link.h"
#include "process_injector.h"
#include "common/ipc_codec.h"
#include <objbase.h>
#include <algorithm>
#include <cwchar>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <vector>

namespace wpe::shell {

namespace {
class Handle final {
public:
    explicit Handle(HANDLE value = nullptr) noexcept : value_(value) {}
    ~Handle() { if (value_) CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    [[nodiscard]] HANDLE get() const noexcept { return value_; }
    HANDLE release() noexcept { return std::exchange(value_, nullptr); }

private:
    HANDLE value_{};
};

std::wstring QuoteArg(std::wstring_view value) {
    if (!value.empty() && value.find_first_of(L" \t\"") == std::wstring_view::npos)
        return std::wstring(value);
    std::wstring result = L"\"";
    std::size_t slashes = 0;
    for (const auto character : value) {
        if (character == L'\\') { ++slashes; continue; }
        if (character == L'"') {
            result.append(slashes * 2 + 1, L'\\');
            result.push_back(L'"');
            slashes = 0;
            continue;
        }
        result.append(slashes, L'\\');
        slashes = 0;
        result.push_back(character);
    }
    result.append(slashes * 2, L'\\');
    result.push_back(L'\"');
    return result;
}

std::wstring WideAscii(std::string_view value) {
    std::wstring result;
    result.reserve(value.size());
    for (const auto character : value) result.push_back(static_cast<unsigned char>(character));
    return result;
}

std::wstring HelperEventName(std::string_view session, const wchar_t* suffix) {
    return L"Local\\WPE64-X86-" + WideAscii(session) + L"-" + suffix;
}

bool IsX86Executable(const std::filesystem::path& executable) {
    DWORD type = 0;
    if (!GetBinaryTypeW(executable.c_str(), &type))
        throw ProtocolError("无法读取目标程序位数");
    return type == SCS_32BIT_BINARY;
}

bool IsX86Process(DWORD pid) {
    Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!process.get()) {
        std::ostringstream text;
        text << "OpenProcess(query target) failed with Win32 error " << GetLastError();
        throw ProtocolError(text.str());
    }
    return QueryProcessMachine(process.get()) == ProcessMachine::X86;
}
} // namespace

TargetLink::TargetLink(EventHandler event_handler, StateHandler state_handler,
                       std::filesystem::path x86_hook,
                       std::filesystem::path x86_helper)
    : event_handler_(std::move(event_handler)), state_handler_(std::move(state_handler)),
      x86_hook_(std::move(x86_hook)), x86_helper_(std::move(x86_helper)),
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

void TargetLink::ResumeLaunched(Completion done) {
    Submit({Job::Kind::Resume, 0, {}, {}, {}, {}, std::move(done)});
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

void TargetLink::CleanupX86Helper(bool abort) noexcept {
    if (abort && x86_helper_abort_) (void)SetEvent(x86_helper_abort_);
    if (x86_helper_process_) {
        const auto wait = WaitForSingleObject(x86_helper_process_, 5000);
        if (wait == WAIT_TIMEOUT) {
            (void)TerminateProcess(x86_helper_process_, ERROR_CANCELLED);
            (void)WaitForSingleObject(x86_helper_process_, 2000);
        }
        CloseHandle(x86_helper_process_);
    }
    if (x86_helper_resume_) CloseHandle(x86_helper_resume_);
    if (x86_helper_abort_) CloseHandle(x86_helper_abort_);
    x86_helper_process_ = nullptr;
    x86_helper_resume_ = nullptr;
    x86_helper_abort_ = nullptr;
    x86_helper_launch_ = false;
}

bool TargetLink::TargetIsX86(const Job& job, bool launch) const {
    return launch ? IsX86Executable(job.path) : IsX86Process(job.pid);
}

void TargetLink::StartX86Helper(const Job& job, bool launch, const std::string& session_name) {
    if (x86_helper_.empty() || !std::filesystem::is_regular_file(x86_helper_))
        throw ProtocolError("未找到 x86 辅助注入器 wpe64-x86-helper.exe");
    if (x86_hook_.empty() || !std::filesystem::is_regular_file(x86_hook_))
        throw ProtocolError("未找到 x86 目标注入 DLL wpe64-hook-x86.dll");

    const auto ready_name = HelperEventName(session_name, L"ready");
    Handle ready(CreateEventW(nullptr, TRUE, FALSE, ready_name.c_str()));
    if (!ready.get()) throw ProtocolError("无法创建 x86 helper ready 事件");

    std::wstring command = QuoteArg(x86_helper_.wstring());
    if (!launch) {
        command += L" --attach " + std::to_wstring(job.pid) + L" " +
                   QuoteArg(x86_hook_.wstring()) + L" " + QuoteArg(WideAscii(session_name));
    } else {
        const auto resume_name = HelperEventName(session_name, L"resume");
        const auto abort_name = HelperEventName(session_name, L"abort");
        Handle resume(CreateEventW(nullptr, TRUE, FALSE, resume_name.c_str()));
        Handle abort(CreateEventW(nullptr, TRUE, FALSE, abort_name.c_str()));
        if (!resume.get() || !abort.get())
            throw ProtocolError("无法创建 x86 helper 控制事件");
        command += L" --launch " + QuoteArg(job.path.wstring()) + L" " +
                   QuoteArg(job.arguments) + L" " + QuoteArg(x86_hook_.wstring()) + L" " +
                   QuoteArg(WideAscii(session_name)) + L" " + QuoteArg(ready_name) + L" " +
                   QuoteArg(resume_name) + L" " + QuoteArg(abort_name);
        x86_helper_resume_ = resume.release();
        x86_helper_abort_ = abort.release();
        x86_helper_launch_ = true;
    }

    std::vector<wchar_t> mutable_command(command.begin(), command.end());
    mutable_command.push_back(L'\0');
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(nullptr, mutable_command.data(), nullptr, nullptr, FALSE,
                         CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) {
        CleanupX86Helper(true);
        throw ProtocolError("无法启动 x86 辅助注入器");
    }
    CloseHandle(process.hThread);
    x86_helper_process_ = process.hProcess;

    const auto ready_wait = WaitForSingleObject(ready.get(), 10000);
    if (ready_wait != WAIT_OBJECT_0) {
        CleanupX86Helper(true);
        throw ProtocolError(ready_wait == WAIT_TIMEOUT ?
            "x86 辅助注入器等待超时" : "x86 辅助注入器 ready 等待失败");
    }
    if (!launch) {
        const auto helper_wait = WaitForSingleObject(x86_helper_process_, 10000);
        if (helper_wait != WAIT_OBJECT_0) {
            CleanupX86Helper(true);
            throw ProtocolError("x86 辅助注入器未正常退出");
        }
        DWORD exit_code = ERROR_GEN_FAILURE;
        if (!GetExitCodeProcess(x86_helper_process_, &exit_code) || exit_code != 0) {
            CleanupX86Helper(false);
            throw ProtocolError("x86 辅助注入失败");
        }
        CleanupX86Helper(false);
    }
}

void TargetLink::Attach(Job& job, bool launch) {
    if (session_) {
        try { session_->Detach(); } catch (...) { session_->Stop(); }
        session_.reset();
    }
    suspended_.reset();
    CleanupX86Helper(true);
    target_pid_.store(0);
    target_is_64_.store(false);
    SetState(IpcLinkState::Attaching);

    const auto session_name = NewSession();
    session_ = std::make_unique<ShellIpcSession>(
        session_name,
        [this](ByteBuffer frame) { if (event_handler_) event_handler_(std::move(frame), true); },
        [this](ByteBuffer frame) { if (event_handler_) event_handler_(std::move(frame), false); },
        [this](IpcLinkState state) { SetState(state); });

    const bool x86 = TargetIsX86(job, launch);
    // A Win32 shell is already the correct injector for an x86 target.  Only
    // the x64 shell needs to dispatch the external helper.
    const bool use_x86_helper = x86 && sizeof(void*) == 8;
    std::optional<SuspendedProcess> suspended;
    DWORD pid = job.pid;
    if (launch && !use_x86_helper) {
        suspended.emplace(ProcessInjector::LaunchSuspended(job.path, job.arguments,
                                                            job.path.parent_path()));
        pid = suspended->Pid();
    }
    InjectionOptions options;
    options.session = session_name;
    options.connect_timeout_ms = 5000;
    options.suspended_launch = launch;
    if (use_x86_helper) {
        StartX86Helper(job, launch, session_name);
    } else {
        ProcessInjector::InjectAndStart(pid, job.dll, options);
        if (suspended)
            suspended_ = std::make_unique<SuspendedProcess>(std::move(*suspended));
    }
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
            } else if (job.kind == Job::Kind::Resume) {
                if (suspended_) {
                    suspended_->Resume();
                    suspended_.reset();
                } else if (x86_helper_resume_) {
                    if (!SetEvent(x86_helper_resume_))
                        throw ProtocolError("x86 辅助注入器恢复事件失败");
                    if (WaitForSingleObject(x86_helper_process_, 10000) != WAIT_OBJECT_0) {
                        CleanupX86Helper(true);
                        throw ProtocolError("x86 辅助注入器恢复超时");
                    }
                    DWORD exit_code = ERROR_GEN_FAILURE;
                    if (!GetExitCodeProcess(x86_helper_process_, &exit_code) || exit_code != 0) {
                        CleanupX86Helper(false);
                        throw ProtocolError("x86 辅助注入器恢复失败");
                    }
                    CleanupX86Helper(false);
                }
                Complete(job.done, true, {});
            } else if (job.kind == Job::Kind::CallVoid) {
                if (!session_ || State() != IpcLinkState::Attached)
                    throw std::runtime_error("尚未连接目标进程");
                session_->CallVoid(job.request);
                Complete(job.done, true, {});
            } else if (job.kind == Job::Kind::Detach) {
                if (session_) { session_->Detach(); session_.reset(); }
                CleanupX86Helper(true);
                suspended_.reset();
                target_pid_.store(0); target_is_64_.store(false);
                SetState(IpcLinkState::Idle);
                Complete(job.done, true, {});
            }
        } catch (const std::exception& error) {
            if (job.kind == Job::Kind::AttachPid || job.kind == Job::Kind::AttachLaunch) {
                if (session_) { session_->Stop(); session_.reset(); }
                CleanupX86Helper(true);
                suspended_.reset();
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
    CleanupX86Helper(true);
    suspended_.reset();
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
