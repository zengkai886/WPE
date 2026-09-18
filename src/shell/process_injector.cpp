#include "process_injector.h"
#include "common/injection_protocol.h"
#include "common/ipc_codec.h"
#include "common/ipc_pipe.h"
#include <TlHelp32.h>
#include <algorithm>
#include <cstring>
#include <limits>
#include <sstream>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace wpe::shell {
namespace {
class Handle final {
public:
    explicit Handle(HANDLE value = nullptr) noexcept : value_(value) {}
    ~Handle() { if (value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    [[nodiscard]] HANDLE Get() const noexcept { return value_; }
private:
    HANDLE value_;
};

class Module final {
public:
    explicit Module(HMODULE value = nullptr) noexcept : value_(value) {}
    ~Module() { if (value_) FreeLibrary(value_); }
    Module(const Module&) = delete;
    Module& operator=(const Module&) = delete;
    [[nodiscard]] HMODULE Get() const noexcept { return value_; }
private:
    HMODULE value_;
};

[[noreturn]] void Fail(const char* operation, DWORD code = GetLastError()) {
    std::ostringstream out;
    out << operation << " failed with Win32 error " << code;
    throw ProtocolError(out.str());
}

ProcessMachine FromMachine(USHORT machine) {
    switch (machine) {
    case IMAGE_FILE_MACHINE_I386: return ProcessMachine::X86;
    case IMAGE_FILE_MACHINE_AMD64: return ProcessMachine::X64;
    case IMAGE_FILE_MACHINE_ARM64: return ProcessMachine::Arm64;
    default: return ProcessMachine::Unknown;
    }
}

std::filesystem::path FullExistingFile(const std::filesystem::path& input, const char* what) {
    std::error_code error;
    const auto full = std::filesystem::absolute(input, error).lexically_normal();
    if (error || !std::filesystem::is_regular_file(full, error) || error)
        throw ProtocolError(std::string(what) + " does not exist");
    return full;
}

std::uintptr_t RemoteModuleBase(DWORD pid, const wchar_t* module_name) {
    for (int attempt = 0; attempt < 200; ++attempt) {
        Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
        if (snapshot.Get() == INVALID_HANDLE_VALUE) {
            const DWORD error = GetLastError();
            if (error == ERROR_BAD_LENGTH || error == ERROR_PARTIAL_COPY) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }
            Fail("CreateToolhelp32Snapshot", error);
        }
        MODULEENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        if (!Module32FirstW(snapshot.Get(), &entry)) {
            const DWORD error = GetLastError();
            if (error == ERROR_BAD_LENGTH || error == ERROR_PARTIAL_COPY ||
                error == ERROR_NO_MORE_FILES) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }
            Fail("Module32FirstW", error);
        }
        do {
            if (_wcsicmp(entry.szModule, module_name) == 0)
                return reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
        } while (Module32NextW(snapshot.Get(), &entry));
        return 0;
    }
    throw ProtocolError("Target module list did not become readable");
}

bool HasRemoteModule(DWORD pid, const std::wstring& module_name) {
    return RemoteModuleBase(pid, module_name.c_str()) != 0;
}

LPTHREAD_START_ROUTINE RemoteLoadLibrary(DWORD pid, bool suspended_launch) {
    const auto local_module = GetModuleHandleW(L"kernel32.dll");
    if (!local_module) Fail("GetModuleHandleW(kernel32)");
    const auto local_proc = GetProcAddress(local_module, "LoadLibraryW");
    if (!local_proc) Fail("GetProcAddress(LoadLibraryW)");
    // A CREATE_SUSPENDED primary thread can still be inside the process
    // loader's initialisation.  Toolhelp then cannot acquire the loader lock
    // and may report ERROR_PARTIAL_COPY for the entire retry window.  System
    // DLLs use the same image mapping for a given machine/boot session, so the
    // local kernel32 base is a safe fallback until the suspended loader has
    // published its module list.  Once the target is running normally the
    // Toolhelp path remains the preferred (and independently verified) one.
    std::uintptr_t remote_base = 0;
    try { remote_base = RemoteModuleBase(pid, L"kernel32.dll"); }
    catch (const ProtocolError&) {
        if (!suspended_launch) throw;
        remote_base = reinterpret_cast<std::uintptr_t>(local_module);
    }
    if (!remote_base && !suspended_launch)
        throw ProtocolError("Target kernel32.dll was not found");
    if (!remote_base) remote_base = reinterpret_cast<std::uintptr_t>(local_module);
    const auto offset = reinterpret_cast<std::uintptr_t>(local_proc) -
                        reinterpret_cast<std::uintptr_t>(local_module);
    return reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_base + offset);
}

InjectionBootstrapV1 MakeBootstrap(const InjectionOptions& options) {
    if (options.connect_timeout_ms == 0 || options.connect_timeout_ms == INFINITE)
        throw ProtocolError("Target connection timeout is invalid");
    // Reuse the transport's canonical validation rather than allowing the
    // bootstrap record to create an arbitrary named-pipe path.
    (void)PipeEndpoint::FullName(options.session, PipeChannel::Control);
    InjectionBootstrapV1 bootstrap;
    bootstrap.connect_timeout_ms = options.connect_timeout_ms;
    bootstrap.flags = options.suspended_launch ? InjectionFlagSuspendedLaunch : 0U;
    if (options.session.size() >= sizeof(bootstrap.session))
        throw ProtocolError("Injection session is too long");
    std::memcpy(bootstrap.session, options.session.data(), options.session.size());
    bootstrap.session[options.session.size()] = '\0';
    return bootstrap;
}

LPTHREAD_START_ROUTINE RemoteExport(DWORD pid, const std::filesystem::path& dll,
                                    const char* export_name) {
    Module local(LoadLibraryExW(dll.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES));
    if (!local.Get()) Fail("LoadLibraryExW(injection DLL)");
    const auto procedure = GetProcAddress(local.Get(), export_name);
    if (!procedure) Fail("GetProcAddress(injection entry)");
    const auto remote_base = RemoteModuleBase(pid, dll.filename().c_str());
    if (!remote_base) throw ProtocolError("Injected DLL was not found in the target module list");
    const auto offset = reinterpret_cast<std::uintptr_t>(procedure) -
                        reinterpret_cast<std::uintptr_t>(local.Get());
    return reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_base + offset);
}
} // namespace

ProcessMachine QueryProcessMachine(HANDLE process) {
    using IsWow64Process2Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
    const auto kernel = GetModuleHandleW(L"kernel32.dll");
    const auto fn = reinterpret_cast<IsWow64Process2Fn>(GetProcAddress(kernel, "IsWow64Process2"));
    if (fn) {
        USHORT process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
        USHORT native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
        if (!fn(process, &process_machine, &native_machine)) Fail("IsWow64Process2");
        return FromMachine(process_machine == IMAGE_FILE_MACHINE_UNKNOWN ? native_machine : process_machine);
    }
    BOOL wow64 = FALSE;
    if (!IsWow64Process(process, &wow64)) Fail("IsWow64Process");
    if (wow64) return ProcessMachine::X86;
    SYSTEM_INFO info{};
    GetNativeSystemInfo(&info);
    if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) return ProcessMachine::X64;
    if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) return ProcessMachine::Arm64;
    return ProcessMachine::X86;
}

SuspendedProcess::SuspendedProcess(HANDLE process, HANDLE thread, DWORD process_id) noexcept
    : process_(process), thread_(thread), process_id_(process_id) {}
SuspendedProcess::~SuspendedProcess() { Close(); }
SuspendedProcess::SuspendedProcess(SuspendedProcess&& other) noexcept { *this = std::move(other); }
SuspendedProcess& SuspendedProcess::operator=(SuspendedProcess&& other) noexcept {
    if (this == &other) return *this;
    Close();
    process_ = std::exchange(other.process_, nullptr);
    thread_ = std::exchange(other.thread_, nullptr);
    process_id_ = std::exchange(other.process_id_, 0);
    resumed_ = std::exchange(other.resumed_, false);
    return *this;
}
void SuspendedProcess::Resume() {
    if (!process_ || !thread_) throw ProtocolError("Suspended process is not valid");
    if (resumed_) return;
    if (ResumeThread(thread_) == std::numeric_limits<DWORD>::max()) Fail("ResumeThread");
    resumed_ = true;
}
void SuspendedProcess::Close() noexcept {
    if (process_ && !resumed_) {
        (void)TerminateProcess(process_, ERROR_CANCELLED);
        (void)WaitForSingleObject(process_, 2000);
    }
    if (thread_) CloseHandle(thread_);
    if (process_) CloseHandle(process_);
    thread_ = nullptr; process_ = nullptr; process_id_ = 0; resumed_ = false;
}

SuspendedProcess ProcessInjector::LaunchSuspended(const std::filesystem::path& executable,
                                                  std::wstring_view arguments,
                                                  const std::filesystem::path& working_directory) {
    const auto full = FullExistingFile(executable, "Executable");
    std::wstring command = L"\"" + full.wstring() + L"\"";
    if (!arguments.empty()) { command.push_back(L' '); command.append(arguments); }
    std::vector<wchar_t> mutable_command(command.begin(), command.end());
    mutable_command.push_back(L'\0');
    std::wstring directory;
    if (!working_directory.empty()) directory = std::filesystem::absolute(working_directory).wstring();
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(full.c_str(), mutable_command.data(), nullptr, nullptr, FALSE,
                        CREATE_SUSPENDED, nullptr, directory.empty() ? nullptr : directory.c_str(),
                        &startup, &process)) Fail("CreateProcessW(CREATE_SUSPENDED)");
    return SuspendedProcess(process.hProcess, process.hThread, process.dwProcessId);
}

void InjectModule(DWORD process_id, const std::filesystem::path& dll_path,
                  bool suspended_launch, std::chrono::milliseconds timeout) {
    if (timeout.count() <= 0 || timeout.count() > static_cast<long long>(INFINITE - 1U))
        throw ProtocolError("Injection timeout is invalid");
    const auto dll = FullExistingFile(dll_path, "Injection DLL");
    if (_wcsicmp(dll.extension().c_str(), L".dll") != 0)
        throw ProtocolError("Injection file must have a .dll extension");
    Handle process(OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                               PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                               FALSE, process_id));
    if (!process.Get()) Fail("OpenProcess(injection target)");
    if (QueryProcessMachine(process.Get()) != QueryProcessMachine(GetCurrentProcess()))
        throw ProtocolError("Injector and target process architectures do not match");

    const auto text = dll.wstring();
    if (text.size() >= std::numeric_limits<SIZE_T>::max() / sizeof(wchar_t))
        throw ProtocolError("Injection DLL path is too long");
    const SIZE_T byte_count = (text.size() + 1) * sizeof(wchar_t);
    void* remote = VirtualAllocEx(process.Get(), nullptr, byte_count, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) Fail("VirtualAllocEx");
    bool release_remote = true;
    try {
        SIZE_T written = 0;
        if (!WriteProcessMemory(process.Get(), remote, text.c_str(), byte_count, &written) || written != byte_count)
            Fail("WriteProcessMemory");
        Handle thread(CreateRemoteThread(process.Get(), nullptr, 0,
                                         RemoteLoadLibrary(process_id, suspended_launch),
                                         remote, 0, nullptr));
        if (!thread.Get()) Fail("CreateRemoteThread(LoadLibraryW)");
        const auto wait = WaitForSingleObject(thread.Get(), static_cast<DWORD>(timeout.count()));
        if (wait == WAIT_TIMEOUT) {
            release_remote = false; // remote thread may still be reading the path
            throw ProtocolError("Remote LoadLibraryW timed out");
        }
        if (wait != WAIT_OBJECT_0) Fail("WaitForSingleObject(remote LoadLibraryW)");
        if (!HasRemoteModule(process_id, dll.filename().wstring()))
            throw ProtocolError("Remote LoadLibraryW completed but the DLL is not loaded");
    } catch (...) {
        if (release_remote) (void)VirtualFreeEx(process.Get(), remote, 0, MEM_RELEASE);
        throw;
    }
    if (!VirtualFreeEx(process.Get(), remote, 0, MEM_RELEASE)) Fail("VirtualFreeEx");
}

void ProcessInjector::Inject(DWORD process_id, const std::filesystem::path& dll_path,
                             std::chrono::milliseconds timeout) {
    InjectModule(process_id, dll_path, false, timeout);
}

void ProcessInjector::InjectAndStart(DWORD process_id, const std::filesystem::path& dll_path,
                                     const InjectionOptions& options,
                                     std::chrono::milliseconds timeout) {
    const auto bootstrap = MakeBootstrap(options);
    const auto dll = FullExistingFile(dll_path, "Injection DLL");
    InjectModule(process_id, dll, options.suspended_launch, timeout);

    Handle process(OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                               PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                               FALSE, process_id));
    if (!process.Get()) Fail("OpenProcess(injection target entry)");
    if (QueryProcessMachine(process.Get()) != QueryProcessMachine(GetCurrentProcess()))
        throw ProtocolError("Injector and target process architectures do not match");

    void* remote = VirtualAllocEx(process.Get(), nullptr, sizeof(bootstrap),
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) Fail("VirtualAllocEx(injection bootstrap)");
    bool release_remote = true;
    try {
        SIZE_T written = 0;
        if (!WriteProcessMemory(process.Get(), remote, &bootstrap, sizeof(bootstrap), &written) ||
            written != sizeof(bootstrap))
            Fail("WriteProcessMemory(injection bootstrap)");
        Handle thread(CreateRemoteThread(process.Get(), nullptr, 0,
                                         RemoteExport(process_id, dll, "WpeStart"),
                                         remote, 0, nullptr));
        if (!thread.Get()) Fail("CreateRemoteThread(WpeStart)");
        const auto wait = WaitForSingleObject(thread.Get(), static_cast<DWORD>(timeout.count()));
        if (wait == WAIT_TIMEOUT) {
            release_remote = false;
            throw ProtocolError("Remote WpeStart timed out");
        }
        if (wait != WAIT_OBJECT_0) Fail("WaitForSingleObject(remote WpeStart)");
        DWORD result = 0;
        if (!GetExitCodeThread(thread.Get(), &result)) Fail("GetExitCodeThread(WpeStart)");
        if (result != static_cast<DWORD>(InjectionStartResult::Ok))
            throw ProtocolError("Remote WpeStart rejected bootstrap parameters with code " +
                                std::to_string(result));
    } catch (...) {
        if (release_remote) (void)VirtualFreeEx(process.Get(), remote, 0, MEM_RELEASE);
        throw;
    }
    if (!VirtualFreeEx(process.Get(), remote, 0, MEM_RELEASE))
        Fail("VirtualFreeEx(injection bootstrap)");
}

} // namespace wpe::shell
