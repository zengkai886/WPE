#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "process_injector.h"
#include "common/ipc_codec.h"
#include <Windows.h>
#include <cstdint>
#include <filesystem>
#include <cwchar>
#include <stdexcept>
#include <string>
#include <string_view>

static_assert(sizeof(void*) == 4, "wpe64-x86-helper must be built with the Win32 generator");

namespace {
class Handle final {
public:
    explicit Handle(HANDLE value = nullptr) noexcept : value_(value) {}
    ~Handle() { if (value_) CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    [[nodiscard]] HANDLE get() const noexcept { return value_; }

private:
    HANDLE value_{};
};

std::wstring Arg(const wchar_t* value) { return value ? std::wstring(value) : std::wstring{}; }
std::string Narrow(const wchar_t* value) {
    const auto text = Arg(value);
    std::string result;
    result.reserve(text.size());
    for (const auto character : text) {
        if (character > 0x7f) throw wpe::ProtocolError("x86 helper session is not ASCII");
        result.push_back(static_cast<char>(character));
    }
    return result;
}
DWORD Number(const wchar_t* value) {
    try {
        const auto text = Arg(value);
        std::size_t used = 0;
        const auto result = std::stoul(text, &used, 10);
        if (used != text.size() || result > 0xffffffffUL) throw std::runtime_error("invalid number");
        return static_cast<DWORD>(result);
    } catch (...) {
        throw wpe::ProtocolError("x86 helper PID is invalid");
    }
}

Handle OpenNamed(const wchar_t* name, DWORD access) {
    const auto handle = OpenEventW(access, FALSE, name);
    if (!handle) throw wpe::ProtocolError("x86 helper event is unavailable");
    return Handle(handle);
}

int Attach(int argc, wchar_t** argv) {
    if (argc != 6) return ERROR_INVALID_PARAMETER;
    auto ready = OpenNamed(argv[5], EVENT_MODIFY_STATE);
    wpe::shell::InjectionOptions options{Narrow(argv[4]), 5000, false};
    wpe::shell::ProcessInjector::InjectAndStart(Number(argv[2]), argv[3], options);
    if (!SetEvent(ready.get())) throw wpe::ProtocolError("x86 helper could not signal ready");
    return 0;
}

int Launch(int argc, wchar_t** argv) {
    if (argc != 9) return ERROR_INVALID_PARAMETER;
    const auto executable = std::filesystem::path(argv[2]);
    const auto arguments = std::wstring_view(argv[3]);
    const auto dll = std::filesystem::path(argv[4]);
    const std::string session = Narrow(argv[5]);
    auto ready = OpenNamed(argv[6], EVENT_MODIFY_STATE);
    auto resume = OpenNamed(argv[7], SYNCHRONIZE);
    auto abort = OpenNamed(argv[8], SYNCHRONIZE);
    auto child = wpe::shell::ProcessInjector::LaunchSuspended(
        executable, arguments, executable.parent_path());
    wpe::shell::InjectionOptions options{session, 5000, true};
    wpe::shell::ProcessInjector::InjectAndStart(child.Pid(), dll, options);
    if (!SetEvent(ready.get())) throw wpe::ProtocolError("x86 helper could not signal ready");

    HANDLE waits[] = {resume.get(), abort.get()};
    const auto selected = WaitForMultipleObjects(2, waits, FALSE, 30000);
    if (selected == WAIT_OBJECT_0) {
        child.Resume();
        return 0;
    }
    if (selected == WAIT_OBJECT_0 + 1) return ERROR_CANCELLED;
    if (selected == WAIT_TIMEOUT) throw wpe::ProtocolError("x86 helper resume timed out");
    throw wpe::ProtocolError("x86 helper wait failed");
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc < 2) return ERROR_INVALID_PARAMETER;
        const auto mode = std::wstring_view(argv[1]);
        if (mode == L"--attach") return Attach(argc, argv);
        if (mode == L"--launch") return Launch(argc, argv);
        return ERROR_INVALID_PARAMETER;
    } catch (...) {
        return ERROR_GEN_FAILURE;
    }
}
