#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace wpe::shell {

enum class ProcessMachine : std::uint8_t { Unknown, X86, X64, Arm64 };

ProcessMachine QueryProcessMachine(HANDLE process);

class SuspendedProcess final {
public:
    SuspendedProcess() noexcept = default;
    ~SuspendedProcess();
    SuspendedProcess(const SuspendedProcess&) = delete;
    SuspendedProcess& operator=(const SuspendedProcess&) = delete;
    SuspendedProcess(SuspendedProcess&& other) noexcept;
    SuspendedProcess& operator=(SuspendedProcess&& other) noexcept;

    [[nodiscard]] DWORD Pid() const noexcept { return process_id_; }
    [[nodiscard]] HANDLE ProcessHandle() const noexcept { return process_; }
    void Resume();

private:
    friend class ProcessInjector;
    SuspendedProcess(HANDLE process, HANDLE thread, DWORD process_id) noexcept;
    void Close() noexcept;
    HANDLE process_{nullptr};
    HANDLE thread_{nullptr};
    DWORD process_id_{};
    bool resumed_{};
};

class ProcessInjector final {
public:
    static SuspendedProcess LaunchSuspended(const std::filesystem::path& executable,
                                            std::wstring_view arguments = {},
                                            const std::filesystem::path& working_directory = {});
    static void Inject(DWORD process_id, const std::filesystem::path& dll_path,
                       std::chrono::milliseconds timeout = std::chrono::seconds(10));
};

} // namespace wpe::shell
