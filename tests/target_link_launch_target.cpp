#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

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
} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc != 4) return ERROR_INVALID_PARAMETER;

    // The process is created with CREATE_SUSPENDED by the test.  Reaching this
    // point is therefore the observable proof that the shell resumed the
    // primary thread only after IPC injection and StartHook completed.
    Handle entered(OpenEventW(EVENT_MODIFY_STATE, FALSE, argv[1]));
    Handle release(OpenEventW(SYNCHRONIZE, FALSE, argv[2]));
    Handle exited(OpenEventW(EVENT_MODIFY_STATE, FALSE, argv[3]));
    if (!entered.get() || !release.get() || !exited.get())
        return static_cast<int>(GetLastError());

    if (!SetEvent(entered.get())) return static_cast<int>(GetLastError());
    const auto wait = WaitForSingleObject(release.get(), 10000);
    if (wait != WAIT_OBJECT_0) return ERROR_TIMEOUT;
    if (!SetEvent(exited.get())) return static_cast<int>(GetLastError());
    return 0;
}
