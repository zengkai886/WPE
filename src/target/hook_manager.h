#pragma once

#include <Windows.h>
#include <mutex>
#include <vector>

namespace wpe {

// Thin RAII boundary around the process-global MinHook runtime. The injected
// target owns one instance and destroys it only after command/executor threads
// have stopped, so no trampoline can outlive its target function pointers.
class HookManager final {
public:
    HookManager() = default;
    ~HookManager();
    HookManager(const HookManager&) = delete;
    HookManager& operator=(const HookManager&) = delete;

    void Initialize();
    void* Create(const char* module, const char* procedure,
                 void* detour, void** original);
    void Enable(void* target);
    [[nodiscard]] bool Disable(void* target) noexcept;
    [[nodiscard]] bool DisableAll() noexcept;
    // False means at least one owned registration/runtime resource could not
    // be released and remains tracked for a later retry.
    [[nodiscard]] bool Shutdown() noexcept;

    [[nodiscard]] bool Initialized() const noexcept;
    [[nodiscard]] std::size_t HookCount() const noexcept;

private:
    bool Contains(void* target) const noexcept;

    mutable std::mutex mutex_;
    std::vector<void*> targets_;
    bool initialized_{};
    bool owns_runtime_{};
};

} // namespace wpe
