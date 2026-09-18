#include "hook_manager.h"
#include "common/ipc_codec.h"
#include <MinHook.h>
#include <algorithm>
#include <string>

namespace wpe {
namespace {
std::mutex g_runtime_mutex;
std::size_t g_runtime_users{};
bool g_runtime_owned{};

[[noreturn]] void Fail(const char* operation, MH_STATUS status) {
    const char* text = MH_StatusToString(status);
    throw ProtocolError(std::string(operation) + " failed: " +
                        (text ? text : "unknown MinHook status"));
}
} // namespace

HookManager::~HookManager() { (void)Shutdown(); }

void HookManager::Initialize() {
    std::lock_guard lock(mutex_);
    if (initialized_) return;
    std::lock_guard runtime_lock(g_runtime_mutex);
    if (g_runtime_users == 0) {
        const auto status = MH_Initialize();
        if (status != MH_OK && status != MH_ERROR_ALREADY_INITIALIZED)
            Fail("MH_Initialize", status);
        g_runtime_owned = status == MH_OK;
    }
    ++g_runtime_users;
    initialized_ = true;
    owns_runtime_ = g_runtime_owned;
}

void* HookManager::Create(const char* module, const char* procedure,
                          void* detour, void** original) {
    if (!module || !*module || !procedure || !*procedure || !detour || !original)
        throw ProtocolError("Hook creation arguments are invalid");
    std::lock_guard lock(mutex_);
    if (!initialized_) throw ProtocolError("Hook manager is not initialized");
    const auto loaded = GetModuleHandleA(module);
    if (!loaded) throw ProtocolError(std::string("Hook module is not loaded: ") + module);
    const auto target = reinterpret_cast<void*>(GetProcAddress(loaded, procedure));
    if (!target) throw ProtocolError(std::string("Hook procedure was not found: ") + procedure);
    if (Contains(target)) throw ProtocolError("Hook target is already registered");
    const auto status = MH_CreateHook(target, detour, original);
    if (status != MH_OK) Fail("MH_CreateHook", status);
    targets_.push_back(target);
    return target;
}

void HookManager::Enable(void* target) {
    std::lock_guard lock(mutex_);
    if (!initialized_ || !Contains(target))
        throw ProtocolError("Hook target is not registered");
    const auto status = MH_EnableHook(target);
    if (status != MH_OK && status != MH_ERROR_ENABLED) Fail("MH_EnableHook", status);
}

bool HookManager::Disable(void* target) noexcept {
    std::lock_guard lock(mutex_);
    if (!initialized_ || !Contains(target)) return false;
    const auto status = MH_DisableHook(target);
    return status == MH_OK || status == MH_ERROR_DISABLED;
}

bool HookManager::DisableAll() noexcept {
    std::lock_guard lock(mutex_);
    if (!initialized_) return true;
    // MinHook is process-global and may already be owned by the host. Never
    // use MH_ALL_HOOKS here: only disable registrations created by this owner.
    bool success = true;
    for (auto it = targets_.rbegin(); it != targets_.rend(); ++it) {
        const auto status = MH_DisableHook(*it);
        if (status != MH_OK && status != MH_ERROR_DISABLED) success = false;
    }
    return success;
}

bool HookManager::Shutdown() noexcept {
    std::lock_guard lock(mutex_);
    if (!initialized_) return true;
    std::vector<void*> remaining;
    remaining.reserve(targets_.size());
    for (auto it = targets_.rbegin(); it != targets_.rend(); ++it) {
        const auto disable = MH_DisableHook(*it);
        if (disable != MH_OK && disable != MH_ERROR_DISABLED) {
            remaining.push_back(*it);
            continue;
        }
        const auto remove = MH_RemoveHook(*it);
        if (remove != MH_OK && remove != MH_ERROR_NOT_CREATED)
            remaining.push_back(*it);
    }
    if (!remaining.empty()) {
        std::reverse(remaining.begin(), remaining.end());
        targets_ = std::move(remaining);
        return false;
    }
    targets_.clear();
    {
        std::lock_guard runtime_lock(g_runtime_mutex);
        if (g_runtime_users == 1 && g_runtime_owned) {
            const auto status = MH_Uninitialize();
            if (status != MH_OK && status != MH_ERROR_NOT_INITIALIZED)
                return false;
            g_runtime_owned = false;
        }
        if (g_runtime_users != 0) --g_runtime_users;
    }
    initialized_ = false;
    owns_runtime_ = false;
    return true;
}

bool HookManager::Initialized() const noexcept {
    std::lock_guard lock(mutex_);
    return initialized_;
}

std::size_t HookManager::HookCount() const noexcept {
    std::lock_guard lock(mutex_);
    return targets_.size();
}

bool HookManager::Contains(void* target) const noexcept {
    return std::find(targets_.begin(), targets_.end(), target) != targets_.end();
}

} // namespace wpe
