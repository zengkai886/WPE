#include "hook_manager.h"
#include "common/ipc_codec.h"
#include <MinHook.h>
#include <algorithm>
#include <string>

namespace wpe {
namespace {
[[noreturn]] void Fail(const char* operation, MH_STATUS status) {
    const char* text = MH_StatusToString(status);
    throw ProtocolError(std::string(operation) + " failed: " +
                        (text ? text : "unknown MinHook status"));
}
} // namespace

HookManager::~HookManager() { Shutdown(); }

void HookManager::Initialize() {
    std::lock_guard lock(mutex_);
    if (initialized_) return;
    const auto status = MH_Initialize();
    if (status != MH_OK && status != MH_ERROR_ALREADY_INITIALIZED)
        Fail("MH_Initialize", status);
    initialized_ = true;
    owns_runtime_ = status == MH_OK;
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

void HookManager::Disable(void* target) noexcept {
    std::lock_guard lock(mutex_);
    if (!initialized_ || !Contains(target)) return;
    const auto status = MH_DisableHook(target);
    (void)status;
}

void HookManager::DisableAll() noexcept {
    std::lock_guard lock(mutex_);
    if (!initialized_) return;
    const auto status = MH_DisableHook(MH_ALL_HOOKS);
    (void)status;
}

void HookManager::Shutdown() noexcept {
    std::lock_guard lock(mutex_);
    if (!initialized_) return;
    (void)MH_DisableHook(MH_ALL_HOOKS);
    for (auto it = targets_.rbegin(); it != targets_.rend(); ++it)
        (void)MH_RemoveHook(*it);
    targets_.clear();
    if (owns_runtime_) (void)MH_Uninitialize();
    initialized_ = false;
    owns_runtime_ = false;
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
