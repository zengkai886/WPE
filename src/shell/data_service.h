#pragma once
#include "database.h"
#include <array>
#include <cstdint>
#include <set>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
namespace wpe::shell {
class StoreEventCommittedError final : public std::runtime_error {
public:
    explicit StoreEventCommittedError(std::string message)
        : std::runtime_error(std::move(message)) {}
};
// Business/data seam: original RPC argument/result names and original FeedRow fields.
// Single-worker confined; the browser has no access to SQL, paths or model mutation.
class DataService {
public:
    using Emit=std::function<void(std::string,Json)>;
    DataService(const std::filesystem::path& database,Emit emit);
    static std::vector<std::string> Methods();
    Json Call(const std::string& method,const Json& args);
    // Applies one target-side StoreAdded event. This is intentionally a
    // native seam rather than a browser RPC: the target event pipe is parsed
    // and committed on the data worker before the warehouse feed is emitted.
    bool ApplyStoreEvent(std::span<const std::uint8_t> frame);
    void PublishAll();
    Json Prefs() const;
    // Target-facing snapshot used when publishing configuration to the
    // injected headless core. Robot execution is deliberately excluded.
    Json TargetConfiguration() const;
    static bool NeedsConfirmation(const std::string& method,const Json& args);
    static bool NeedsOpenFile(const std::string& method,const Json& args);
    static bool NeedsSaveFile(const std::string& method,const Json& args);
    static std::string FileKind(const std::string& method,const Json& args);
private:
    Json FileInfo(const std::string& kind,bool save)const;
    std::optional<Json> CallFiles(const std::string& method,const Json& args);
    Json PrepareParentExport(const std::string& method,const Json& args);
    Json ApplyImport(const std::string& method,const Json& args,std::string_view bytes);
    void PersistList(int list,const Json& rows);
    void PersistIpRules(int list,const Json& rows);
    void PersistAccounts(const Json& rows);
    void PersistAutoStores(const Json& rows);
    void PersistMap(int list,const Json& rows);
    void PersistServers(const Json& rows);
    void PersistNotices(const Json& rows);
    void RefreshExportAliases(int list);
    Json PrepareExport(const std::string& method,const Json& args);
    Json WriteExport(Json plan,const std::string& path,const std::string& password={});
    std::optional<Json> CallEditor(const std::string& method,const Json& args);
    std::optional<Json> CallConfigLists(const std::string& method,const Json& args);
    Json InstructionRows();
    std::string ValidateInstruction(int type,const std::string& content);
    Json SaveRobot(const Json& args);
    Json* EditPacket(const std::string& id);
    void TrimStores(Json& items) const;
    Json NewRow(int list);
    Json Rows(int list) const;
    void Publish(int list);
    void SaveList(int list,const Json& rows);
    void SaveIpRules(int list,const Json& rows);
    void SaveAccounts(const Json& rows);
    void SaveConfig(const Json& changes);
    void SaveInjectConfig(const Json& changes);
    void SaveProxyConfig(const Json& changes);
    Json FilterEdit(const Json& row) const;
    Json SaveFilter(const Json& args);
    Json ListAction(int list,const Json& args);
    Json* Find(int list,const std::string& id);
    std::string Text(const std::string& key,const std::string& fallback) const;
    Database db_;
    Emit emit_;
    Json config_;
    Json inject_config_;
    Json proxy_config_;
    std::array<Json,19> lists_;
    Json send_edit_=nullptr,robot_edit_=nullptr;
    std::map<std::string,Json> export_plans_; // Membership frozen; PacketInfo fields retain alias semantics.
    struct ImportPlan {std::string method,bytes;Json args;};
    std::map<std::string,ImportPlan> import_plans_;
    std::uint64_t packet_id_{};
    bool hook_tcp_req_{true},hook_tcp_resp_{true},hook_udp_req_{true},hook_udp_resp_{true};
    bool auto_stores_enabled_{}; // Upstream runtime-only switch; deliberately resets on restart.
};
}
