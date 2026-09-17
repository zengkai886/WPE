#pragma once
#include "database.h"
#include <array>
#include <set>
namespace wpe::shell {
// Business/data seam: original RPC argument/result names and original FeedRow fields.
// Single-worker confined; the browser has no access to SQL, paths or model mutation.
class DataService {
public:
    using Emit=std::function<void(std::string,Json)>;
    DataService(const std::filesystem::path& database,Emit emit);
    static std::vector<std::string> Methods();
    Json Call(const std::string& method,const Json& args);
    void PublishAll();
    Json Prefs() const;
    static bool NeedsConfirmation(const std::string& method,const Json& args);
private:
    Json NewRow(int list);
    Json Rows(int list) const;
    void Publish(int list);
    void SaveList(int list,const Json& rows);
    void SaveConfig(const Json& changes);
    Json FilterEdit(const Json& row) const;
    Json SaveFilter(const Json& args);
    Json ListAction(int list,const Json& args);
    Json* Find(int list,const std::string& id);
    std::string Text(const std::string& key,const std::string& fallback) const;
    Database db_;
    Emit emit_;
    Json config_;
    std::array<Json,19> lists_;
    Json send_edit_=nullptr,robot_edit_=nullptr;
    std::uint64_t packet_id_{};
};
}
