#pragma once
#include "web_bridge.h"
#include <filesystem>
#include <functional>
struct sqlite3;
namespace wpe::shell {
// Only used by the shell's data worker. Never linked into an injected DLL.
class Database {
public:
    explicit Database(const std::filesystem::path& path);
    ~Database();
    Database(const Database&)=delete;
    Database& operator=(const Database&)=delete;
    Json Query(const std::string& sql,const Json& parameters=Json::array());
    void Execute(const std::string& sql,const Json& parameters=Json::array());
    void Transaction(const std::function<void()>& action);
    void Replace(const std::string& table,const Json& rows);
private:
    sqlite3* db_{};
};
}
