#include "database.h"
#include <sqlite/sqlite3.h>
#include <limits>
#include <memory>

namespace wpe::shell {
namespace {
void Check(sqlite3* db,int code){if(code!=SQLITE_OK)throw std::runtime_error("SQLite: "+std::string(db?sqlite3_errmsg(db):"open failed"));}
std::string Identifier(const std::string& text){
    if(text.empty()||text.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")!=std::string::npos)throw std::invalid_argument("Invalid SQL identifier");
    return '"'+text+'"';
}
using Statement=std::unique_ptr<sqlite3_stmt,decltype(&sqlite3_finalize)>;
Statement Prepare(sqlite3* db,const std::string& sql,const Json& parameters){
    sqlite3_stmt* raw=nullptr;
    const auto rc=sqlite3_prepare_v2(db,sql.c_str(),-1,&raw,nullptr);
    Statement result(raw,sqlite3_finalize);Check(db,rc);
    if(!raw)throw std::invalid_argument("Empty SQL");
    if(parameters.size()!=static_cast<std::size_t>(sqlite3_bind_parameter_count(raw)))throw std::invalid_argument("SQL parameter count mismatch");
    int i=0;
    for(const auto& value:parameters){
        ++i;int status=SQLITE_OK;
        if(value.is_null())status=sqlite3_bind_null(raw,i);
        else if(value.is_boolean())status=sqlite3_bind_int(raw,i,value.get<bool>()?1:0);
        else if(value.is_number_integer())status=sqlite3_bind_int64(raw,i,value.get<std::int64_t>());
        else if(value.is_number_float())status=sqlite3_bind_double(raw,i,value.get<double>());
        else if(value.is_binary()){
            const auto& b=value.get_binary();
            // A zero-length blob must not become SQL NULL.
            status=b.empty()?sqlite3_bind_zeroblob(raw,i,0):sqlite3_bind_blob64(raw,i,b.data(),b.size(),SQLITE_TRANSIENT);
        }else if(value.is_string()){
            const auto& s=value.get_ref<const std::string&>();
            status=sqlite3_bind_text64(raw,i,s.data(),s.size(),SQLITE_TRANSIENT,SQLITE_UTF8);
        }else throw std::invalid_argument("Non-scalar database value");
        Check(db,status);
    }
    return result;
}
}
Database::Database(const std::filesystem::path& path){
    if(!path.parent_path().empty())std::filesystem::create_directories(path.parent_path());
    const auto bytes=path.u8string();
    const auto rc=sqlite3_open_v2(reinterpret_cast<const char*>(bytes.c_str()),&db_,SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE|SQLITE_OPEN_FULLMUTEX,nullptr);
    try{Check(db_,rc);Check(db_,sqlite3_busy_timeout(db_,1000));Execute("PRAGMA foreign_keys=ON");Execute("PRAGMA synchronous=FULL");}
    catch(...){if(db_)sqlite3_close(db_);db_=nullptr;throw;}
}
Database::~Database(){if(db_)sqlite3_close(db_);}
Json Database::Query(const std::string& sql,const Json& parameters){
    auto stmt=Prepare(db_,sql,parameters);Json rows=Json::array();int rc;
    while((rc=sqlite3_step(stmt.get()))==SQLITE_ROW){
        Json row=Json::object();
        for(int i=0;i<sqlite3_column_count(stmt.get());++i){
            auto& v=row[sqlite3_column_name(stmt.get(),i)];
            switch(sqlite3_column_type(stmt.get(),i)){
            case SQLITE_INTEGER:v=sqlite3_column_int64(stmt.get(),i);break;
            case SQLITE_FLOAT:v=sqlite3_column_double(stmt.get(),i);break;
            case SQLITE_TEXT:v=std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(),i)),static_cast<std::size_t>(sqlite3_column_bytes(stmt.get(),i)));break;
            case SQLITE_BLOB:{const auto n=sqlite3_column_bytes(stmt.get(),i);const auto p=static_cast<const std::uint8_t*>(sqlite3_column_blob(stmt.get(),i));v=Json::binary(n?std::vector<std::uint8_t>(p,p+n):std::vector<std::uint8_t>{});break;}
            default:v=nullptr;
            }
        }rows.push_back(std::move(row));
    }
    if(rc!=SQLITE_DONE)Check(db_,rc);return rows;
}
void Database::Execute(const std::string& sql,const Json& parameters){
    if(!parameters.empty()){
        auto stmt=Prepare(db_,sql,parameters);const auto rc=sqlite3_step(stmt.get());if(rc!=SQLITE_DONE)Check(db_,rc);
    }else Check(db_,sqlite3_exec(db_,sql.c_str(),nullptr,nullptr,nullptr));
}
void Database::Transaction(const std::function<void()>& action){
    Execute("BEGIN IMMEDIATE");
    try{action();Execute("COMMIT");}catch(...){try{Execute("ROLLBACK");}catch(...){}throw;}
}
void Database::Replace(const std::string& table,const Json& rows){
    Execute("DELETE FROM "+Identifier(table));
    for(const auto& row:rows){
        std::string columns,slots;Json params=Json::array();
        for(auto it=row.begin();it!=row.end();++it){if(!columns.empty()){columns+=',';slots+=',';}columns+=Identifier(it.key());slots+='?';params.push_back(it.value());}
        Execute("INSERT INTO "+Identifier(table)+" ("+columns+") VALUES ("+slots+")",params);
    }
}
}
