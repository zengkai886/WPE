#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <objbase.h>
#include "data_service.h"
#include "data_schema.h"
#include "data_l10n.h"
#include "common/ipc_codec.h"
#include "common/ipc_protocol.h"
#include <algorithm>
#include <charconv>
#include <iomanip>
#include <regex>
#include <random>
#include <sstream>
#include <cmath>
#include <unordered_map>
#include <unordered_set>
#include <cstring>

#include "data_util.h"
namespace wpe::shell {
using namespace data_detail;
namespace {
Json BatchRows(const Json& args){
    Json rows=Json::array();const auto it=args.find("rows");if(it==args.end()||!it->is_array())return rows;
    for(const auto& source:*it){
        if(!source.is_object())continue;const auto user=S(source,"UserName"),password=S(source,"Password");
        // Upstream tests IsNullOrEmpty before Trim. Whitespace-only rows are
        // retained here and rejected by AddBatchAccounts later.
        if(!user.empty()&&!password.empty())rows.push_back({{"UserName",Trim(user)},{"Password",Trim(password)}});
    }return rows;
}
std::string BatchExpiry(const Json& args){
    if(const auto value=DateTimeText(S(args,"expiryTime")))return *value;
    const auto value=AddDateTimeYears(LocalDateTime(),100);if(!value)throw std::runtime_error("批量账号过期时间超出范围");return *value;
}
std::string BatchPassword(int length){
    static constexpr std::string_view chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    static std::mt19937 random([]{std::random_device source;std::seed_seq seed{source(),source(),source(),source()};return std::mt19937(seed);}());
    std::uniform_int_distribution<std::size_t> pick(0,chars.size()-1);std::string password;password.reserve(static_cast<std::size_t>(length));
    for(int i=0;i<length;++i)password+=chars[pick(random)];return password;
}
std::string BatchTimeHead(){SYSTEMTIME now{};GetLocalTime(&now);char text[7]{};sprintf_s(text,"%02u%02u%02u",now.wHour,now.wMinute,now.wSecond);return text;}
class Winsock final{public:Winsock(){WSADATA data{};ready_=WSAStartup(MAKEWORD(2,2),&data)==0;}~Winsock(){if(ready_)WSACleanup();}explicit operator bool()const{return ready_;}private:bool ready_{};};
Json LocalAddresses(){
    const Winsock winsock;if(!winsock)return Json::array();
    ULONG bytes=0;const ULONG flags=GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST|GAA_FLAG_SKIP_DNS_SERVER;
    if(GetAdaptersAddresses(AF_UNSPEC,flags,nullptr,nullptr,&bytes)!=ERROR_BUFFER_OVERFLOW)return Json::array();
    std::vector<std::byte> storage(bytes);auto* first=reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data());
    if(GetAdaptersAddresses(AF_UNSPEC,flags,nullptr,first,&bytes)!=NO_ERROR)return Json::array();
    Json result=Json::array();std::set<std::string> seen;
    for(auto* adapter=first;adapter;adapter=adapter->Next){if(adapter->OperStatus!=IfOperStatusUp)continue;for(auto* item=adapter->FirstUnicastAddress;item;item=item->Next){
        if(!item->Address.lpSockaddr)continue;const void* source=nullptr;ULONG scope=0;
        if(item->Address.lpSockaddr->sa_family==AF_INET)source=&reinterpret_cast<const SOCKADDR_IN*>(item->Address.lpSockaddr)->sin_addr;
        else if(item->Address.lpSockaddr->sa_family==AF_INET6){const auto* address=reinterpret_cast<const SOCKADDR_IN6*>(item->Address.lpSockaddr);source=&address->sin6_addr;scope=address->sin6_scope_id;}else continue;
        wchar_t wide[INET6_ADDRSTRLEN]{};if(!InetNtopW(item->Address.lpSockaddr->sa_family,const_cast<void*>(source),wide,std::size(wide)))continue;
        const auto count=WideCharToMultiByte(CP_UTF8,0,wide,-1,nullptr,0,nullptr,nullptr);if(count<=1)continue;std::string value(static_cast<std::size_t>(count),0);WideCharToMultiByte(CP_UTF8,0,wide,-1,value.data(),count,nullptr,nullptr);value.pop_back();if(scope)value+="%"+std::to_string(scope);
        if(seen.insert(value).second)result.push_back(value);
    }}
    // Prefer a routable IPv4 address for the display value.  On Windows the
    // first adapter is often an IPv6 link-local address (fe80::...%N).  That
    // address is valid for diagnostics but is a poor default for a proxy
    // listener and the scope suffix is not accepted by InetPtonA.  The native
    // listener still binds 0.0.0.0 in auto mode; this ordering keeps the UI
    // endpoint consistent with what users can actually connect to.
    std::stable_sort(result.begin(),result.end(),[](const Json& left,const Json& right){
        const auto a=left.is_string()?left.get<std::string>():std::string{};
        const auto b=right.is_string()?right.get<std::string>():std::string{};
        return (a.find(':')==a.npos)>(b.find(':')==b.npos);
    });
    return result;
}
std::uint64_t PhysicalMemory(){MEMORYSTATUSEX info{};info.dwLength=sizeof(info);return GlobalMemoryStatusEx(&info)?info.ullTotalPhys:0;}
int MaxConnectionCap(){constexpr std::uint64_t mb=1024ull*1024ull;std::uint64_t bytes;
#if defined(_WIN64)
    const auto physical=PhysicalMemory();bytes=physical?std::min<std::uint64_t>(physical/2,1536ull*mb):512ull*mb;
#else
    bytes=256ull*mb;
#endif
    return static_cast<int>(std::max<std::uint64_t>(1,bytes/(16ull*1024ull)));
}
bool ValidIp(const std::string& value){const Winsock winsock;if(!winsock)return false;IN_ADDR v4{};IN6_ADDR v6{};return InetPtonA(AF_INET,value.c_str(),&v4)==1||InetPtonA(AF_INET6,value.c_str(),&v6)==1;}
std::string Address(const Json& proxy,const Json& local,bool http){
    if(http&&!B(proxy,"Enable_HTTP"))return {};std::string ip=S(proxy,"ProxyIP");if(B(proxy,"ProxyIP_Auto",true)||ip.empty())ip=local.empty()?"0.0.0.0":local[0].get<std::string>();
    if(ip.find(':')!=ip.npos)ip="["+ip+"]";return ip+":"+std::to_string(N(proxy,http?"HTTP_Port":"SOCKS5_Port",http?1081:1080));
}

std::vector<std::uint8_t> DecodeHexLoose(std::string_view text){
    std::vector<std::uint8_t> out;int high=-1;
    for(const unsigned char c:text){
        if(c==' '||c=='\t'||c=='\r'||c=='\n'||c==':'||c=='-')continue;
        const int v=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:-1;
        if(v<0)return {};
        if(high<0)high=v;else{out.push_back(static_cast<std::uint8_t>((high<<4)|v));high=-1;}
    }
    return high<0?out:std::vector<std::uint8_t>{};
}
std::string HexBytes(std::span<const std::uint8_t> bytes){
    static constexpr char digits[]="0123456789ABCDEF";std::string out;out.reserve(bytes.size()*3);
    for(std::size_t i=0;i<bytes.size();++i){if(i)out+=' ';out+=digits[bytes[i]>>4];out+=digits[bytes[i]&15];}return out;
}
std::string B64Bytes(std::span<const std::uint8_t> bytes){
    static constexpr char alphabet[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";std::string out;
    for(std::size_t i=0;i<bytes.size();i+=3){const auto a=bytes[i];const std::uint8_t b=i+1<bytes.size()?bytes[i+1]:0;const std::uint8_t c=i+2<bytes.size()?bytes[i+2]:0;out+=alphabet[a>>2];out+=alphabet[((a&3)<<4)|(b>>4)];out+=i+1<bytes.size()?alphabet[((b&15)<<2)|(c>>6)]:'=';out+=i+2<bytes.size()?alphabet[c&63]:'=';}return out;
}
std::vector<std::uint8_t> Unb64(std::string_view text){
    std::string s;for(const auto c:text)if(c!=' '&&c!='\r'&&c!='\n'&&c!='\t')s+=c;
    auto val=[](char c){return c>='A'&&c<='Z'?c-'A':c>='a'&&c<='z'?c-'a'+26:c>='0'&&c<='9'?c-'0'+52:c=='+'?62:c=='/'?63:-1;};
    if(s.size()%4)return {};
    std::vector<std::uint8_t> out;for(std::size_t i=0;i<s.size();i+=4){const int a=val(s[i]),b=val(s[i+1]),c=s[i+2]=='='?-1:val(s[i+2]),d=s[i+3]=='='?-1:val(s[i+3]);if(a<0||b<0||c<-1||d<-1)return {};out.push_back(static_cast<std::uint8_t>((a<<2)|(b>>4)));if(c>=0){out.push_back(static_cast<std::uint8_t>((b<<4)|(c>>2)));if(d>=0)out.push_back(static_cast<std::uint8_t>((c<<6)|d));}}return out;
}
std::wstring DecodeCp(UINT cp,std::span<const std::uint8_t> bytes){
    if(bytes.empty())return {};const int n=MultiByteToWideChar(cp,MB_ERR_INVALID_CHARS,reinterpret_cast<const char*>(bytes.data()),static_cast<int>(bytes.size()),nullptr,0);if(n<=0)return {};
    std::wstring out(static_cast<std::size_t>(n),L'\0');MultiByteToWideChar(cp,MB_ERR_INVALID_CHARS,reinterpret_cast<const char*>(bytes.data()),static_cast<int>(bytes.size()),out.data(),n);return out;
}
std::vector<std::uint8_t> EncodeCp(UINT cp,std::wstring_view text){
    if(text.empty())return {};const int n=WideCharToMultiByte(cp,0,text.data(),static_cast<int>(text.size()),nullptr,0,nullptr,nullptr);if(n<=0)return {};
    std::vector<std::uint8_t> out(static_cast<std::size_t>(n));WideCharToMultiByte(cp,0,text.data(),static_cast<int>(text.size()),reinterpret_cast<char*>(out.data()),n,nullptr,nullptr);return out;
}
std::string Utf8Bytes(std::span<const std::uint8_t> bytes){
    if(bytes.empty())return {};const int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,reinterpret_cast<const char*>(bytes.data()),static_cast<int>(bytes.size()),nullptr,0);if(n<=0)return std::string(reinterpret_cast<const char*>(bytes.data()),bytes.size());std::wstring w(static_cast<std::size_t>(n),L'\0');MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,reinterpret_cast<const char*>(bytes.data()),static_cast<int>(bytes.size()),w.data(),n);const int m=WideCharToMultiByte(CP_UTF8,0,w.data(),n,nullptr,0,nullptr,nullptr);std::string out(static_cast<std::size_t>(m),'\0');WideCharToMultiByte(CP_UTF8,0,w.data(),n,out.data(),m,nullptr,nullptr);return out;
}
std::string Utf8Wide(std::wstring_view text){
    if(text.empty())return {};
    const int n=WideCharToMultiByte(CP_UTF8,0,text.data(),static_cast<int>(text.size()),nullptr,0,nullptr,nullptr);if(n<=0)return {};
    std::string out(static_cast<std::size_t>(n),'\0');WideCharToMultiByte(CP_UTF8,0,text.data(),static_cast<int>(text.size()),out.data(),n,nullptr,nullptr);return out;
}
}

DataService::DataService(const std::filesystem::path& path,Emit emit):db_(path),emit_(std::move(emit)){
    for(auto& list:lists_)list=Json::array();
    db_.Transaction([&]{db_.Execute(data_schema);
        auto ensure=[&](const char* table,const char* column,const char* declaration){const auto info=db_.Query("PRAGMA table_info("+std::string(table)+")");
            if(std::none_of(info.begin(),info.end(),[&](const Json& row){return Upper(S(row,"name"))==Upper(column);}))db_.Execute("ALTER TABLE "+std::string(table)+" ADD COLUMN "+column+" "+declaration);
        };
        for(const auto& field:std::array<std::pair<const char*,const char*>,8>{{{"ThemeFollowSystem","BOOLEAN DEFAULT 0"},{"ScanLine","BOOLEAN DEFAULT 1"},{"StoresLimit","BOOLEAN DEFAULT 1"},{"StoresLimit_Value","INTEGER DEFAULT 5000"},{"LastInjectMethod","INTEGER DEFAULT 0"},{"LastInjectPath","TEXT"},{"LastInjectArgs","TEXT"},{"LastInjectTime","TEXT"}}})ensure("SystemConfig",field.first,field.second);
        ensure("ProxyMode","DriverType","INTEGER DEFAULT 1");ensure("ProxyMode","SelectProcessNames","TEXT");ensure("ProxyMode","Only_WPC_Client","BOOLEAN DEFAULT 0");
        // Column visibility is kept separately for proxy and inject mode, as
        // in the original client.  Older databases do not have these columns
        // yet, so add them idempotently before loading either config mirror.
        for(const auto suffix:{"ShowSocket","ShowType","ShowClientAddr","ShowClientLoc","ShowServerAddr","ShowServerLoc","ShowLen"}){
            const auto inject_name="PacketList_"+std::string(suffix);
            const auto proxy_name="ProxyList_"+std::string(suffix);
            ensure("InjectMode",inject_name.c_str(),"BOOLEAN DEFAULT 1");
            ensure("ProxyMode",proxy_name.c_str(),"BOOLEAN DEFAULT 1");
        }
    });
    auto settings=db_.Query("SELECT * FROM SystemConfig ORDER BY rowid LIMIT 1");
    if(settings.empty()){
        db_.Transaction([&]{db_.Execute("INSERT INTO SystemConfig DEFAULT VALUES");
            db_.Execute("UPDATE SystemConfig SET IsDark=1, DefaultLanguage='zh-CN', SystemColor=-15304705, FilterReplace_ForeColor=-20232, FilterReplace_BackColor=-11658154, FilterIntercept_ForeColor=-23112, FilterIntercept_BackColor=-11461589, FilterChange_ForeColor=-403345, FilterChange_BackColor=-11649779, FilterDisplay_ForeColor=-7673089, FilterDisplay_BackColor=-15908013");
        // These upstream columns are not exposed as working remote/hotkey features
        // yet, but must retain valid original defaults for original DB readers.
            db_.Execute("UPDATE SystemConfig SET IsShowInWindow=1, Remote_Port=88, CheckType_Value='0:0:0:0:0:0:0:0:0:0:0:0'");
            for(int i=1;i<=12;++i)db_.Execute("UPDATE SystemConfig SET HotKey"+std::to_string(i)+"=?",Json::array({"Ctrl + Alt + F"+std::to_string(i)}));
        });
        settings=db_.Query("SELECT * FROM SystemConfig ORDER BY rowid LIMIT 1");
    }
    config_=settings.at(0);
    auto inject=db_.Query("SELECT * FROM InjectMode ORDER BY rowid LIMIT 1");
    auto proxy=db_.Query("SELECT * FROM ProxyMode ORDER BY rowid LIMIT 1");
    if(inject.empty()||proxy.empty())db_.Transaction([&]{if(inject.empty())db_.Execute("INSERT INTO InjectMode DEFAULT VALUES");if(proxy.empty())db_.Execute("INSERT INTO ProxyMode DEFAULT VALUES");});
    if(inject.empty())inject=db_.Query("SELECT * FROM InjectMode ORDER BY rowid LIMIT 1");if(proxy.empty())proxy=db_.Query("SELECT * FROM ProxyMode ORDER BY rowid LIMIT 1");
    inject_config_=inject.at(0);proxy_config_=proxy.at(0);
    for(int list=8;list<=11;++list){
        auto rows=db_.Query("SELECT * FROM "+tables[list-8]+" ORDER BY rowid");
        for(auto& row:rows){
            row["GUID"]=Upper(S(row,"GUID"));row["_objectId"]=Guid();
            if(list>8)row["_children"]=RuntimeChildren(db_.Query("SELECT * FROM "+children[list-8]+" WHERE GUID=? COLLATE NOCASE ORDER BY rowid",Json::array({row["GUID"]})),list,packet_id_);
        }lists_[list]=std::move(rows);
    }
    for(int list=15;list<=16;++list){
        auto rows=db_.Query("SELECT * FROM "+std::string(list==15?"WhiteList":"BlackList")+" ORDER BY rowid");
        for(auto& row:rows){row["IsExpiry"]=B(row,"IsExpiry");row["IPLocation"]="";row["EffectCount"]=0;}
        lists_[list]=std::move(rows);
    }
    {auto rows=db_.Query("SELECT * FROM ProxyAccount ORDER BY rowid"),logins=db_.Query("SELECT * FROM ProxyAccountIPInfo ORDER BY rowid");for(auto& row:rows){for(const auto* key:{"IsEnable","IsLimitLinks","IsLimitDevices","IsExpiry"})row[key]=B(row,key);row["IsOnLine"]=false;row["_logins"]=Json::array();for(const auto& login:logins)if(Upper(S(login,"GUID"))==Upper(S(row,"GUID")))row["_logins"].push_back({{"LoginTime",S(login,"LoginTime")},{"LoginIP",S(login,"LoginIP")},{"IPLocation",""}});}lists_[5]=std::move(rows);}
    {auto rows=db_.Query("SELECT * FROM AutoStores ORDER BY rowid");for(auto& row:rows){row["IsEnable"]=B(row,"IsEnable");row["WID"]=Upper(S(row,"WID"));row["_id"]=Guid();}lists_[12]=std::move(rows);}
    {auto rows=db_.Query("SELECT * FROM ProxyMapLocal ORDER BY rowid");for(auto& row:rows){row["IsEnable"]=B(row,"IsEnable");row["_id"]=Guid();}lists_[13]=std::move(rows);}
    {auto rows=db_.Query("SELECT * FROM ProxyMapRemote ORDER BY rowid");for(auto& row:rows){row["IsEnable"]=B(row,"IsEnable");row["_id"]=Guid();}lists_[14]=std::move(rows);}
    {auto rows=db_.Query("SELECT * FROM ServerInfo ORDER BY rowid"),rules=db_.Query("SELECT * FROM ServerRuleInfo ORDER BY rowid");for(auto& row:rows){row["SID"]=Upper(S(row,"SID"));row["IsEnable"]=B(row,"IsEnable");row["_rules"]=Json::array();for(auto rule:rules)if(Upper(S(rule,"SID"))==S(row,"SID")){rule["RID"]=Upper(S(rule,"RID"));rule["IsEnable"]=B(rule,"IsEnable");rule.erase("SID");row["_rules"].push_back(std::move(rule));}}lists_[17]=std::move(rows);}
    {auto rows=db_.Query("SELECT * FROM NoticeInfo ORDER BY rowid");for(auto& row:rows){row["NID"]=Upper(S(row,"NID"));}lists_[18]=std::move(rows);}
}
bool DataService::ApplyStoreEvent(std::span<const std::uint8_t> frame){
    if(frame.empty()||frame.size()>static_cast<std::size_t>(wpe::IpcProtocol::MaxControlFrame))
        throw wpe::ProtocolError("StoreAdded event frame is out of bounds");
    wpe::IpcReader reader(frame);
    if(static_cast<wpe::IpcEvent>(reader.U8())!=wpe::IpcEvent::StoreAdded)
        throw wpe::ProtocolError("Unexpected target event for warehouse ingestion");
    const auto warehouse_id=data_detail::Upper(reader.Guid_().ToString());
    const auto bytes=reader.Bytes();
    if(!bytes)throw wpe::ProtocolError("StoreAdded event bytes cannot be null");
    if(reader.Remaining()!=0)throw wpe::ProtocolError("StoreAdded event has trailing fields");
    auto* warehouse=Find(11,warehouse_id);
    if(!warehouse)return false; // A deleted warehouse is a benign stale event.
    const auto stored_guid=S(*warehouse,"GUID");
    const auto limit_enabled=B(config_,"StoresLimit",true);
    const auto limit=std::max(1,N(config_,"StoresLimit_Value",5000));
    const auto blob=Json::binary(*bytes);
    // Build and trim the next in-memory mirror before touching SQLite. Any
    // allocation/validation failure therefore leaves both stores unchanged.
    auto next_children = warehouse->at("_children");
    next_children.push_back({{"_id",data_detail::Guid()},{"Buffer",blob}});
    TrimStores(next_children);
    Json next_feed = Json::array();
    for (const auto& row : lists_[11]) {
        const auto& feed_children = Upper(S(row,"GUID")) == warehouse_id
            ? next_children : row.at("_children");
        next_feed.push_back({{"Id",row["GUID"]},{"Name",S(row,"Name")},
                             {"IsEnable",B(row,"IsEnable")},{"DataCount",feed_children.size()}});
    }
    db_.Transaction([&]{
        db_.Execute("INSERT INTO WareHouseData (GUID,Buffer) VALUES (?,?)",
                    Json::array({stored_guid,blob}));
        if(limit_enabled){
            const auto count_rows=db_.Query(
                "SELECT COUNT(*) AS Count FROM WareHouseData WHERE GUID=? COLLATE NOCASE",
                Json::array({stored_guid}));
            const auto count=count_rows.empty()?0:count_rows.front().at("Count").get<std::int64_t>();
            if(count>limit){
                db_.Execute("DELETE FROM WareHouseData WHERE rowid IN ("
                            "SELECT rowid FROM WareHouseData WHERE GUID=? COLLATE NOCASE "
                            "ORDER BY rowid LIMIT ?)",
                            Json::array({stored_guid,count-static_cast<std::int64_t>(limit)}));
            }
        }
    });
    // Json::swap is noexcept for the configured JSON value type. The commit
    // is now reflected atomically in the worker-owned mirror; a UI/feed sink
    // failure is reported as a committed event rather than rolling back SQL.
    warehouse->at("_children").swap(next_children);
    try { emit_("feed:replace", {{"list",11},{"rows",std::move(next_feed)}}); }
    catch (const std::exception& error) {
        throw StoreEventCommittedError("数据已提交，但界面更新失败：" +
                                       std::string(error.what()));
    } catch (...) {
        throw StoreEventCommittedError("数据已提交，但界面更新失败");
    }
    return true;
}
std::vector<std::string> DataService::Methods(){return {
    "getPrefs","setAppearance","setLanguage","saveActionColor","getSystemSetting","saveSystemSetting","getLogSetting","saveLogSetting",
    "getProxySetting","saveProxySetting","getRemoteSetting","saveRemoteSetting","getHookSetting","saveHookSetting","getLeachSetting","saveLeachSetting","getFireWall","saveFireWall","saveListAutoClear",
    "addIpRule","saveIPRule","deleteIPRule","ipRuleAction",
    "getAccountPassword","getAccountLogins","saveAccount","deleteAccount","clearAllAccounts","setAccountEnable","importAccounts","exportAccounts","previewBatchAccounts","saveBatchAccounts","exportBatchAccounts","adjustAccountExpiry","adjustAccountLimit","exportSelectedAccounts","deleteSelectedAccounts",
    "enterProxyMode","enterInjectMode","getStats","getClientConnections","getListSetting","saveListSetting","clearLogs","getCountryTable",
    "getFilterExecute","getFilterEdit","saveFilterEdit","getExecuteTargets","addFilter","setFilterEnable","setAllFilterEnable","resetFilterCount","filterListAction","clearFilters","setListEnable",
    "getSendMeta","addSend","setSendEnable","setAllSendEnable","resetSendCount","sendListAction","clearSends","openSendEdit","closeSendEdit","getSendCollection","saveSendEdit","exportSendCollection",
    "getRobotMeta","addRobot","setRobotEnable","setAllRobotEnable","resetRobotCount","robotListAction","clearRobots",
    "addWareHouse","wareHouseListAction","clearWareHouses","openWareHouseEdit","getStoreRows","getStorePreviews","copyStoresHex","saveWareHouseName",
    "getAutoStoresMeta","setAutoStoresSwitch","saveAutoStores","setAutoStoresEnable","deleteAutoStores","autoStoresAction",
    "getMapSetting","saveMapSetting","saveMapLocal","saveMapRemote","setMapEnable","mapAction","mapCommand",
    "saveServer","setServerEnable","serverListAction","clearServers","getRuleTypes","getServerRules","saveServerRule","setServerRuleEnable","serverRuleAction","clearServerRules","saveNotice","noticeListAction","clearNotices",
    "openRobotEdit","closeRobotEdit","getRobotInstructions","addRobotInstruction","robotInstructionAction","saveRobotEdit",
    "sendCollectionAction","clearSendCollection","importSendCollection","openPacketEdit","savePacketEdit","storesAction","storesCommand",
    "importFilters","exportFilters","importSends","exportSends","importRobots","exportRobots","importWareHouses","exportWareHouses","importBackup","exportBackup","textDuplicates","transcode","extractBytes","saveExtraction","getProcessSetting","addSelectProcessName","removeSelectProcessName","saveProcessSetting","testSocksProxy","getExtProxySetting","saveExtProxySetting","getHotkeySetting","registerHotkey","saveHotkeyType"
};}
bool DataService::NeedsConfirmation(const std::string& method,const Json& args){
    if(method=="deleteAccount"||method=="clearAllAccounts"||method=="deleteSelectedAccounts"||method=="deleteIPRule"||method=="deleteAutoStores"||method=="clearSendCollection"||method=="clearServers"||method=="clearServerRules"||method=="clearNotices"||((method=="mapAction")&&N(args,"action",-1)==6)||((method=="mapCommand"||method=="robotInstructionAction"||method=="storesCommand"||method=="sendCollectionAction"||method=="ipRuleAction"||method=="autoStoresAction")&&N(args,"action",-1)==7)||((method=="serverListAction"||method=="serverRuleAction"||method=="noticeListAction")&&N(args,"action",-1)==6))return true;
    return method=="clearFilters"||method=="clearSends"||method=="clearRobots"||method=="clearWareHouses"||method=="clearLogs"||
        ((method=="filterListAction"||method=="sendListAction"||method=="robotListAction"||method=="wareHouseListAction")&&N(args,"action",-1)==6);
}
std::string DataService::Text(const std::string& key,const std::string& fallback)const{
    static const auto translations=[] {std::string text;for(auto chunk:data_l10n_chunks)text+=chunk;return Json::parse(text);}();const auto lang=S(config_,"DefaultLanguage","zh-CN");
    if(!translations.contains(lang))return fallback;
    if(translations[lang].contains(key))return translations[lang][key].get<std::string>();
    return translations.at("en-US").value(key,fallback);
}
Json DataService::Prefs()const{
    const bool dark=B(config_,"IsDark",true);
    Json colors;for(const auto& pair:std::array<std::pair<const char*,const char*>,4>{{{"replace","FilterReplace"},{"intercept","FilterIntercept"},{"change","FilterChange"},{"display","FilterDisplay"}}}){
        colors[pair.first]={{"fore",Color(config_,(std::string(pair.second)+"_ForeColor").c_str())},{"back",Color(config_,(std::string(pair.second)+"_BackColor").c_str())}};
    }
    return {{"isDark",dark},{"themeMode",B(config_,"ThemeFollowSystem")?"system":dark?"dark":"light"},{"scanLine",B(config_,"ScanLine",true)},{"language",S(config_,"DefaultLanguage","zh-CN")},{"systemColor",Color(config_,"SystemColor")},{"filter",colors}};
}
Json DataService::TargetConfiguration() const {
    Json result{{"hookFlags",Json::array()}, {"runtime", Json::object()}, {"captureFilter", Json::object()},
                {"filters", Json::array()}, {"sends", Json::array()}};
    const std::array<const char*,12> hook_keys{{"HookWS1_Send","HookWS1_SendTo",
        "HookWS1_Recv","HookWS1_RecvFrom","HookWS2_Send","HookWS2_SendTo",
        "HookWS2_Recv","HookWS2_RecvFrom","HookWSA_Send","HookWSA_SendTo",
        "HookWSA_Recv","HookWSA_RecvFrom"}};
    for (const auto key : hook_keys) result["hookFlags"].push_back(B(inject_config_,key,true));
    result["runtime"] = {{"speedMode",B(config_,"SpeedMode")}, {"systemSocket",0},
        {"listExecute",N(config_,"ListExecute",1)}, {"filterExecute",N(config_,"FilterExecute",1)}};
    const auto capture_mask=Split(S(config_,"CheckType_Value",""),':');
    auto capture_flag=[&](std::size_t index){int value=0;return index<capture_mask.size()&&Integer(capture_mask[index],value)&&value!=0;};
    result["captureFilter"] = {
        {"notShow",B(config_,"CheckNotShow",true)},
        {"checkSocket",B(config_,"CheckSocket")},{"socketValue",S(config_,"CheckSocket_Value")},
        {"checkIP",B(config_,"CheckIP")},{"ipValue",S(config_,"CheckIP_Value")},
        {"checkPort",B(config_,"CheckPort")},{"portValue",S(config_,"CheckPort_Value")},
        {"checkHead",B(config_,"CheckHead")},{"headValue",S(config_,"CheckHead_Value")},
        {"checkData",B(config_,"CheckData")},{"dataValue",S(config_,"CheckData_Value")},
        {"checkLen",B(config_,"CheckSize")},{"lenValue",S(config_,"CheckLength_Value")},
        {"checkType",B(config_,"CheckType")},
        {"send",capture_flag(0)},{"sendTo",capture_flag(1)},{"recv",capture_flag(2)},{"recvFrom",capture_flag(3)},
        {"wsaSend",capture_flag(4)},{"wsaSendTo",capture_flag(5)},{"wsaRecv",capture_flag(6)},{"wsaRecvFrom",capture_flag(7)},
        {"tcpReq",capture_flag(8)},{"udpReq",capture_flag(9)},{"tcpResp",capture_flag(10)},{"udpResp",capture_flag(11)}
    };
    for (const auto& row : lists_[8]) {
        Json item{{"enabled",B(row,"IsEnable")},{"id",S(row,"GUID")},{"name",S(row,"Name")},
            {"appointHeader",B(row,"AppointHeader")},{"header",S(row,"HeaderContent")},
            {"appointSocket",B(row,"AppointSocket")},{"socket",S(row,"SocketContent")},
            {"appointLength",B(row,"AppointLength")},{"length",S(row,"LengthContent")},
            {"appointPort",B(row,"AppointPort")},{"port",S(row,"PortContent")},
            {"mode",N(row,"Mode")},{"action",N(row,"Action")},{"execute",B(row,"IsExecute")},
            {"executeType",N(row,"ExecuteType")},{"executeId",S(row,"ExecuteGUID")},
            {"functionMask",Mask(S(row,"Function"))},{"startFrom",N(row,"StartFrom")},
            {"progressionDone",false},{"progressionContinuous",B(row,"IsProgressionContinuous")},
            {"progressionStep",N(row,"ProgressionStep",1)},{"progressionCarry",B(row,"IsProgressionCarry")},
            {"progressionCarryNumber",N(row,"ProgressionCarryNumber",1)},
            {"progressionPosition",S(row,"ProgressionPosition")},{"progressionCount",0},
            {"excludePosition",S(row,"ExcludePosition")},{"randomPosition",S(row,"RandomPosition")},
            {"search",S(row,"Search")},{"modify",S(row,"Modify")}};
        result["filters"].push_back(std::move(item));
    }
    for (const auto& row : lists_[9]) {
        Json item{{"enabled",B(row,"IsEnable")},{"id",S(row,"GUID")},{"name",S(row,"Name")},
            {"systemSocket",B(row,"SystemSocket")},{"loopCount",N(row,"LoopCNT",1)},
            {"loopInterval",N(row,"LoopINT",1000)},{"notes",S(row,"Notes")},
            {"packets",Json::array()}};
        for (const auto& packet : row.at("_children")) {
            item["packets"].push_back({{"socket",N(packet,"Socket")},{"type",N(packet,"Type")},
                {"from",S(packet,"IPFrom")},{"to",S(packet,"IPTo")},
                {"bytes",packet.contains("Buffer")&&packet.at("Buffer").is_binary()
                    ? packet.at("Buffer") : Json::binary({})}});
        }
        result["sends"].push_back(std::move(item));
    }
    return result;
}
void DataService::SaveConfig(const Json& changes){
    if(changes.empty())return;
    auto next=config_;for(auto it=changes.begin();it!=changes.end();++it){if(!next.contains(it.key()))throw std::invalid_argument("Unknown setting");next[it.key()]=it.value();}
    // Preserve every untouched upstream column. Commit before changing the live mirror.
    db_.Transaction([&]{db_.Replace("SystemConfig",Json::array({next}));});config_=std::move(next);
}
void DataService::SaveInjectConfig(const Json& changes){
    auto next=inject_config_;for(auto it=changes.begin();it!=changes.end();++it){if(!next.contains(it.key()))throw std::invalid_argument("Unknown inject setting");next[it.key()]=it.value();}
    db_.Transaction([&]{db_.Replace("InjectMode",Json::array({next}));});inject_config_=std::move(next);
}
void DataService::SaveProxyConfig(const Json& changes){
    auto next=proxy_config_;for(auto it=changes.begin();it!=changes.end();++it){if(!next.contains(it.key()))throw std::invalid_argument("Unknown proxy setting");next[it.key()]=it.value();}
    db_.Transaction([&]{db_.Replace("ProxyMode",Json::array({next}));});proxy_config_=std::move(next);
}
Json DataService::NewRow(int list){
    Json row{{"GUID",Guid()},{"Name",""},{"_objectId",Guid()}};
    const std::array<std::string,4> keys={"FilterList.NewFilter","SendList.NewSend","RobotList.NewRobot","WareHouseList.NewWareHouse"};
    const std::array<std::string,4> fallback={"滤镜 {0}","发送 {0}","机器人 {0}","仓库 {0}"};
    auto name=Text(keys[list-8],fallback[list-8]);const auto pos=name.find("{0}");if(pos!=name.npos)name.replace(pos,3,std::to_string(lists_[list].size()+1));row["Name"]=name;
    if(list<11)row["IsEnable"]=false;
    if(list==8){
        row.update({{"AppointHeader",false},{"HeaderContent",""},{"AppointSocket",false},{"SocketContent",""},{"AppointLength",false},{"LengthContent",""},{"AppointPort",false},{"PortContent",""},{"Mode",0},{"Action",0},{"IsExecute",false},{"ExecuteType",2},{"ExecuteGUID",zero_guid},{"Function",Function(4095)},{"StartFrom",0},{"IsProgressionContinuous",false},{"ProgressionStep",1},{"IsProgressionCarry",false},{"ProgressionCarryNumber",1},{"ProgressionPosition",""},{"ExcludePosition",""},{"RandomPosition",""},{"Search",""},{"Modify",""}});
    }else{
        row["_children"]=Json::array();
        if(list==9)row.update({{"SystemSocket",false},{"LoopCNT",1},{"LoopINT",1000},{"Notes",""}});
    }return row;
}
Json* DataService::Find(int list,const std::string& id){const auto key=Upper(id);for(auto& row:lists_[list])if(S(row,"GUID")==key)return &row;return nullptr;}
void DataService::PersistList(int list,const Json& rows){
    Json parents=rows,child=Json::array();
    for(auto& row:parents){
        row.erase("_objectId");
        if(row.contains("_children")){
            for(auto item:row["_children"]){item.erase("_id");item["GUID"]=row["GUID"];child.push_back(std::move(item));}
            row.erase("_children");
        }
    }
    if(list>8)db_.Execute("DELETE FROM "+children[list-8]);
    db_.Replace(tables[list-8],parents);
    if(list>8)db_.Replace(children[list-8],child);
}
void DataService::PersistIpRules(int list,const Json& rows){
    if(list!=15&&list!=16)throw std::invalid_argument("Invalid IP rule list");Json stored=rows;
    for(auto& row:stored){row.erase("IPLocation");row.erase("EffectCount");}
    db_.Replace(list==15?"WhiteList":"BlackList",stored);
}
void DataService::PersistAccounts(const Json& rows){
    Json accounts=Json::array(),logins=Json::array();for(const auto& source:rows){auto row=source;row.erase("IsOnLine");row.erase("_logins");accounts.push_back(std::move(row));if(source.contains("_logins"))for(const auto& sourceLogin:source.at("_logins")){auto login=sourceLogin;login.erase("IPLocation");login["GUID"]=S(source,"GUID");logins.push_back(std::move(login));}}
    db_.Execute("DELETE FROM ProxyAccountIPInfo");db_.Replace("ProxyAccount",accounts);db_.Replace("ProxyAccountIPInfo",logins);
}
void DataService::PersistAutoStores(const Json& rows){
    // Upstream deletes the table, then InsertTable_AutoStores silently skips an
    // exact PacketHead duplicate while leaving both runtime rows visible until
    // restart. Preserve that unusual split instead of making import fail.
    db_.Execute("DELETE FROM AutoStores");for(const auto& row:rows)db_.Execute("INSERT OR IGNORE INTO AutoStores (IsEnable,PacketHead,WID) VALUES (?,?,?)",Json::array({B(row,"IsEnable"),S(row,"PacketHead"),Upper(S(row,"WID"))}));
}
void DataService::SaveList(int list,const Json& rows){
    db_.Transaction([&]{PersistList(list,rows);});lists_[list]=rows;RefreshExportAliases(list);Publish(list);
}
void DataService::SaveIpRules(int list,const Json& rows){db_.Transaction([&]{PersistIpRules(list,rows);});lists_[list]=rows;Publish(list);}
void DataService::SaveAccounts(const Json& rows){db_.Transaction([&]{PersistAccounts(rows);});lists_[5]=rows;Publish(5);}
Json DataService::Rows(int list)const{
    Json result=Json::array();
    // Runtime log rows are session-scoped, but they still use the normal feed
    // contract.  Keep them in the worker mirror so switching to the log page
    // after an operation can republish the rows instead of showing a blank
    // table until the next event.
    if(list==2||list==3||list==4||list==6)return lists_[list];
    if(list==5){for(const auto& row:lists_[5])result.push_back({{"Id",Upper(S(row,"GUID"))},{"IsCheck",false},{"IsEnable",B(row,"IsEnable")},{"UserName",S(row,"UserName")},{"IsLimitLinks",B(row,"IsLimitLinks")},{"LimitLinks",N(row,"LimitLinks")},{"IsLimitDevices",B(row,"IsLimitDevices")},{"LimitDevices",N(row,"LimitDevices")},{"IsExpiry",B(row,"IsExpiry")},{"ExpiryTime",S(row,"ExpiryTime")},{"CreateTime",S(row,"CreateTime")},{"IsOnLine",B(row,"IsOnLine")},{"LoginCount",row.contains("_logins")?row.at("_logins").size():0}});return result;}
    if(list==12){for(const auto& row:lists_[12])result.push_back({{"Id",S(row,"_id")},{"IsEnable",B(row,"IsEnable")},{"PacketHead",S(row,"PacketHead")},{"WareHouseId",Upper(S(row,"WID"))}});return result;}
    if(list==13){for(const auto& row:lists_[13])result.push_back({{"Id",S(row,"_id")},{"IsEnable",B(row,"IsEnable")},{"Protocol",0},{"Host",S(row,"Host")},{"Port",N(row,"Port",80)},{"RemotePath",S(row,"RemotePath")},{"LocalPath",S(row,"LocalPath")}});return result;}
    if(list==14){for(const auto& row:lists_[14])result.push_back({{"Id",S(row,"_id")},{"IsEnable",B(row,"IsEnable")},{"ProtocolFrom",0},{"HostFrom",S(row,"Host_From")},{"PortFrom",N(row,"Port_From",80)},{"PathFrom",S(row,"Path_From")},{"ProtocolTo",0},{"HostTo",S(row,"Host_To")},{"PortTo",N(row,"Port_To",80)},{"PathTo",S(row,"Path_To")}});return result;}
    if(list==17){for(const auto& row:lists_[17])result.push_back({{"Id",S(row,"SID")},{"IsEnable",B(row,"IsEnable")},{"Name",S(row,"ServerName")},{"IP",S(row,"ServerIP")},{"Port",N(row,"ServerPort",1080)},{"ForgotURL",S(row,"ForgotURL")},{"RegisterURL",S(row,"RegisterURL")},{"VerifyURL",S(row,"VerifyURL")},{"RuleCount",row.at("_rules").size()}});return result;}
    if(list==18){for(const auto& row:lists_[18])result.push_back({{"Id",S(row,"NID")},{"Type",N(row,"NoticeType",1)},{"Title",S(row,"NoticeTitle")},{"Content",S(row,"NoticeContent")},{"More",S(row,"NoticeMore")},{"Time",S(row,"NoticeTime")}});return result;}
    if(list<8||list>11)return lists_[list];
    for(const auto& row:lists_[list]){
        Json r{{"Id",row["GUID"]},{"Name",S(row,"Name")}};
        if(list<11)r.update({{"IsEnable",B(row,"IsEnable")},{"ExecutionCount",0}});
        if(list==8){
            for(const auto* key:{"Mode","Action","StartFrom","ExecuteType"})r[key]=N(row,key);
            for(const auto* key:{"AppointHeader","AppointSocket","AppointLength","AppointPort","IsExecute","IsProgressionContinuous","IsProgressionCarry"})r[key]=B(row,key);
            for(const auto* key:{"HeaderContent","SocketContent","LengthContent","PortContent","ProgressionPosition"})r[key]=S(row,key);
            r["FunctionMask"]=Mask(S(row,"Function"));r["ExecuteId"]=Upper(S(row,"ExecuteGUID"));
        }else if(list==9){r.update({{"ExecutionSuccess",0},{"ExecutionFail",0},{"UseSystemSocket",B(row,"SystemSocket")},{"LoopCount",N(row,"LoopCNT",1)},{"LoopInterval",N(row,"LoopINT",1000)},{"Notes",S(row,"Notes")},{"PacketCount",row["_children"].size()}});
        }else r[list==10?"InstructionCount":"DataCount"]=row["_children"].size();
        result.push_back(std::move(r));
    }return result;
}
void DataService::Publish(int list){emit_("feed:replace",{{"list",list},{"rows",Rows(list)}});}
void DataService::PublishAll(){
    // Only publish implemented collections. Empty unsupported tables are not fake data sources.
    for(int list=8;list<=11;++list)Publish(list);
    for(int list=2;list<=4;++list)Publish(list);
    Publish(5);
    Publish(6);
    Publish(12);
    Publish(13);Publish(14);
    Publish(15);Publish(16);
    Publish(17);Publish(18);
}
Json DataService::FilterEdit(const Json& row)const{
    Json r{{"Id",row["GUID"]},{"Name",S(row,"Name")},{"FunctionMask",Mask(S(row,"Function"))},{"ExecuteId",Upper(S(row,"ExecuteGUID"))}};
    for(const auto* key:{"Mode","Action","StartFrom","ExecuteType","ProgressionStep","ProgressionCarryNumber"})r[key]=N(row,key);
    for(const auto* key:{"AppointHeader","AppointSocket","AppointLength","AppointPort","IsExecute","IsProgressionContinuous","IsProgressionCarry"})r[key]=B(row,key);
    for(const auto* key:{"HeaderContent","SocketContent","LengthContent","PortContent"})r[key]=S(row,key);
    for(const auto* kind:{"Search","Modify"}){
        std::map<int,Json> cells;
        auto cell=[&](int i)->Json&{auto [it,inserted]=cells.try_emplace(i,Json{{"Index",i},{"Value",""}});if(inserted){if(std::string(kind)=="Search")it->second["Exclude"]=false;else it->second.update({{"Progression",false},{"Random",false}});}return it->second;};
        for(const auto& pair:Split(S(row,kind),',')){const auto p=pair.find('|');int i=0;if(p!=pair.npos&&Integer(pair.substr(0,p),i))cell(i)["Value"]=pair.substr(p+1);}
        const std::vector<std::string> flags=std::string(kind)=="Search"?std::vector<std::string>{"Exclude"}:std::vector<std::string>{"Progression","Random"};
        for(const auto& flag:flags)for(const auto& index:Split(S(row,(flag+"Position").c_str()),',')){int i=0;if(Integer(index,i))cell(i)[flag]=true;}
        r[kind]=Json::array();for(auto& [index,value]:cells){(void)index;r[kind].push_back(std::move(value));}
    }return r;
}
Json DataService::SaveFilter(const Json& args){
    const auto input=args.value("row",Json::object());if(!input.is_object())return Bad(Text("FilterEditForm.FilterName.Empty","请输入滤镜名称"));
    auto row=Find(8,S(input,"Id"));if(!row)return Bad(Text("FilterEditForm.NotFound","这条滤镜已经不在列表里了"));
    const auto name=Trim(S(input,"Name"));if(name.empty())return Bad(Text("FilterEditForm.FilterName.Empty","请输入滤镜名称"));
    for(const auto* kind:{"Header","Socket","Length","Port"}){
        const auto prefix=std::string(kind);if(!B(input,("Appoint"+prefix).c_str()))continue;
        const auto value=Trim(S(input,(prefix+"Content").c_str()));
        const auto pattern=prefix=="Header"?"^([0-9a-fA-F]{2}\\s*)+$":prefix=="Socket"?"^(\\d+)(;\\d+)*$":"^(\\d+[-;])*\\d+$";
        if(!std::regex_match(value,std::regex(pattern)))return Bad(Text("FilterEditForm.Appoint"+(prefix=="Header"?std::string("Head"):prefix)+".Error","指定"+prefix+"数据错误"));
    }
    if(N(input,"Action")==5){
        std::set<int> filled;for(const auto& cell:input.value("Modify",Json::array()))if(cell.is_object()&&N(cell,"Index")>=0&&!Trim(S(cell,"Value")).empty())filled.insert(N(cell,"Index"));
        if(filled.empty()||*filled.rbegin()>1000000||filled.size()!=static_cast<std::size_t>(*filled.rbegin())+1)return Bad(Text("FilterEditForm.Change.Error","换包数据错误"));
    }
    Json next=*row;next["Name"]=name;next["Function"]=Function(N(input,"FunctionMask"));next["ExecuteGUID"]=NormalGuid(S(input,"ExecuteId"));
    for(const auto* key:{"Mode","Action","StartFrom","ExecuteType"})next[key]=N(input,key);
    for(const auto* key:{"ProgressionStep","ProgressionCarryNumber"})next[key]=std::max(1,N(input,key));
    for(const auto* key:{"AppointHeader","AppointSocket","AppointLength","AppointPort","IsExecute","IsProgressionContinuous","IsProgressionCarry"})next[key]=B(input,key);
    for(const auto* key:{"HeaderContent","SocketContent","LengthContent","PortContent"})next[key]=Trim(S(input,key));
    std::map<std::string,std::string> packed;
    auto append=[&](const std::string& key,const std::string& value){if(!packed[key].empty())packed[key]+=',';packed[key]+=value;};
    for(const auto* kind:{"Search","Modify"}){
        const bool search=std::string(kind)=="Search";const int low=!search&&N(input,"Mode")==1&&N(input,"StartFrom")==1?-1000:0;
        for(const auto& cell:input.value(kind,Json::array())){
            if(!cell.is_object())continue;const int index=N(cell,"Index");if(index<low||index>=1000)continue;
            const auto value=Trim(S(cell,"Value")),position=std::to_string(index);
            if(!value.empty())append(kind,position+'|'+value);
            if(search){if(!value.empty()&&B(cell,"Exclude"))append("ExcludePosition",position);}
            else if(B(cell,"Progression"))append("ProgressionPosition",position);
            else if(B(cell,"Random"))append("RandomPosition",position);
        }
    }
    for(const auto* key:{"Search","Modify","ExcludePosition","ProgressionPosition","RandomPosition"})next[key]=packed[key];
    auto rows=lists_[8];for(auto& item:rows)if(item["GUID"]==next["GUID"]){item=std::move(next);break;}
    SaveList(8,rows);return {{"ok",true},{"error",""}};
}
Json DataService::ListAction(int list,const Json& args){
    const int action=N(args,"action",-1);if(action==5)throw std::runtime_error("尚未实现：原版 XML 导出与文件选择");
    if(action<0||action>6)return {{"ok",false},{"delta",0}};
    std::set<std::string> ids;for(const auto& id:args.value("ids",Json::array()))if(id.is_string())ids.insert(Upper(id.get<std::string>()));
    if(ids.empty())return {{"ok",false},{"delta",0}};
    std::vector<std::string> picked;auto rows=lists_[list];for(const auto& row:rows)if(ids.contains(S(row,"GUID")))picked.push_back(S(row,"GUID"));
    const auto before=static_cast<std::int64_t>(rows.size());
    for(const auto& id:picked){
        auto it=std::find_if(rows.begin(),rows.end(),[&](const Json& row){return S(row,"GUID")==id;});if(it==rows.end())continue;
        const auto index=static_cast<std::size_t>(it-rows.begin());auto row=*it;
        if(action==4){
            row["GUID"]=Guid();row["_objectId"]=Guid();if(list<11)row["IsEnable"]=false;
            auto name=Text("CopyName","{0} - 副本");const auto pos=name.find("{0}");if(pos!=name.npos)name.replace(pos,3,S(row,"Name"));row["Name"]=name;
            // Original CopySend copies the list, not its PacketInfo objects.
            if(list>9)row["_children"]=RuntimeChildren(row["_children"],list,packet_id_);rows.push_back(std::move(row));continue;
        }
        if((action==1&&index==0)||(action==2&&index+1==rows.size()))continue;
        rows.erase(it);if(action==6)continue;
        const auto target=action==0?0:action==1?index-1:action==2?index+1:rows.size();rows.insert(rows.begin()+static_cast<Json::difference_type>(target),std::move(row));
    }
    const auto delta=static_cast<std::int64_t>(rows.size())-before;SaveList(list,rows);return {{"ok",true},{"delta",delta}};
}

Json DataService::Call(const std::string& method,const Json& args){
    if(auto result=CallEditor(method,args))return std::move(*result);
    if(auto result=CallConfigLists(method,args))return std::move(*result);
    if(method=="textDuplicates"){
        const auto parse=[&](const char* key){const auto text=S(args,key);auto bytes=DecodeHexLoose(text);if(bytes.empty()&&!text.empty())bytes.assign(text.begin(),text.end());return bytes;};
        const auto a=parse("a"),b=parse("b");const auto minimum=std::clamp(N(args,"min",4),1,1024);Json rows=Json::array();
        std::unordered_set<std::string> seen;
        const auto limit=std::min<std::size_t>(a.size(),b.size());
        for(std::size_t len=static_cast<std::size_t>(minimum);len<=std::min<std::size_t>(limit,256);++len){
            for(std::size_t i=0;i+len<=a.size();++i){const std::string key(reinterpret_cast<const char*>(a.data()+i),len);if(seen.contains(key))continue;
                std::vector<int> pa,pb;for(std::size_t p=i;p+len<=a.size();++p)if(std::memcmp(a.data()+p,key.data(),len)==0)pa.push_back(static_cast<int>(p));for(std::size_t p=0;p+len<=b.size();++p)if(std::memcmp(b.data()+p,key.data(),len)==0)pb.push_back(static_cast<int>(p));
                if(!pb.empty()){seen.insert(key);rows.push_back({{"Sequence",HexBytes(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(key.data()),key.size()))},{"Length",static_cast<int>(len)},{"CountInA",static_cast<int>(pa.size())},{"CountInB",static_cast<int>(pb.size())},{"PositionsInA",pa},{"PositionsInB",pb}});}
            }
        }
        std::sort(rows.begin(),rows.end(),[](const Json& x,const Json& y){if(N(x,"Length")!=N(y,"Length"))return N(x,"Length")>N(y,"Length");return S(x,"Sequence")<S(y,"Sequence");});
        if(rows.size()>512)rows.erase(rows.begin()+512,rows.end());return {{"rows",std::move(rows)}};
    }
    if(method=="transcode"){
        const auto text=S(args,"text");const bool decode=B(args,"decode");const auto input=decode?DecodeHexLoose(text):std::vector<std::uint8_t>(text.begin(),text.end());
        std::wstring utf8_text; if(!decode){const int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),nullptr,0);if(n>0){utf8_text.resize(static_cast<std::size_t>(n));MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),utf8_text.data(),n);}}
        auto add=[&](const char* key,std::span<const std::uint8_t> bytes){return Json{{"Key",key},{"Value",decode?Utf8Bytes(bytes):HexBytes(bytes)}};};Json rows=Json::array();
        if(!decode)rows.push_back({{"Key","Bytes"},{"Value",text}});else rows.push_back({{"Key","Bytes"},{"Value",Utf8Bytes(input)}});
        const auto source=decode?std::wstring{}:utf8_text;
        if(!decode){rows.push_back(add("ANSI-GBK",EncodeCp(936,source)));rows.push_back(add("ANSI-UTF7",EncodeCp(65000,source)));rows.push_back(add("ANSI-UTF8",EncodeCp(CP_UTF8,source)));auto le=EncodeCp(1200,source);for(std::size_t i=0;i+1<le.size();i+=2)std::swap(le[i],le[i+1]);rows.push_back({{"Key","ANSI-UTF16"},{"Value",HexBytes(le)}});rows.push_back(add("ANSI-UTF32",EncodeCp(12000,source)));rows.push_back(add("ANSI-Unicode",EncodeCp(1200,source)));rows.push_back({{"Key","base64"},{"Value",B64Bytes(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(text.data()),text.size()))}});}
        // Decode rows above need a stable UTF-8 conversion; rebuild them from the input bytes.
        if(decode){rows=Json::array();rows.push_back({{"Key","Bytes"},{"Value",Utf8Bytes(input)}});for(const auto& [key,cp]:std::array<std::pair<const char*,UINT>,5>{{{"ANSI-GBK",936},{"ANSI-UTF8",CP_UTF8},{"ANSI-UTF16",1201},{"ANSI-UTF32",12000},{"ANSI-Unicode",1200}}}){auto w=DecodeCp(cp,input);const int n=WideCharToMultiByte(CP_UTF8,0,w.data(),static_cast<int>(w.size()),nullptr,0,nullptr,nullptr);std::string out(static_cast<std::size_t>(std::max(0,n)),'\0');if(n)WideCharToMultiByte(CP_UTF8,0,w.data(),static_cast<int>(w.size()),out.data(),n,nullptr,nullptr);rows.push_back({{"Key",key},{"Value",out}});}rows.push_back({{"Key","base64"},{"Value",Utf8Bytes(Unb64(text))}});}
        return {{"rows",std::move(rows)}};
    }
    if(method=="extractBytes"){
        const auto bytes=Unb64(S(args,"content"));const auto kind=N(args,"kind");std::string text;
        if(kind==0||kind==1)text=Utf8Bytes(bytes);else text=Utf8Bytes(bytes);
        if(text.empty()&&!bytes.empty())text=HexBytes(bytes);return {{"Path",S(args,"name")},{"Text",text},{"Error",text.empty()?"文件中没有可提取的数据":""},{"Count",text.empty()?0:1}};
    }
    if(method=="saveExtraction")return Bad("提取文件必须通过宿主文件保存对话框写入");
    if(method=="getProcessSetting"){
        Json p={{"DriverType",N(proxy_config_,"DriverType",1)},{"IsLoadDriver",false},{"MustTCP",B(proxy_config_,"MustTCP",true)},{"IP",S(proxy_config_,"MustTCP_IP","127.0.0.1")},{"Port",N(proxy_config_,"MustTCP_Port",1080)},{"AppointPort",B(proxy_config_,"MustTCP_AppointPort")},{"AppointPortContent",S(proxy_config_,"MustTCP_AppointPortContent")},{"Auth",B(proxy_config_,"MustTCP_Auth")},{"UserName",S(proxy_config_,"MustTCP_UserName")},{"PassWord",S(proxy_config_,"MustTCP_PassWord")},{"CheckedPids",Json::array()}};return p;
    }
    if(method=="addSelectProcessName"||method=="removeSelectProcessName"){
        auto text=S(proxy_config_,"SelectProcessNames");std::vector<std::string> names;for(auto part:Split(text,';'))if(!Trim(part).empty())names.push_back(Trim(part));
        std::string name=Trim(S(args,"name"));
        if(name.empty()&&args.contains("pid")){const auto pid=static_cast<DWORD>(N(args,"pid"));HANDLE process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);if(process){wchar_t path[MAX_PATH*4]{};DWORD size=static_cast<DWORD>(std::size(path));if(QueryFullProcessImageNameW(process,0,path,&size)){std::wstring_view full(path,size);const auto slash=full.find_last_of(L"\\/");name=Utf8Wide(slash==std::wstring_view::npos?full:full.substr(slash+1));}CloseHandle(process);}}
        if(method=="addSelectProcessName"&&!name.empty()&&std::find(names.begin(),names.end(),name)==names.end())names.push_back(name);
        if(method=="removeSelectProcessName"&&!name.empty())names.erase(std::remove(names.begin(),names.end(),name),names.end());
        std::string packed;for(const auto& item:names){if(!packed.empty())packed+=';';packed+=item;}SaveProxyConfig({{"SelectProcessNames",packed}});return {{"ok",!name.empty()}};
    }
    if(method=="saveProcessSetting"){
        const auto port=N(args,"port",0);
        if(port<1||port>65535)return Json{{"error","代理端口必须在 1 ~ 65535 之间"}};
        Json changes=Json::object();changes["DriverType"]=N(args,"driverType",1);changes["MustTCP"]=B(args,"mustTcp",true);changes["MustTCP_IP"]=Trim(S(args,"ip"));changes["MustTCP_Port"]=port;changes["MustTCP_AppointPort"]=B(args,"appointPort");changes["MustTCP_AppointPortContent"]=Trim(S(args,"appointPortContent"));changes["MustTCP_Auth"]=B(args,"auth");changes["MustTCP_UserName"]=S(args,"userName");changes["MustTCP_PassWord"]=S(args,"passWord");
        SaveProxyConfig(changes);
        return Json{{"error",""}};
    }
    if(method=="testSocksProxy"){
        const auto host=Trim(S(args,"ip","127.0.0.1"));const auto port=N(args,"port",1080);if(port<1||port>65535)return {{"error","代理端口不正确"}};
        const Winsock winsock;if(!winsock)return {{"error","Winsock 初始化失败"}};addrinfo hints{};hints.ai_socktype=SOCK_STREAM;hints.ai_protocol=IPPROTO_TCP;addrinfo* result=nullptr;const auto service=std::to_string(port);if(getaddrinfo(host.c_str(),service.c_str(),&hints,&result)!=0)return {{"error","无法解析代理地址"}};std::string error;for(auto* item=result;item;item=item->ai_next){SOCKET socket=::socket(item->ai_family,item->ai_socktype,item->ai_protocol);if(socket==INVALID_SOCKET)continue;u_long nonblocking=1;ioctlsocket(socket,FIONBIO,&nonblocking);const int rc=connect(socket,item->ai_addr,static_cast<int>(item->ai_addrlen));if(rc==SOCKET_ERROR&&WSAGetLastError()==WSAEWOULDBLOCK){fd_set write_set;FD_ZERO(&write_set);FD_SET(socket,&write_set);timeval timeout{2,0};if(select(0,nullptr,&write_set,nullptr,&timeout)>0){int so_error=0;int length=sizeof(so_error);getsockopt(socket,SOL_SOCKET,SO_ERROR,reinterpret_cast<char*>(&so_error),&length);if(so_error==0){closesocket(socket);freeaddrinfo(result);return {{"error",""}};}}}else if(rc==0){closesocket(socket);freeaddrinfo(result);return {{"error",""}};}closesocket(socket);}freeaddrinfo(result);return {{"error","无法连接代理地址"}};
    }
    if(method=="getExtProxySetting")return {{"enable",B(proxy_config_,"Enable_ExternalProxy")},{"ip",S(proxy_config_,"ExternalProxy_IP")},{"port",N(proxy_config_,"ExternalProxy_Port",8889)},{"appointPort",B(proxy_config_,"Enable_ExternalProxy_AppointPort")},{"appointPortContent",S(proxy_config_,"ExternalProxy_AppointPort")},{"auth",B(proxy_config_,"Enable_ExternalProxy_Auth")},{"userName",S(proxy_config_,"ExternalProxy_UserName")},{"passWord",S(proxy_config_,"ExternalProxy_PassWord")}};
    if(method=="saveExtProxySetting"){
        const auto port=N(args,"port",8889);
        if(port<1||port>65535)return Json{{"error","外部代理端口不正确"}};
        Json changes=Json::object();changes["Enable_ExternalProxy"]=B(args,"enable");changes["ExternalProxy_IP"]=Trim(S(args,"ip"));changes["ExternalProxy_Port"]=port;changes["Enable_ExternalProxy_AppointPort"]=B(args,"appointPort");changes["ExternalProxy_AppointPort"]=Trim(S(args,"appointPortContent"));changes["Enable_ExternalProxy_Auth"]=B(args,"auth");changes["ExternalProxy_UserName"]=S(args,"userName");changes["ExternalProxy_PassWord"]=S(args,"passWord");
        SaveProxyConfig(changes);
        return Json{{"error",""}};
    }
    if(method=="getHotkeySetting"){
        Json keys=Json::array();for(int i=1;i<=12;++i)keys.push_back(S(config_,("HotKey"+std::to_string(i)).c_str()));return {{"Type",N(config_,"HotKeyType",0)},{"Keys",std::move(keys)}};
    }
    if(method=="registerHotkey"){
        const int index=N(args,"index");if(index<1||index>12||S(args,"text").empty())return Json{{"ok",false}};Json change=Json::object();change["HotKey"+std::to_string(index)]=S(args,"text");SaveConfig(change);return Json{{"ok",true}};
    }
    if(method=="saveHotkeyType"){SaveConfig({{"HotKeyType",N(args,"type",0)}});return Good();}
    if(method=="getCountryTable")return Json::parse(country_codes);
    if(method=="getPrefs")return Prefs();
    if(method=="setAppearance"){
        Json update=Json::object();if(args.contains("mode"))update["ThemeFollowSystem"]=Upper(S(args,"mode"))=="SYSTEM";
        if(args.contains("isDark"))update["IsDark"]=B(args,"isDark");if(args.contains("scan"))update["ScanLine"]=B(args,"scan");SaveConfig(update);
        auto p=Prefs();return {{"ok",true},{"isDark",p["isDark"]},{"mode",p["themeMode"]},{"scan",p["scanLine"]}};
    }
    if(method=="setLanguage"){
        auto lang=Upper(S(args,"language"));std::string normalized="zh-CN";
        if(lang=="TW"||(lang.starts_with("ZH")&&(lang.find("TW")!=lang.npos||lang.find("HK")!=lang.npos||lang.find("MO")!=lang.npos||lang.find("HANT")!=lang.npos)))normalized="zh-TW";
        for(auto item:{"en-US","ja-JP","ko-KR","vi-VN","ru-RU"})if(lang.starts_with(Upper(std::string(item).substr(0,2))))normalized=item;
        SaveConfig({{"DefaultLanguage",normalized}});return {{"language",normalized}};
    }
    if(method=="saveActionColor"){
        const std::map<std::string,std::string> groups={{"replace","FilterReplace"},{"intercept","FilterIntercept"},{"change","FilterChange"},{"display","FilterDisplay"}};
        const auto group=groups.find(S(args,"action"));if(group==groups.end())return Bad("unknown action: "+S(args,"action"));Json update=Json::object();
        for(auto [arg,field]:std::array<std::pair<const char*,const char*>,2>{{{"fore","_ForeColor"},{"back","_BackColor"}}}){
            const auto value=Trim(S(args,arg));if(!std::regex_match(value,std::regex("#[0-9a-fA-F]{6}")))continue;
            update[group->second+field]=static_cast<std::int64_t>(std::stoul(value.substr(1),nullptr,16))-16777216;
        }SaveConfig(update);return {{"ok",true},{"error",""}};
    }
    if(method=="getSystemSetting")return {{"speedMode",B(config_,"SpeedMode")},{"listExecute",N(config_,"ListExecute",1)},{"filterExecute",N(config_,"FilterExecute",1)}};
    if(method=="saveSystemSetting"){
        SaveConfig({{"SpeedMode",B(args,"speedMode")},{"ListExecute",N(args,"listExecute")==1?1:0},{"FilterExecute",N(args,"filterExecute")==1?1:0}});return Good();
    }
    if(method=="getListSetting"){
        const bool inject=Upper(S(args,"mode"))=="INJECT";
        const auto& source=inject?inject_config_:proxy_config_;
        const std::string prefix=inject?"PacketList_":"ProxyList_";
        auto value=[&](const char* suffix){return B(source,(prefix+suffix).c_str(),true);};
        return {{"showSocket",value("ShowSocket")},{"showType",value("ShowType")},
            {"showClientAddr",value("ShowClientAddr")},{"showClientLoc",value("ShowClientLoc")},
            {"showServerAddr",value("ShowServerAddr")},{"showServerLoc",value("ShowServerLoc")},
            {"showLen",value("ShowLen")},
            // Auto-clear is one shared inject-list setting in the original
            // configuration, even though the column switches are per mode.
            {"autoClear",B(inject_config_,"PacketList_AutoClear",true)},
            {"autoClearValue",N(inject_config_,"PacketList_AutoClear_Value",5000)}};
    }
    if(method=="saveListSetting"){
        const bool inject=Upper(S(args,"mode"))=="INJECT";
        const std::string prefix=inject?"PacketList_":"ProxyList_";
        Json changes=Json::object();
        for(const auto suffix:{"ShowSocket","ShowType","ShowClientAddr","ShowClientLoc","ShowServerAddr","ShowServerLoc","ShowLen"}){
            const auto key=prefix+std::string(suffix);
            const auto arg=std::string("show")+std::string(suffix).substr(4); // ShowSocket -> showSocket
            if(args.contains(arg))changes[key]=B(args,arg.c_str());
        }
        if(inject){
            if(args.contains("autoClear"))changes["PacketList_AutoClear"]=B(args,"autoClear");
            if(args.contains("autoClearValue")){
                const int keep=N(args,"autoClearValue");
                if(keep<100||keep>500000)return Bad(Text("ListSettingsForm.Range","保留条数需在 100 ~ 500000 之间"));
                changes["PacketList_AutoClear_Value"]=keep;
            }
            SaveInjectConfig(changes);
        }else SaveProxyConfig(changes);
        return Good();
    }
    if(method=="getLeachSetting"){
        // Capture filtering is stored in SystemConfig using the same names as
        // the original database.  CheckType_Value is the twelve-field
        // colon-separated bit mask used by FilterFunction (bit 0..11).
        const auto mask=[&]{
            std::array<bool,12> flags{};
            const auto fields=Split(S(config_,"CheckType_Value",""),':');
            for(std::size_t i=0;i<flags.size()&&i<fields.size();++i){int value=0;if(Integer(fields[i],value))flags[i]=value!=0;}
            return flags;
        }();
        return {
            {"notShow",B(config_,"CheckNotShow",true)},
            {"checkSocket",B(config_,"CheckSocket")},{"socketValue",S(config_,"CheckSocket_Value")},
            {"checkIP",B(config_,"CheckIP")},{"ipValue",S(config_,"CheckIP_Value")},
            {"checkPort",B(config_,"CheckPort")},{"portValue",S(config_,"CheckPort_Value")},
            {"checkHead",B(config_,"CheckHead")},{"headValue",S(config_,"CheckHead_Value")},
            {"checkData",B(config_,"CheckData")},{"dataValue",S(config_,"CheckData_Value")},
            {"checkLen",B(config_,"CheckSize")},{"lenValue",S(config_,"CheckLength_Value")},
            {"checkType",B(config_,"CheckType")},
            {"send",mask[0]},{"sendTo",mask[1]},{"recv",mask[2]},{"recvFrom",mask[3]},
            {"wsaSend",mask[4]},{"wsaSendTo",mask[5]},{"wsaRecv",mask[6]},{"wsaRecvFrom",mask[7]},
            {"tcpReq",mask[8]},{"udpReq",mask[9]},{"tcpResp",mask[10]},{"udpResp",mask[11]}
        };
    }
    if(method=="saveLeachSetting"){
        const auto text=[&](const char* key){return Trim(S(args,key));};
        const std::array<std::pair<const char*,const char*>,6> conditions{{{
            "checkSocket","socketValue"},{"checkIP","ipValue"},{"checkPort","portValue"},
            {"checkHead","headValue"},{"checkData","dataValue"},{"checkLen","lenValue"}}};
        for(const auto& [enabled,value] : conditions){
            if(B(args,enabled) && text(value).empty())
                return Bad(Text("LeachSetting.Empty","勾选的条件不能留空"));
        }
        // The UI sends only the type group for the active mode.  Start with
        // the persisted mask and replace fields that are actually present so
        // saving the proxy dialog cannot clear injection type flags (or vice
        // versa).
        std::array<bool,12> mask{};
        const auto current=Split(S(config_,"CheckType_Value",""),':');
        for(std::size_t i=0;i<mask.size()&&i<current.size();++i){int value=0;if(Integer(current[i],value))mask[i]=value!=0;}
        const std::array<std::pair<const char*,std::size_t>,12> type_fields{{{
            "send",0},{"sendTo",1},{"recv",2},{"recvFrom",3},
            {"wsaSend",4},{"wsaSendTo",5},{"wsaRecv",6},{"wsaRecvFrom",7},
            {"tcpReq",8},{"udpReq",9},{"tcpResp",10},{"udpResp",11}}};
        for(const auto& [key,index] : type_fields)if(args.contains(key)&&!args.at(key).is_null())mask[index]=B(args,key);
        std::string serialized;for(std::size_t i=0;i<mask.size();++i){if(i)serialized+=':';serialized+=mask[i]?'1':'0';}
        SaveConfig({
            {"CheckNotShow",B(args,"notShow")},{"CheckSocket",B(args,"checkSocket")},{"CheckSocket_Value",text("socketValue")},
            {"CheckIP",B(args,"checkIP")},{"CheckIP_Value",text("ipValue")},{"CheckPort",B(args,"checkPort")},{"CheckPort_Value",text("portValue")},
            {"CheckHead",B(args,"checkHead")},{"CheckHead_Value",text("headValue")},{"CheckData",B(args,"checkData")},{"CheckData_Value",text("dataValue")},
            {"CheckSize",B(args,"checkLen")},{"CheckLength_Value",text("lenValue")},{"CheckType",B(args,"checkType")},{"CheckType_Value",serialized}
        });
        emit_("toast",{{"level",2},{"text",Text("LeachSetting.Success","过滤设置保存成功")}});
        return Good();
    }
    if(method=="getLogSetting")return {{"autoClear",B(config_,"LogList_AutoClear",true)},{"autoClearValue",N(config_,"LogList_AutoClear_Value",5000)}};
    if(method=="saveLogSetting"){
        Json changes=Json::object();if(args.contains("autoClear"))changes["LogList_AutoClear"]=B(args,"autoClear");
        if(args.contains("autoClearValue")){const int v=N(args,"autoClearValue");if(v<100||v>500000)return Bad(Text("ListSettingsForm.Range","保留条数需在 100 ~ 500000 之间"));changes["LogList_AutoClear_Value"]=v;}
        SaveConfig(changes);return Good();
    }
    if(method=="getProxySetting"){
        const auto ips=LocalAddresses();const auto physical=PhysicalMemory();const double gb=std::round(static_cast<double>(physical)/(1024.0*1024.0*1024.0)*10.0)/10.0;
        return {{"proxyIpAuto",B(proxy_config_,"ProxyIP_Auto",true)},{"proxyIp",S(proxy_config_,"ProxyIP")},{"localIps",ips},
            {"enableSocks5",B(proxy_config_,"Enable_SOCKS5",true)},{"socks5Port",N(proxy_config_,"SOCKS5_Port",1080)},
            {"enableAuth",B(proxy_config_,"EnableAuth",true)},{"onlyWpc",B(proxy_config_,"Only_WPC_Client")},
            {"maxConnection",N(proxy_config_,"MaxConnectionNumber",5000)},{"maxConnectionCap",MaxConnectionCap()},
            {"maxConnectionDefault",5000},{"connBufferKB",16},{"memoryGB",gb},{"enableHttp",B(proxy_config_,"Enable_HTTP",true)},
            {"httpPort",N(proxy_config_,"HTTP_Port",1081)},{"enableSystemProxy",false},{"running",false}};
    }
    if(method=="getRemoteSetting"){
        const auto ips=LocalAddresses();
        auto selected=S(config_,"Remote_IP");
        bool missing=!selected.empty();
        for(const auto& value:ips)if(value.is_string()&&value.get<std::string>()==selected){missing=false;break;}
        Json choices=ips;
        if(missing)choices.insert(choices.begin(),selected);
        if(selected.empty())selected=choices.empty()?std::string("127.0.0.1"):choices.front().get<std::string>();
        return {{"IsRemote",B(config_,"Remote_IsEnable")},{"IP",selected},{"IPs",std::move(choices)},
                {"Port",N(config_,"Remote_Port",88)},{"UserName",S(config_,"Remote_UserName")},
                {"PassWord",S(config_,"Remote_PassWord")},{"Running",false},{"IPMissing",missing}};
    }
    if(method=="saveRemoteSetting"){
        const bool enabled=B(args,"isRemote");
        const auto ip=Trim(S(args,"ip")),user=Trim(S(args,"userName")),password=S(args,"passWord");
        const int port=N(args,"port",88);
        if(enabled&&!ValidIp(ip))return Bad("远程管理监听地址不是本机有效 IP");
        if(enabled&&(port<1||port>65535))return Bad("远程管理端口必须在 1 ~ 65535 之间");
        if(enabled&&(user.empty()||password.empty()))return Bad("远程管理账号和密码不能为空");
        SaveConfig({{"Remote_IsEnable",enabled},{"Remote_IP",ip},{"Remote_Port",port},
                    {"Remote_UserName",user},{"Remote_PassWord",password}});
        return {{"ok",true},{"running",false}};
    }
    if(method=="__wpcSnapshot"){
        return {{"servers",lists_[17]},{"notices",lists_[18]}};
    }
    if(method=="__appendLog"){
        const int list=N(args,"list",-1);
        if(list<2||list>4)return Bad("Invalid log list");
        const auto row=args.value("row",Json::object());
        if(!row.is_object())return Bad("Invalid log row");
        lists_[list].push_back(row);
        const bool auto_clear=B(config_,"LogList_AutoClear",true);
        const auto keep=std::max(100,N(config_,"LogList_AutoClear_Value",5000));
        if(auto_clear&&lists_[list].size()>static_cast<std::size_t>(keep)){
            const auto drop=lists_[list].size()-static_cast<std::size_t>(keep);
            lists_[list].erase(lists_[list].begin(),lists_[list].begin()+static_cast<Json::difference_type>(drop));
            emit_("feed:trim",{{"list",list},{"keep",keep}});
        }
        emit_("feed:append",{{"list",list},{"rows",Json::array({row})}});
        return Good();
    }
    if(method=="__setClientRows"){
        const auto input=args.value("rows",Json::array());
        if(!input.is_array())return Bad("Invalid client rows");
        Json rows=Json::array();
        for(const auto& source:input){
            if(!source.is_object())continue;
            auto row=source;
            const auto key=Trim(S(row,"AccountId"));
            // Runtime events can identify an account by username (ordinary
            // SOCKS/HTTP) or GUID (WPC).  Restore the original AuthInfo
            // contract so the UI always shows the friendly username.
            for(const auto& account:lists_[5]){
                if(Upper(S(account,"GUID"))==Upper(key)||S(account,"UserName")==key){
                    row["AccountId"]=Upper(S(account,"GUID"));
                    row["UserName"]=S(account,"UserName");
                    break;
                }
            }
            row["LinksNumber"]=std::max<std::int64_t>(0,N(row,"LinksNumber"));
            row["DevicesNumber"]=std::max<std::int64_t>(0,N(row,"DevicesNumber",1));
            row["TrafficStatistics"]=std::max<std::int64_t>(0,N(row,"TrafficStatistics"));
            row["AuthResult"]=B(row,"AuthResult",true);
            rows.push_back(std::move(row));
        }
        lists_[6]=std::move(rows);
        Publish(6);
        return Good();
    }
    if(method=="__setClientConnections"){
        const auto items=args.value("items",Json::array());
        if(!items.is_array())return Bad("Invalid client connections");
        client_connections_=items;
        return Good();
    }
    if(method=="__setAccountOnline"){
        // Runtime listeners report the authenticated username; WPC control
        // sessions report the account GUID.  Match either representation so
        // the account list reflects both ordinary proxy clients and WPC
        // heartbeats without exposing credentials to the browser.
        std::unordered_set<std::string> online;
        for(const auto& item:args.value("accounts",Json::array()))
            if(item.is_string()&&!item.get<std::string>().empty())online.insert(item.get<std::string>());
        bool changed=false;
        for(auto& row:lists_[5]){
            const bool value=online.contains(S(row,"UserName"))||online.contains(Upper(S(row,"GUID")));
            if(B(row,"IsOnLine")!=value){row["IsOnLine"]=value;changed=true;}
        }
        if(changed)Publish(5);
        return Good();
    }
    // Native-only snapshot consumed by the SOCKS5 and HTTP proxy listeners.  It deliberately
    // is not part of Methods(), so browser code cannot ask the bridge for
    // decrypted proxy credentials.
    if(method=="__proxyRuntimeConfiguration"){
        Json accounts=Json::array();
        Json wpc_accounts=Json::array();
        for(const auto& row:lists_[5]){
            const auto user=Trim(S(row,"UserName")),password=PasswordDecrypt(S(row,"PassWord"));
            if(user.empty())continue;
            if(B(row,"IsEnable")&&!password.empty())
                accounts.push_back({{"user",user},{"password",password}});
            wpc_accounts.push_back({
                {"accountId",S(row,"GUID")},{"user",user},{"password",password},
                {"enabled",B(row,"IsEnable")},{"limitDevices",B(row,"IsLimitDevices")},
                {"maxDevices",std::max(1,N(row,"LimitDevices",1))},
                {"expiry",B(row,"IsExpiry")},{"expiryTime",S(row,"ExpiryTime")}
            });
        }
        Json local_maps=Json::array();
        for(const auto& row:lists_[13]){
            if(!B(row,"IsEnable"))continue;
            local_maps.push_back({{"enabled",true},{"protocol",S(row,"ProtocolType","Http")},
                                  {"host",S(row,"Host")},{"port",N(row,"Port",80)},
                                  {"remotePath",S(row,"RemotePath")},{"localPath",S(row,"LocalPath")}});
        }
        Json remote_maps=Json::array();
        for(const auto& row:lists_[14]){
            if(!B(row,"IsEnable"))continue;
            remote_maps.push_back({{"enabled",true},{"protocolFrom",S(row,"ProtocolType_From","Http")},
                                   {"hostFrom",S(row,"Host_From")},{"portFrom",N(row,"Port_From",80)},
                                   {"pathFrom",S(row,"Path_From")},{"protocolTo",S(row,"ProtocolType_To","Http")},
                                   {"hostTo",S(row,"Host_To")},{"portTo",N(row,"Port_To",80)},
                                   {"pathTo",S(row,"Path_To")}});
        }
        const auto capture_mask=Split(S(config_,"CheckType_Value",""),':');
        auto capture_flag=[&](std::size_t index){int value=0;return index<capture_mask.size()&&Integer(capture_mask[index],value)&&value!=0;};
        const Json capture_filter={
            {"notShow",B(config_,"CheckNotShow",true)},
            {"checkSocket",B(config_,"CheckSocket")},{"socketValue",S(config_,"CheckSocket_Value")},
            {"checkIP",B(config_,"CheckIP")},{"ipValue",S(config_,"CheckIP_Value")},
            {"checkPort",B(config_,"CheckPort")},{"portValue",S(config_,"CheckPort_Value")},
            {"checkHead",B(config_,"CheckHead")},{"headValue",S(config_,"CheckHead_Value")},
            {"checkData",B(config_,"CheckData")},{"dataValue",S(config_,"CheckData_Value")},
            {"checkLen",B(config_,"CheckSize")},{"lenValue",S(config_,"CheckLength_Value")},
            {"checkType",B(config_,"CheckType")},
            {"send",capture_flag(0)},{"sendTo",capture_flag(1)},{"recv",capture_flag(2)},{"recvFrom",capture_flag(3)},
            {"wsaSend",capture_flag(4)},{"wsaSendTo",capture_flag(5)},{"wsaRecv",capture_flag(6)},{"wsaRecvFrom",capture_flag(7)},
            {"tcpReq",capture_flag(8)},{"udpReq",capture_flag(9)},{"tcpResp",capture_flag(10)},{"udpResp",capture_flag(11)}
        };
        return {{"proxyIpAuto",B(proxy_config_,"ProxyIP_Auto",true)},
                {"proxyIp",S(proxy_config_,"ProxyIP")},
                {"enableSocks5",B(proxy_config_,"Enable_SOCKS5",true)},
                {"socks5Port",N(proxy_config_,"SOCKS5_Port",1080)},
                {"enableHttp",B(proxy_config_,"Enable_HTTP",true)},
                {"httpPort",N(proxy_config_,"HTTP_Port",1081)},
                {"enableAuth",B(proxy_config_,"EnableAuth",true)},
                {"onlyWpc",B(proxy_config_,"Only_WPC_Client")},
                {"maxConnection",N(proxy_config_,"MaxConnectionNumber",5000)},
                {"enableLocalMap",B(proxy_config_,"Enable_MapLocal")},
                {"enableRemoteMap",B(proxy_config_,"Enable_MapRemote")},
                {"localMaps",std::move(local_maps)},
                {"remoteMaps",std::move(remote_maps)},
                {"captureFilter",capture_filter},
                {"accounts",std::move(accounts)},{"wpcAccounts",std::move(wpc_accounts)}};
    }
    if(method=="saveProxySetting"){
        const bool socks=B(args,"enableSocks5"),http=B(args,"enableHttp"),automatic=B(args,"proxyIpAuto"),auth=B(args,"enableAuth"),only=B(args,"onlyWpc");
        const int socksPort=N(args,"socks5Port",1080),httpPort=N(args,"httpPort",1081),maximum=N(args,"maxConnection",5000);const auto ip=Trim(S(args,"proxyIp"));
        if(!socks)return Bad(Text("ProxySettingsForm.ProxyType.Error","代理类型未设置"));
        if(http&&socksPort==httpPort)return Bad(Text("ProxySettingsForm.ProxyType.Error","SOCKS 和 HTTP 端口不能相同"));
        if(socksPort<1||socksPort>65535||httpPort<1||httpPort>65535)return Bad(Text("ProxySettingsForm.Port.Error","端口必须在 1 ~ 65535 之间"));
        if(!automatic&&!ValidIp(ip))return Bad(Text("ProxySettingsForm.ProxyIP.Empty","请选择监听地址，或勾上「自动检测」"));
        if(only&&!auth)return Bad(Text("ProxySettingsForm.OnlyWpc.NeedAuth","「只允许 WPC 客户端连接」需要先启用身份认证"));
        if(maximum<1||maximum>MaxConnectionCap())return Bad(Text("ProxySettingsForm.MaxConnection.Error","最大连接数超出本机可预留内存范围"));
        SaveProxyConfig({{"ProxyIP_Auto",automatic},{"ProxyIP",ip},{"Enable_SOCKS5",socks},{"SOCKS5_Port",socksPort},{"EnableAuth",auth},
            {"Only_WPC_Client",only},{"MaxConnectionNumber",maximum},{"Enable_HTTP",http},{"HTTP_Port",httpPort}});
        const auto ips=LocalAddresses();emit_("toast",{{"level",2},{"text",Text("ProxySettingsForm.Success","代理设置保存成功")}});
        return {{"ok",true},{"socks5Addr",Address(proxy_config_,ips,false)},{"httpAddr",Address(proxy_config_,ips,true)}};
    }
    if(method=="getHookSetting")return {
        {"ws1Send",B(inject_config_,"HookWS1_Send",true)},{"ws1SendTo",B(inject_config_,"HookWS1_SendTo",true)},
        {"ws1Recv",B(inject_config_,"HookWS1_Recv",true)},{"ws1RecvFrom",B(inject_config_,"HookWS1_RecvFrom",true)},
        {"ws2Send",B(inject_config_,"HookWS2_Send",true)},{"ws2SendTo",B(inject_config_,"HookWS2_SendTo",true)},
        {"ws2Recv",B(inject_config_,"HookWS2_Recv",true)},{"ws2RecvFrom",B(inject_config_,"HookWS2_RecvFrom",true)},
        {"wsaSend",B(inject_config_,"HookWSA_Send",true)},{"wsaSendTo",B(inject_config_,"HookWSA_SendTo",true)},
        {"wsaRecv",B(inject_config_,"HookWSA_Recv",true)},{"wsaRecvFrom",B(inject_config_,"HookWSA_RecvFrom",true)},
        {"tcpReq",hook_tcp_req_},{"tcpResp",hook_tcp_resp_},{"udpReq",hook_udp_req_},{"udpResp",hook_udp_resp_},
        {"unpack",B(proxy_config_,"Enable_UnPack")},{"unpackHead",S(proxy_config_,"UnPack_Head")},{"unpackLength",S(proxy_config_,"UnPack_Length")}};
    if(method=="saveHookSetting"){
        Json inject=Json::object();const std::array<std::pair<const char*,const char*>,12> hooks={{{"ws1Send","HookWS1_Send"},{"ws1SendTo","HookWS1_SendTo"},{"ws1Recv","HookWS1_Recv"},{"ws1RecvFrom","HookWS1_RecvFrom"},
            {"ws2Send","HookWS2_Send"},{"ws2SendTo","HookWS2_SendTo"},{"ws2Recv","HookWS2_Recv"},{"ws2RecvFrom","HookWS2_RecvFrom"},{"wsaSend","HookWSA_Send"},{"wsaSendTo","HookWSA_SendTo"},{"wsaRecv","HookWSA_Recv"},{"wsaRecvFrom","HookWSA_RecvFrom"}}};
        for(const auto& [arg,key]:hooks)if(args.contains(arg)&&!args.at(arg).is_null())inject[key]=B(args,arg);if(!inject.empty())SaveInjectConfig(inject);
        if(args.contains("tcpReq")&&!args.at("tcpReq").is_null()){
            const bool unpack=B(args,"unpack");const auto head=Trim(S(args,"unpackHead")),length=Trim(S(args,"unpackLength"));
            if(unpack){if(!std::regex_match(head,std::regex(R"(^[0-9A-Fa-f]{2}([ ,;]+[0-9A-Fa-f]{2})*$)"))||!std::regex_match(length,std::regex(R"(^\d+-\d+$)")))return Bad(Text("HookSettingsForm.UnPack.Error","拆包设置不正确"));
                const auto dash=length.find('-');int start=0,end=0;if(!Integer(length.substr(0,dash),start)||!Integer(length.substr(dash+1),end)||end<start)return Bad(Text("HookSettingsForm.UnPack.Error","拆包设置不正确"));}
            hook_tcp_req_=B(args,"tcpReq");hook_tcp_resp_=B(args,"tcpResp");hook_udp_req_=B(args,"udpReq");hook_udp_resp_=B(args,"udpResp");
            SaveProxyConfig({{"Enable_UnPack",unpack},{"UnPack_Head",head},{"UnPack_Length",length}});
        }
        emit_("toast",{{"level",2},{"text",Text("HookSettingsForm.Success","拦截设置保存成功")}});return Good();
    }
    if(method=="getFireWall")return {{"enable",B(proxy_config_,"EnableFireWall")},{"whiteMode",B(proxy_config_,"WhiteListMode")},
        {"autoWhiteAuthOk",B(proxy_config_,"FireWall_AutoWhiteList_AuthSuccess")},{"autoBlackUnsupport",B(proxy_config_,"FireWall_AutoBlackList_UnSupport")},
        {"autoBlackAuthFail",B(proxy_config_,"FireWall_AutoBlackList_AuthFail")},{"autoBlackMinutes",N(proxy_config_,"FireWall_AutoBlackList_Minutes",30)},
        {"autoClearExpiry",B(proxy_config_,"FireWall_AutoClear_Expiry")}};
    if(method=="saveFireWall"){
        const int minutes=N(args,"autoBlackMinutes",30);if(minutes<1||minutes>525600)return Bad(Text("FireWallSetting.Minutes.Range","屏蔽时长需在 1 ~ 525600 分钟之间"));
        SaveProxyConfig({{"EnableFireWall",B(args,"enable")},{"WhiteListMode",B(args,"whiteMode")},{"FireWall_AutoWhiteList_AuthSuccess",B(args,"autoWhiteAuthOk")},
            {"FireWall_AutoBlackList_UnSupport",B(args,"autoBlackUnsupport")},{"FireWall_AutoBlackList_AuthFail",B(args,"autoBlackAuthFail")},
            {"FireWall_AutoBlackList_Minutes",minutes},{"FireWall_AutoClear_Expiry",B(args,"autoClearExpiry")}});return Good();
    }
    if(method=="getAccountPassword"){
        const auto id=Upper(S(args,"id"));for(const auto& row:lists_[5])if(Upper(S(row,"GUID"))==id)return {{"password",PasswordDecrypt(S(row,"PassWord"))}};return {{"password",""}};
    }
    if(method=="getAccountLogins"){
        const auto id=Upper(S(args,"id"));for(const auto& row:lists_[5])if(Upper(S(row,"GUID"))==id)return {{"rows",row.value("_logins",Json::array())}};return {{"rows",Json::array()}};
    }
    if(method=="saveAccount"){
        const auto id=Upper(S(args,"id")),user=Trim(S(args,"userName")),password=Trim(S(args,"password"));if(user.empty())return Bad(Text("AccountEditForm.UserName.Empty","请输入用户名"));if(id.empty()&&password.empty())return Bad(Text("AccountEditForm.PassWord.Empty","请输入密码"));
        const bool expiry=B(args,"isExpiry"),limitLinks=B(args,"isLimitLinks"),limitDevices=B(args,"isLimitDevices");const auto parsed=DateTimeText(S(args,"expiryTime"));if(expiry&&!parsed)return Bad(Text("AccountEditForm.ExpiryTime","过期时间格式不正确"));const auto expiryTime=expiry?*parsed:*AddDateTimeYears(LocalDateTime(),100);auto rows=lists_[5];
        if(id.empty()){
            for(const auto& row:rows)if(S(row,"UserName")==user)return Bad(Text("AccountEditForm.UserName.Error","用户名已存在"));
            rows.push_back({{"GUID",Guid()},{"IsEnable",B(args,"isEnable")},{"UserName",user},{"PassWord",PasswordEncrypt(password)},{"IsLimitLinks",limitLinks},{"LimitLinks",limitLinks?std::max(1,N(args,"limitLinks")):N(args,"limitLinks")},{"IsLimitDevices",limitDevices},{"LimitDevices",limitDevices?std::max(1,N(args,"limitDevices")):N(args,"limitDevices")},{"IsExpiry",expiry},{"ExpiryTime",expiryTime},{"CreateTime",LocalDateTime()},{"IsOnLine",false},{"_logins",Json::array()}});
        }else{
            auto found=std::find_if(rows.begin(),rows.end(),[&](const Json& row){return Upper(S(row,"GUID"))==id;});if(found==rows.end())return Bad(Text("AccountList.Empty","请选择账号"));found->at("IsEnable")=B(args,"isEnable");if(!password.empty())found->at("PassWord")=PasswordEncrypt(password);found->at("IsLimitLinks")=limitLinks;found->at("LimitLinks")=limitLinks?std::max(1,N(args,"limitLinks")):N(args,"limitLinks");found->at("IsLimitDevices")=limitDevices;found->at("LimitDevices")=limitDevices?std::max(1,N(args,"limitDevices")):N(args,"limitDevices");found->at("IsExpiry")=expiry;found->at("ExpiryTime")=expiryTime;
        }SaveAccounts(rows);emit_("toast",{{"level",1},{"text",Text("AccountEditForm.Success","账号保存成功")}});return Good();
    }
    if(method=="deleteAccount"){
        const auto id=Upper(S(args,"id"));if(id.empty())return Json{{"ok",false}};auto rows=lists_[5];const auto found=std::find_if(rows.begin(),rows.end(),[&](const Json& row){return Upper(S(row,"GUID"))==id;});if(found==rows.end())return Json{{"ok",false}};rows.erase(found);SaveAccounts(rows);return Good();
    }
    if(method=="clearAllAccounts"){SaveAccounts(Json::array());return Good();}
    if(method=="setAccountEnable"){
        const auto id=Upper(S(args,"id"));auto rows=lists_[5];const auto found=std::find_if(rows.begin(),rows.end(),[&](const Json& row){return Upper(S(row,"GUID"))==id;});if(found==rows.end())return Json{{"ok",false}};found->at("IsEnable")=B(args,"enable");SaveAccounts(rows);return Good();
    }
    if(method=="previewBatchAccounts"){
        const int count=std::clamp(N(args,"count",10),1,999),rule=N(args,"rule"),passwordLength=std::clamp(N(args,"passwordLength",6),1,20);const auto prefix=Trim(S(args,"prefix"));
        if(rule==1&&prefix.empty())return {{"ok",false},{"error",Text("BatchAccounts.Prefix.Empty","请输入用户名前缀")},{"rows",Json::array()}};
        const auto head=rule==1?prefix:BatchTimeHead();Json rows=Json::array(),duplicates=Json::array();rows.get_ref<Json::array_t&>().reserve(static_cast<std::size_t>(count));
        for(int i=1;i<=count;++i){std::ostringstream suffix;suffix<<std::setfill('0')<<std::setw(3)<<i;const auto user=head+suffix.str();rows.push_back({{"UserName",user},{"Password",BatchPassword(passwordLength)}});for(const auto& existing:lists_[5])if(S(existing,"UserName")==user){duplicates.push_back(user);break;}}
        return {{"ok",true},{"error",""},{"rows",std::move(rows)},{"duplicates",std::move(duplicates)}};
    }
    if(method=="saveBatchAccounts"){
        const auto draft=BatchRows(args);if(draft.empty())return {{"ok",false},{"added",0},{"skipped",0},{"error",Text("BatchAccounts.Empty","没有可保存的账号")}};
        const bool limitLinks=B(args,"isLimitLinks"),limitDevices=B(args,"isLimitDevices"),expiry=B(args,"isExpiry");const int links=N(args,"limitLinks"),devices=N(args,"limitDevices");const auto expiryTime=BatchExpiry(args);auto rows=lists_[5];int added=0;
        for(const auto& item:draft){const auto user=S(item,"UserName"),password=S(item,"Password");if(user.empty()||password.empty())continue;bool duplicate=false;for(const auto& row:rows)if(S(row,"UserName")==user){duplicate=true;break;}if(duplicate)continue;
            rows.push_back({{"GUID",Guid()},{"IsEnable",true},{"UserName",user},{"PassWord",PasswordEncrypt(password)},
                {"IsLimitLinks",limitLinks},{"LimitLinks",limitLinks?std::max(1,links):links},{"IsLimitDevices",limitDevices},{"LimitDevices",limitDevices?std::max(1,devices):devices},
                {"IsExpiry",expiry},{"ExpiryTime",expiryTime},{"CreateTime",LocalDateTime()},{"IsOnLine",false},{"_logins",Json::array()}});++added;
        }
        if(added){const auto first=lists_[5].size();db_.Transaction([&]{PersistAccounts(rows);});lists_[5]=rows;auto fresh=Rows(5);fresh.erase(fresh.begin(),fresh.begin()+static_cast<Json::difference_type>(first));emit_("feed:append",{{"list",5},{"rows",std::move(fresh)}});}
        return {{"ok",true},{"added",added},{"skipped",static_cast<int>(draft.size())-added},{"error",""}};
    }
    if(method=="adjustAccountExpiry"){
        const int hours=N(args,"hours"),addType=N(args,"addType");if(!hours)return { {"ok",false},{"count",0},{"error",Text("ExpiryTimeForm.Zero","请输入要增加的时长")} };std::set<std::string> ids;for(const auto& id:args.value("ids",Json::array()))if(id.is_string())ids.insert(Upper(id.get<std::string>()));auto rows=lists_[5];int count=0;const auto now=LocalDateTime();
        for(auto& row:rows)if(ids.contains(Upper(S(row,"GUID")))){const auto base=addType==1&&S(row,"ExpiryTime")<now?now:S(row,"ExpiryTime");const auto shifted=AddDateTimeHours(base,hours);if(!shifted)return { {"ok",false},{"count",0},{"error",Text("AccountEditForm.ExpiryTime","过期时间格式不正确")} };row["ExpiryTime"]=*shifted;++count;}if(!count)return {{"ok",false},{"count",0},{"error",Text("AccountList.Empty","请选择账号")}};SaveAccounts(rows);return {{"ok",true},{"count",count},{"error",""}};
    }
    if(method=="adjustAccountLimit"){
        const bool devices=B(args,"devices"),on=B(args,"on");const int value=N(args,"value",1);if(on&&value<1)return {{"ok",false},{"count",0},{"error",Text("LimitForm.Range","限制值至少为 1")}};std::set<std::string> ids;for(const auto& id:args.value("ids",Json::array()))if(id.is_string())ids.insert(Upper(id.get<std::string>()));auto rows=lists_[5];int count=0;
        for(auto& row:rows)if(ids.contains(Upper(S(row,"GUID")))){row[devices?"IsLimitDevices":"IsLimitLinks"]=on;row[devices?"LimitDevices":"LimitLinks"]=value;++count;}if(!count)return {{"ok",false},{"count",0},{"error",Text("AccountList.Empty","请选择账号")}};SaveAccounts(rows);return {{"ok",true},{"count",count},{"error",""}};
    }
    if(method=="deleteSelectedAccounts"){
        std::set<std::string> ids;for(const auto& id:args.value("ids",Json::array()))if(id.is_string())ids.insert(Upper(id.get<std::string>()));auto rows=lists_[5];rows.erase(std::remove_if(rows.begin(),rows.end(),[&](const Json& row){return ids.contains(Upper(S(row,"GUID")));}),rows.end());SaveAccounts(rows);return Good();
    }
    if(method=="addIpRule"){
        const int list=B(args,"black")?16:15;const auto ip=Trim(S(args,"ip"));const auto range=IpRuleRange(ip);if(ip.empty()||!range||ip.find('/')!=ip.npos)return Bad("empty ip");
        for(const auto& row:lists_[list])if(Upper(S(row,"IPAddress"))==Upper(ip))return {{"ok",true},{"error",""}};
        const int hours=N(args,"hours");if(hours>876000)return Bad("expiry out of range");const bool expiry=list==16&&hours>0;const auto now=LocalDateTime(),until=expiry?LocalDateTime(hours):"8888-12-31 00:00:00";auto rows=lists_[list];
        rows.push_back({{"IPAddress",ip},{"StartIP",static_cast<std::int64_t>(range->first)},{"EndIP",static_cast<std::int64_t>(range->second)},{"IsExpiry",expiry},{"ExpiryTime",until},{"CreateTime",now},{"IPLocation",""},{"EffectCount",0}});SaveIpRules(list,rows);return {{"ok",true},{"error",""}};
    }
    if(method=="saveIPRule"){
        const int list=B(args,"black")?16:15;const auto ip=Trim(S(args,"ip")),old=Trim(S(args,"oldIp"));const auto range=IpRuleRange(ip);
        if(ip.empty()||!range||ip.find('/')!=ip.npos)return Bad(Text("FireWallSetting.IPAddress.Error","IP 地址不正确"));
        if(range->first>range->second)return Bad(Text("FireWallSetting.IPAddress.Range","IP 段的起始地址不能大于结束地址"));
        for(const auto& row:lists_[list])if(Upper(S(row,"IPAddress"))==Upper(ip)&&Upper(ip)!=Upper(old))return Bad(Text("FireWallSetting.IPAddress.Exists","这个 IP 已经在名单里了"));
        const bool expiry=B(args,"isExpiry");const auto parsed=DateTimeText(S(args,"expiry"));const auto until=!expiry||!parsed?"8888-12-31 00:00:00":*parsed;auto rows=lists_[list];
        if(old.empty())rows.push_back({{"IPAddress",ip},{"StartIP",static_cast<std::int64_t>(range->first)},{"EndIP",static_cast<std::int64_t>(range->second)},{"IsExpiry",expiry},{"ExpiryTime",until},{"CreateTime",LocalDateTime()},{"IPLocation",""},{"EffectCount",0}});
        else {auto found=std::find_if(rows.begin(),rows.end(),[&](const Json& row){return Upper(S(row,"IPAddress"))==Upper(old);});if(found==rows.end())return Bad(Text("FireWallSetting.IPAddress.Gone","这一条已经不在名单里了"));found->at("IPAddress")=ip;found->at("IsExpiry")=expiry;found->at("ExpiryTime")=until;found->at("IPLocation")="";}
        SaveIpRules(list,rows);return {{"ok",true},{"error",""}};
    }
    if(method=="deleteIPRule"){
        const int list=B(args,"black")?16:15;const auto ip=Upper(Trim(S(args,"ip")));auto rows=lists_[list];const auto found=std::find_if(rows.begin(),rows.end(),[&](const Json& row){return Upper(S(row,"IPAddress"))==ip;});
        if(ip.empty()||found==rows.end())return Json{{"ok",false}};rows.erase(found);SaveIpRules(list,rows);return Good();
    }
    if(method=="ipRuleAction"){
        if(N(args,"action",-1)!=7)throw std::invalid_argument("Unsupported IP rule action");const int list=B(args,"black")?16:15;const auto before=lists_[list].size();SaveIpRules(list,Json::array());return {{"ok",true},{"delta",-static_cast<std::int64_t>(before)}};
    }
    if(method=="saveListAutoClear"){
        Json changes=Json::object();if(args.contains("autoClear"))changes["PacketList_AutoClear"]=B(args,"autoClear");if(args.contains("autoClearValue")){const int keep=N(args,"autoClearValue");if(keep<100||keep>500000)return Bad(Text("ListSettingsForm.Range","保留条数需在 100 ~ 500000 之间"));changes["PacketList_AutoClear_Value"]=keep;}SaveInjectConfig(changes);return Good();
    }
    if(method=="getFilterExecute")return {{"mode",N(config_,"FilterExecute",1)}};
    if(method=="getAutoStoresMeta")return {{"enable",auto_stores_enabled_},{"limit",B(config_,"StoresLimit",true)},{"limitValue",N(config_,"StoresLimit_Value",5000)}};
    if(method=="setAutoStoresSwitch"){
        auto_stores_enabled_=B(args,"enable");Json changes=Json::object();if(args.contains("limit"))changes["StoresLimit"]=B(args,"limit");if(args.contains("limitValue"))changes["StoresLimit_Value"]=std::clamp(N(args,"limitValue"),1,1000000);if(!changes.empty())SaveConfig(changes);
        return {{"ok",true},{"enable",auto_stores_enabled_},{"limit",B(config_,"StoresLimit",true)},{"limitValue",N(config_,"StoresLimit_Value",5000)}};
    }
    if(method=="saveAutoStores"){
        const auto head=Trim(S(args,"head")),compact=Upper(Trim(head,true));if(compact.empty())return Bad(Text("AutoStoresEdit.PacketHead.Error","指定包头设置错误"));
        if(compact.size()%2||!std::all_of(compact.begin(),compact.end(),[](char c){return (c>='0'&&c<='9')||(c>='A'&&c<='F');}))return Bad(Text("AutoStoresEdit.PacketHead.Hex","指定包头应是十六进制字节，如 16 03 01"));
        const auto wid=NormalGuid(S(args,"wid"));if(wid==zero_guid||!Find(11,wid))return Bad(Text("AutoStoresEdit.WareHouse.Error","请选择入库名称"));
        const auto id=Upper(S(args,"id"));auto rows=lists_[12];auto self=rows.end();if(!id.empty())self=std::find_if(rows.begin(),rows.end(),[&](const Json& row){return Upper(S(row,"_id"))==id;});
        for(auto it=rows.begin();it!=rows.end();++it)if(it!=self&&Upper(Trim(S(*it,"PacketHead"),true))==compact)return Bad(Text("AutoStoresEdit.PacketHead.Exists","这个包头已经有一条规则了"));
        if(self==rows.end())rows.push_back({{"IsEnable",false},{"PacketHead",head},{"WID",wid},{"_id",Guid()}});else{(*self)["PacketHead"]=head;(*self)["WID"]=wid;}
        db_.Transaction([&]{PersistAutoStores(rows);});lists_[12]=std::move(rows);Publish(12);return {{"ok",true},{"error",""}};
    }
    if(method=="setAutoStoresEnable"){
        const auto id=Upper(S(args,"id"));auto rows=lists_[12];auto row=std::find_if(rows.begin(),rows.end(),[&](const Json& item){return Upper(S(item,"_id"))==id;});if(row==rows.end())return {{"ok",false}};(*row)["IsEnable"]=B(args,"enable");db_.Transaction([&]{PersistAutoStores(rows);});lists_[12]=std::move(rows);Publish(12);return Good();
    }
    if(method=="deleteAutoStores"){
        const auto id=Upper(S(args,"id"));auto rows=lists_[12];auto row=std::find_if(rows.begin(),rows.end(),[&](const Json& item){return Upper(S(item,"_id"))==id;});if(row==rows.end())return {{"ok",false}};rows.erase(row);db_.Transaction([&]{PersistAutoStores(rows);});lists_[12]=std::move(rows);Publish(12);return Good();
    }
    if(method=="autoStoresAction"){
        const int action=N(args,"action",-1);if(action==5||action==8)return Good();if(action<0||action>7||action==4||action==6)throw std::invalid_argument("Unsupported auto-store action");auto rows=lists_[12];
        if(action==7)rows.clear();else{const auto id=Upper(S(args,"id"));auto it=std::find_if(rows.begin(),rows.end(),[&](const Json& item){return Upper(S(item,"_id"))==id;});if(it==rows.end())return Good();const auto index=static_cast<std::size_t>(it-rows.begin());if((action==1&&index==0)||(action==2&&index+1==rows.size()))return Good();auto row=*it;rows.erase(it);const auto target=action==0?0:action==1?index-1:action==2?index+1:action==3?rows.size():index;rows.insert(rows.begin()+static_cast<Json::difference_type>(target),std::move(row));}
        db_.Transaction([&]{PersistAutoStores(rows);});lists_[12]=std::move(rows);Publish(12);return Good();
    }
    if(method=="getSendMeta")return {{"systemSocket",0},{"running",false},{"listExecute",N(config_,"ListExecute",1)}};
    if(method=="getRobotMeta")return {{"running",false},{"listExecute",N(config_,"ListExecute",1)}};
    if(method=="enterProxyMode"){PublishAll();return Good();}
    if(method=="enterInjectMode")return {{"ok",true},{"lastInject",nullptr}};
    if(method=="getClientConnections"){
        const auto wanted=Trim(S(args,"ip"));
        Json items=Json::array();
        for(const auto& item:client_connections_){
            if(!wanted.empty()&&S(item,"ClientIP")!=wanted)continue;
            items.push_back(item);
        }
        return {{"items",std::move(items)}};
    }
    if(method=="getStats")return {{"queue",0},{"list",0},{"total",0},{"proxyRunning",false},{"tcpReq",0},{"tcpResp",0},{"udpReq",0},{"udpResp",0},{"httpReq",0},{"httpResp",0},{"filterExecute",0},{"filterProxy",0},{"tcpConn",0},{"udpConn",0},{"onlineInfo",""},{"totalRequest",0},{"totalResponse",0},{"speedUp",0},{"speedDown",0},{"mappingHits",0},{"mappingMisses",0},{"mappingErrors",0}};
    if(method=="clearLogs"){const auto kind=N(args,"kind");if(kind<0||kind>2)return Bad("Invalid log kind");lists_[kind+2].clear();Publish(kind+2);return Good();}
    const std::array<std::string,4> singular={"Filter","Send","Robot","WareHouse"},plural={"Filters","Sends","Robots","WareHouses"};
    for(int list=8;list<=11;++list){
        const auto& noun=singular[list-8];auto lower=noun;lower[0]=static_cast<char>(lower[0]+32);
        if(method=="add"+noun){auto rows=lists_[list];auto row=NewRow(list);const auto id=row["GUID"];rows.push_back(std::move(row));SaveList(list,rows);return {{"id",id}};}
        if(method==lower+"ListAction")return ListAction(list,args);
        if(method=="clear"+plural[list-8]){SaveList(list,Json::array());return Good();}
        if(list==11)continue;
        if(method=="set"+noun+"Enable"){
            if(!Find(list,S(args,"id")))return {{"ok",false}};
            auto rows=lists_[list];for(auto& row:rows)if(S(row,"GUID")==Upper(S(args,"id")))row["IsEnable"]=B(args,"enable");SaveList(list,rows);return Good();
        }
        if(method=="setAll"+noun+"Enable"){
            auto rows=lists_[list];int count=0;for(auto& row:rows)if(B(row,"IsEnable")!=B(args,"enable")){row["IsEnable"]=B(args,"enable");++count;}if(count)SaveList(list,rows);return {{"ok",true},{"count",count}};
        }
        if(method=="reset"+noun+"Count"){Publish(list);return Good();}
    }
    if(method=="getFilterEdit"){const auto row=Find(8,S(args,"id"));return {{"row",row?FilterEdit(*row):Json{}}};}
    if(method=="saveFilterEdit")return SaveFilter(args);
    if(method=="getExecuteTargets"){
        const int type=N(args,"type");const int list=type==0?9:type==1?10:type==3?8:type==4?11:-1;Json items=Json::array();
        if(list>=0)for(const auto& row:lists_[list])if(S(row,"GUID")!=Upper(S(args,"excludeId")))items.push_back({{"Id",row["GUID"]},{"Name",row["Name"]}});return {{"items",items}};
    }
    if(method=="openSendEdit"){
        auto row=Find(9,S(args,"id"));
        if(!row)return {{"Id",""},{"Name",""},{"UseSystemSocket",false},{"LoopCount",0},{"LoopInterval",0},{"Notes",""},{"SystemSocket",0}};
        send_edit_=*row;
        return {{"Id",row->at("GUID")},{"Name",row->at("Name")},{"UseSystemSocket",B(*row,"SystemSocket")},{"LoopCount",N(*row,"LoopCNT")},{"LoopInterval",N(*row,"LoopINT")},{"Notes",S(*row,"Notes")},{"SystemSocket",0}};
    }
    if(method=="closeSendEdit"){send_edit_=nullptr;return Good();}
    if(method=="getSendCollection"){
        Json rows=Json::array();if(!send_edit_.is_null())for(const auto& p:send_edit_["_children"])rows.push_back({{"Id",p["_id"]},{"Socket",p["Socket"]},{"Type",p["Type"]},{"From",p["IPFrom"]},{"To",p["IPTo"]},{"Len",Size(p["Buffer"])},{"Preview",Hex(p["Buffer"])}});return {{"rows",rows}};
    }
    if(method=="saveSendEdit"){
        if(send_edit_.is_null()||!Find(9,S(send_edit_,"GUID")))return {{"error",Text("SendEditForm.Gone","这条发送已经不在列表里了")}};
        auto name=Trim(S(args,"name"));if(name.empty())return {{"error",Text("SendEditForm.SendName.Empty","发送名称为空")}};
        auto next=send_edit_;next.update({{"Name",name},{"SystemSocket",B(args,"useSystemSocket")},{"LoopCNT",std::max(1,N(args,"loopCount",1))},{"LoopINT",std::max(0,N(args,"loopInterval"))},{"Notes",Trim(S(args,"notes"))}});
        // Editing the name must not roll back a list enable toggle made meanwhile.
        next["IsEnable"]=Find(9,S(next,"GUID"))->at("IsEnable");
        next["_objectId"]=Find(9,S(next,"GUID"))->at("_objectId");
        auto rows=lists_[9];for(auto& row:rows)if(row["GUID"]==next["GUID"])row=next;SaveList(9,rows);send_edit_=std::move(next);return {{"error",""}};
    }
    if(method=="openWareHouseEdit"){auto row=Find(11,S(args,"wid"));return {{"id",row?S(*row,"GUID"):""},{"name",row?S(*row,"Name"):""}};}
    if(method=="saveWareHouseName"){
        auto row=Find(11,S(args,"wid"));if(!row)return {{"error","仓库不存在"}};auto name=Trim(S(args,"name"));if(name.empty())return {{"error","仓库名称为空"}};
        auto rows=lists_[11];for(auto& item:rows)if(item["GUID"]==row->at("GUID"))item["Name"]=name;SaveList(11,rows);return {{"error",""}};
    }
    if(method=="getStoreRows"||method=="getStorePreviews"||method=="copyStoresHex"){
        auto row=Find(11,S(args,"wid"));Json items=Json::array();std::string hex;
        std::set<std::string> ids;for(const auto& id:args.value("ids",Json::array()))if(id.is_string())ids.insert(Upper(id.get<std::string>()));
        if(row){const auto& data=row->at("_children");const auto from=static_cast<std::size_t>(std::max(0,N(args,"from"))),count=static_cast<std::size_t>(std::max(0,N(args,"count")));
            for(std::size_t i=0;i<data.size();++i){const auto& p=data[i];
                if(method=="getStoreRows")items.push_back({{"Id",p["_id"]},{"Len",Size(p["Buffer"])},{"Preview",""}});
                else if(method=="getStorePreviews"&&i>=from&&i-from<count)items.push_back(Hex(p["Buffer"]));
                else if(method=="copyStoresHex"&&ids.contains(S(p,"_id")))hex+=Hex(p["Buffer"],Size(p["Buffer"]))+"\r\n";
            }
        }
        if(method=="copyStoresHex")return {{"text",hex}};
        return {{method=="getStoreRows"?"rows":"items",items}};
    }
    if(method=="setListEnable"){
        const int list=std::clamp(N(args,"list",9),8,11);auto rows=lists_[list];auto* row=Find(list,S(args,"id"));if(!row)return Json{{"ok",false}};for(auto& item:rows)if(S(item,"GUID")==S(*row,"GUID"))item["IsEnable"]=B(args,"enable");SaveList(list,rows);return Good();
    }
    if(method=="__appendPacketToSend"||method=="__appendPacketToWareHouse"){
        const int list=method.ends_with("Send")?9:11;auto rows=lists_[list];auto* parent=Find(list,S(args,list==9?"sid":"wid"));if(!parent)return Json{{"count",0}};Json child={{"_id",Guid()},{"Socket",N(args,"socket")},{"Type",N(args,"type")},{"IPFrom",S(args,"from")},{"IPTo",S(args,"to")},{"Buffer",Json::binary(Unb64(S(args,"buffer")))}};for(auto& item:rows)if(S(item,"GUID")==S(*parent,"GUID")){item["_children"].push_back(std::move(child));TrimStores(item["_children"]);}SaveList(list,rows);return Json{{"count",1}};
    }
    if(method=="__appendPacketToFilter"){
        auto row=NewRow(8);row["Name"]="封包滤镜";row["Search"]="0|"+S(args,"hex");auto rows=lists_[8];const auto id=row["GUID"];rows.push_back(std::move(row));SaveList(8,rows);return Json{{"ok",true},{"id",id}};
    }
    throw std::runtime_error("尚未实现的方法: "+method);
}
}
