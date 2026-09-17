#include "shell/data_service.h"
#include "shell/data_schema.h"
#include "shell/data_worker.h"
#include "shell/config_xml.h"
#include "shell/xml_crypto.h"
#include "shell/editor_xml.h"
#include <chrono>
#include <iostream>
#include <thread>
#define NOMINMAX
#include <windows.h>
using namespace wpe::shell;namespace fs=std::filesystem;
namespace {
int checks=0;void Check(bool ok,const std::string& message){++checks;if(!ok)throw std::runtime_error(message);}
template<class F>void Throws(F f){bool thrown=false;try{f();}catch(const std::exception&){thrown=true;}Check(thrown,"Expected failure");}
std::string Path(const fs::path& p){const auto u=p.u8string();return {u.begin(),u.end()};}
const std::array<std::string,4> kinds={"fp","sp","rp","whp"},imports={"importFilters","importSends","importRobots","importWareHouses"},exports={"exportFilters","exportSends","exportRobots","exportWareHouses"};
}
int main(int argc,char** argv){try{
    if(argc!=2)throw std::runtime_error("Fixture directory required");const fs::path fixtures=fs::path(argv[1])/"config-files",golden=fixtures/"original";
    const auto dir=fs::current_path()/"config-test"/std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());fs::create_directories(dir);
    auto read=[](const fs::path& p){return ReadXmlFileBytes(p);};
    const auto crypto=Json::parse(read(golden/"crypto.json"));Check(GetACP()==crypto.at("codePage").get<UINT>(),"ACP differs from original oracle: regenerate vectors on this system");
    for(const auto& test:crypto.at("cases")){
        const auto plain=read(golden/test.at("plain").get<std::string>()),cipher=read(golden/test.at("encrypted").get<std::string>()),password=test.at("password").get<std::string>();
        Check(CryptXml(plain,password,true)==cipher,"CNG encryption differs from original for "+test.at("encrypted").get<std::string>());
        Check(CryptXml(cipher,password,false)==plain,"CNG decryption differs from original");
        Throws([&]{(void)ParseXml(CryptXml(cipher,"wrong-fixed-test-password",false));});
    }
    std::uint64_t nextId=0;const auto system=ParseSystemConfig(ParseXml(read(golden/"system.xml")),Json::object());
    Json emptyInject={{"HookWS1_Send",true},{"HookWS1_SendTo",true},{"HookWS1_Recv",true},{"HookWS1_RecvFrom",true},{"HookWS2_Send",true},{"HookWS2_SendTo",true},{"HookWS2_Recv",true},{"HookWS2_RecvFrom",true},{"HookWSA_Send",true},{"HookWSA_SendTo",true},{"HookWSA_Recv",true},{"HookWSA_RecvFrom",true},{"PacketList_AutoRoll",false},{"PacketList_AutoClear",true},{"PacketList_AutoClear_Value",5000}};
    Json emptyProxy;{Database schema(dir/"settings-schema.db");schema.Execute(data_schema);schema.Execute("INSERT INTO ProxyMode DEFAULT VALUES");emptyProxy=schema.Query("SELECT * FROM ProxyMode")[0];}
    {const auto legacyFile=dir/"legacy-settings.db";Database legacy(legacyFile);legacy.Execute(data_schema);legacy.Execute("ALTER TABLE SystemConfig DROP COLUMN ThemeFollowSystem");legacy.Execute("ALTER TABLE ProxyMode DROP COLUMN DriverType");legacy.Execute("ALTER TABLE ProxyMode DROP COLUMN SelectProcessNames");legacy.Execute("ALTER TABLE ProxyMode DROP COLUMN Only_WPC_Client");
        DataService migrated(legacyFile,[](std::string,Json){});const auto saved=migrated.Call("saveProxySetting",{{"proxyIpAuto",true},{"proxyIp",""},{"enableSocks5",true},{"socks5Port",1080},{"enableHttp",false},{"httpPort",1081},{"enableAuth",true},{"onlyWpc",true},{"maxConnection",5000}});Check(saved["ok"]==true,"Original old settings schema did not migrate");
        const auto columns=legacy.Query("PRAGMA table_info(ProxyMode)");std::set<std::string> names;for(const auto& column:columns)names.insert(column["name"].get<std::string>());Check(names.contains("DriverType")&&names.contains("SelectProcessNames")&&names.contains("Only_WPC_Client"),"ProxyMode migration columns missing");}
    const auto inject=ParseInjectMode(ParseXml(read(golden/"inject.xml")),emptyInject),proxy=ParseProxyMode(ParseXml(read(golden/"proxy.xml")),emptyProxy);
    Check(SerializeXml(InjectModeXml(inject))==read(golden/"inject.xml"),"InjectMode XML differs from original");
    Check(SerializeXml(ProxyModeXml(proxy))==read(golden/"proxy.xml"),"ProxyMode XML differs from original");
    Check(SerializeXml(SystemConfigXml(ParseSystemConfig(ParseXml(read(golden/"system-before-import.xml")),Json::object())))==read(golden/"system.xml"),"Original null-to-empty XML import semantics");
    WriteXmlFileBytes(dir/"system.xml",SerializeXml(SystemConfigXml(system)));Check(read(dir/"system.xml")==read(golden/"system.xml"),"System config field or serialization differs");
    for(int i=0;i<4;++i){const auto rows=ParseParentList(i+8,ParseXml(read(fixtures/("input."+kinds[i]))),{},nextId,system);const auto xml=SerializeXml(ParentListXml(i+8,rows));
        WriteXmlFileBytes(dir/("native."+kinds[i]),xml);Check(xml==read(golden/("original."+kinds[i])),"Parent XML differs from original: "+kinds[i]);
    }
    for(const auto& edge:std::array<std::pair<std::string,int>,3>{{{"namespace",9},{"trailing",8},{"namespaced-root",9}}}){
        const auto base=fixtures/"edges";const auto rows=ParseParentList(edge.second,ParseXml(read(base/(edge.first+"-input.xml"))),{},nextId,system);
        Check(SerializeXml(ParentListXml(edge.second,rows))==read(base/(edge.first+"-original.xml")),"Original XML edge parity: "+edge.first);
    }
    Check(ReadEditorXmlNode(ParseXml("<SendCollection><Collection><Buffer>AA<X/>BB</Buffer></Collection></SendCollection>"),true)[0]["Buffer"]==Json::binary({0xaa,0xbb}),"Mixed XML field content lost");
    std::vector<Json> events;DataService service(dir/"data.sqlite",[&](std::string name,Json data){events.push_back({{"name",name},{"data",data}});});
    auto call=[&](const std::string& name,Json args=Json::object()){return service.Call(name,args);};
    {const auto local=call("getProxySetting")["localIps"];bool clean=true;for(const auto& ip:local)clean=clean&&ip.get<std::string>().find(":0:")==std::string::npos&&!ip.get<std::string>().ends_with(":0");Check(clean,"Local address accidentally included a socket port");}
    call("importBackup",{{"_filePath",Path(golden/"settings.sb")}});const auto proxyRpc=call("getProxySetting"),hookRpc=call("getHookSetting"),fireRpc=call("getFireWall");
    Check(proxyRpc["proxyIp"]=="127.0.0.1"&&proxyRpc["socks5Port"]==1088&&proxyRpc["httpPort"]==8088,"Proxy settings RPC did not load backup");
    Check(hookRpc["ws1Send"]==false&&hookRpc["ws2SendTo"]==false&&hookRpc["unpack"]==true,"Hook settings RPC did not load backup");
    Check(fireRpc["enable"]==true&&fireRpc["autoBlackMinutes"]==1440,"Firewall settings RPC did not load backup");
    auto settingsParts=Json{{"proxySet",true},{"injectSet",true},{"_filePath",Path(dir/"settings.sb")}};call("exportBackup",settingsParts);Check(read(dir/"settings.sb")==read(golden/"settings.sb"),"Native proxy/inject backup differs from original");
    Check(call("saveProxySetting",{{"proxyIpAuto",false},{"proxyIp","bad ip"},{"enableSocks5",true},{"socks5Port",1080},{"enableHttp",true},{"httpPort",1081},{"enableAuth",true},{"onlyWpc",false},{"maxConnection",5000}})["ok"]==false,"Invalid manual proxy IP accepted");
    Check(call("saveListAutoClear",{{"autoClearValue",99}})["ok"]==false,"Invalid packet auto-clear size accepted");
    const auto backup=golden/"original.sb",out=dir/"native.sb";const Json parts={{"systemConfig",true},{"filterList",true},{"sendList",true},{"robotList",true},{"wareHouse",true}};
    auto result=call("importBackup",{{"_filePath",Path(backup)}});Check(result.size()==4&&result["language"]=="en-US"&&!result["isDark"].get<bool>(),"Backup preference result");
    auto exportArgs=parts;exportArgs["_filePath"]=Path(out);call("exportBackup",exportArgs);Check(read(out)==read(backup),"Native backup data did not match original");
    for(int i=0;i<4;++i){const auto file=dir/("service."+kinds[i]);call(exports[i],{{"_filePath",Path(file)}});Check(read(file)==read(golden/("original."+kinds[i])),"Persistent parent export differs");
        const auto encryptedFile=dir/("encrypted."+kinds[i]);call(exports[i],{{"_filePath",Path(encryptedFile)},{"_password","密码中文测试"}});Check(read(encryptedFile)==read(golden/(kinds[i]+"-1.encrypted")),"Encrypted parent export differs");
        call(imports[i],{{"_filePath",Path(golden/("original."+kinds[i]))}});call(exports[i],{{"_filePath",Path(file)}});
        const auto root=ParseXml(read(file)),before=ParseXml(read(golden/("original."+kinds[i])));Check(root.nodes.size()==before.nodes.size()*2,"Import should append duplicates");
        std::set<std::string> ids;for(const auto& node:root.nodes)Check(ids.insert(node.Value("ID")).second,"Duplicate GUID not regenerated");
    }
    call("importBackup",{{"_filePath",Path(backup)}}); // Replace, not append.
    const auto wid="44444444-4444-4444-4444-444444444444";
    auto selection=call("__prepareEditorExport",{{"method","wareHouseListAction"},{"args",{{"action",5},{"ids",Json::array({wid})}}}});
    call("saveWareHouseName",{{"wid",wid},{"name","live alias"}});call("__writeEditorExport",{{"plan",selection},{"_filePath",Path(dir/"selection.whp")}});
    Check(ParseXml(read(dir/"selection.whp")).nodes[0].Value("Name")=="live alias","Parent export lost original object alias");
    selection=call("__prepareEditorExport",{{"method","wareHouseListAction"},{"args",{{"action",5},{"ids",Json::array({wid})}}}});
    call("importBackup",{{"_filePath",Path(backup)}});call("saveWareHouseName",{{"wid",wid},{"name","replacement object"}});
    call("__writeEditorExport",{{"plan",selection},{"_filePath",Path(dir/"selection.whp")}});
    Check(ParseXml(read(dir/"selection.whp")).nodes[0].Value("Name")=="live alias","Pending export reattached to different object with same GUID");
    call("importBackup",{{"_filePath",Path(backup)}});
    for(const bool send:{true,false}){
        const auto id=send?"22222222-2222-2222-2222-222222222223":"33333333-3333-3333-3333-333333333334";
        call(send?"openSendEdit":"openRobotEdit",{{"id",id}});selection=call("__prepareEditorExport",{{"method",send?"sendListAction":"robotListAction"},{"args",{{"action",5},{"ids",Json::array({id})}}}});
        call("importBackup",{{"_filePath",Path(backup)}});Check(call(send?"saveSendEdit":"saveRobotEdit",{{"name","saved old editor"}})["error"]=="","Saving existing old editor failed");
        call("__writeEditorExport",{{"plan",selection},{"_filePath",Path(dir/"old-editor.xml")}});
        Check(ParseXml(read(dir/"old-editor.xml")).nodes[0].Value("Name")==std::string(send?"empty send":"empty robot"),"Old editor rebound prior export to restored parent");
        call(send?"closeSendEdit":"closeRobotEdit");call("importBackup",{{"_filePath",Path(backup)}});
    }
    const auto pending=call("__prepareImport",{{"method","importBackup"},{"args",{{"_filePath",Path(golden/"sb-1.encrypted")}}}});
    Check(pending["encrypted"]==true,"Cipher detection");const auto token=pending.at("token");
    Check(call("__verifyImportPassword",{{"token",token},{"password","wrong"}})["ok"]==false,"Wrong password accepted");
    call("exportBackup",exportArgs);Check(read(out)==read(backup),"Password verification mutated DB");
    Check(call("__verifyImportPassword",{{"token",token},{"password","密码中文测试"}})["ok"]==true,"Original password rejected");
    call("__applyImport",{{"token",token},{"password","密码中文测试"}});Throws([&]{call("__applyImport",{{"token",token}});});
    Check(call("__verifyImportPassword",{{"token",token},{"password","密码中文测试"}})["ok"]==false,"Consumed token still usable");
    for(int i=0;i<20;++i){const auto p=call("__prepareImport",{{"method","importBackup"},{"args",{{"_filePath",Path(backup)}}}});call("__discardImport",{{"token",p["token"]}});}
    auto bad=parts;bad["proxyAccount"]=true;bad["_filePath"]=Path(out);Throws([&]{call("exportBackup",bad);});Check(read(out)==read(backup),"Unsupported export replaced file");
    const auto invalid=dir/"invalid.sb";WriteXmlFileBytes(invalid,"<WPE64_BackUp><SystemConfig><DefaultLanguage>ja-JP</DefaultLanguage></SystemConfig><ProxyAccountList /></WPE64_BackUp>");
    Throws([&]{call("importBackup",{{"_filePath",Path(invalid)}});});call("exportBackup",exportArgs);Check(read(out)==read(backup),"Unsupported section partially changed DB");
    WriteXmlFileBytes(invalid,"<WPE64_BackUp><SystemConfig><DefaultLanguage>ja-JP</DefaultLanguage></SystemConfig><SendList><Send><Name>bad</Name><LoopCNT>not-number</LoopCNT></Send></SendList></WPE64_BackUp>");
    Throws([&]{call("importBackup",{{"_filePath",Path(invalid)}});});call("exportBackup",exportArgs);Check(read(out)==read(backup),"Invalid row partially changed DB");
    {Database db(dir/"data.sqlite");db.Execute("CREATE TRIGGER test_failure BEFORE INSERT ON WareHouse BEGIN SELECT RAISE(ABORT,'test-failure'); END");
        WriteXmlFileBytes(invalid,"<WPE64_BackUp><SystemConfig><DefaultLanguage>ja-JP</DefaultLanguage></SystemConfig><FilterList /><WareHouseList><WareHouse><Name>triggers failure</Name></WareHouse></WareHouseList></WPE64_BackUp>");
        Throws([&]{call("importBackup",{{"_filePath",Path(invalid)}});});db.Execute("DROP TRIGGER test_failure");
        call("exportBackup",exportArgs);Check(read(out)==read(backup),"Mid-transaction failure changed live mirror");
        Check(db.Query("SELECT DefaultLanguage FROM SystemConfig")[0]["DefaultLanguage"]=="en-US"&&db.Query("SELECT * FROM Filter").size()==3,"Mid-transaction failure changed persisted data");}
    WriteXmlFileBytes(invalid,"<WPE64_BackUp><RobotList /></WPE64_BackUp>");call("importBackup",{{"_filePath",Path(invalid)}});call("exportBackup",exportArgs);
    const auto root=ParseXml(read(out));Check(!root.Get("RobotList")&&root.Get("SendList"),"Present empty section clears; absent section preserves");
    call("importBackup",{{"_filePath",Path(backup)}});exportArgs["_password"]="密码中文测试";call("exportBackup",exportArgs);Check(read(out)==read(golden/"sb-1.encrypted"),"Native encrypted backup differs");
    Check(call("importBackup").size()==4,"Cancelled backup import must return preferences");
    {auto xml=read(backup);const auto open=xml.find("<WPE64_BackUp>");xml.replace(open,14,"<x:WPE64_BackUp xmlns:x=\"urn:test\">");const auto close=xml.find("</WPE64_BackUp>");xml.replace(close,15,"</x:WPE64_BackUp>");
        WriteXmlFileBytes(invalid,xml);call("importBackup",{{"_filePath",Path(invalid)}});auto plain=parts;plain["_filePath"]=Path(dir/"root.sb");call("exportBackup",plain);Check(read(dir/"root.sb")==read(backup),"Original backup root LocalName behavior");}
    auto sid="22222222-2222-2222-2222-222222222222";call("openSendEdit",{{"id",sid}});const auto sc=dir/"encrypted.sc";
    call("exportSendCollection",{{"_filePath",Path(sc)},{"_password","密码中文测试"}});Check(ReadEditorXmlContent(CryptXml(read(sc),"密码中文测试",false),true).size()==2,"Encrypted standalone send export");
    for(const auto& file:fs::directory_iterator(dir))Check(!file.path().filename().wstring().starts_with(L".wpe-export-"),"Leaked plaintext or temporary export");
    {
        using namespace std::chrono_literals;DataWorker worker(dir/"cancel.db");int replies=0;Json plan;std::string error;
        auto pump=[&](int n){const auto until=std::chrono::steady_clock::now()+5s;while(replies<n&&std::chrono::steady_clock::now()<until){worker.Drain([](std::string,Json){});std::this_thread::sleep_for(2ms);}Check(replies==n,"Import cancellation worker timed out");};
        worker.Submit("__prepareImport",{{"method","importFilters"},{"args",{{"_filePath",Path(fixtures/"input.fp")}}}},[&](Json p,std::string e){plan=std::move(p);error=std::move(e);++replies;});pump(1);Check(error.empty()&&plan["encrypted"]==false,"Prepare plain import");
        Database db(dir/"cancel.db");db.Execute("BEGIN IMMEDIATE");worker.Submit("setLanguage",{{"language","zh-CN"}},[&](Json,std::string){++replies;});std::this_thread::sleep_for(30ms);
        bool applied=false;worker.Submit("__applyImport",{{"token",plan["token"]}},[&](Json,std::string e){applied=e.empty();++replies;});worker.ForgetImportPlan(plan["token"].get<std::string>());db.Execute("ROLLBACK");pump(3);
        Check(!applied&&db.Query("SELECT * FROM Filter").empty(),"Cancelled queued plain import mutated database");
    }
    std::cout<<"PASS: "<<checks<<" configuration and original AES checks; "<<dir.string()<<'\n';return 0;
}catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<'\n';return 1;}}
