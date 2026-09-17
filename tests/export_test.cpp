#include "shell/data_service.h"
#include "shell/editor_xml.h"
#include <fstream>
#include <chrono>
#include <iostream>
#define NOMINMAX
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
using namespace wpe::shell;namespace fs=std::filesystem;
namespace {
int checks=0;void Check(bool value,const char* message){++checks;if(!value)throw std::runtime_error(message);}
std::string Path(const fs::path& p){auto s=p.u8string();return {s.begin(),s.end()};}
std::string Read(const fs::path& p){std::ifstream f(p,std::ios::binary);if(!f)throw std::runtime_error("Cannot read test file");return {std::istreambuf_iterator<char>(f),{}};}
template<class F>void Throws(F f){bool threw=false;try{f();}catch(const std::exception&){threw=true;}Check(threw,"Expected write failure");}
std::wstring Dacl(const fs::path& p){
    PSECURITY_DESCRIPTOR sd=nullptr;Check(GetNamedSecurityInfoW(p.c_str(),SE_FILE_OBJECT,DACL_SECURITY_INFORMATION,nullptr,nullptr,nullptr,nullptr,&sd)==ERROR_SUCCESS,"Read DACL");
    SECURITY_DESCRIPTOR_CONTROL control{};DWORD revision=0;const auto got=GetSecurityDescriptorControl(sd,&control,&revision);
    LPWSTR text=nullptr;const auto ok=ConvertSecurityDescriptorToStringSecurityDescriptorW(sd,SDDL_REVISION_1,DACL_SECURITY_INFORMATION,&text,nullptr);LocalFree(sd);Check(got&&ok,"Format DACL");
    std::wstring result(text);LocalFree(text);
    // Windows may add the AI bookkeeping flag without changing access. Compare
    // protection and every ACE, not that non-security formatting difference.
    const auto start=result.find(L'(');return std::wstring((control&SE_DACL_PROTECTED)?L"P:":L"U:")+(start==result.npos?result:result.substr(start));
}
void Restrict(const fs::path& p){
    HANDLE token=nullptr;Check(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token)!=FALSE,"Open test token");DWORD bytes=0;GetTokenInformation(token,TokenUser,nullptr,0,&bytes);std::vector<std::uint8_t> user(bytes);
    const auto got=GetTokenInformation(token,TokenUser,user.data(),bytes,&bytes);CloseHandle(token);Check(got!=FALSE,"Read test SID");
    LPWSTR sid=nullptr;Check(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid,&sid)!=FALSE,"Format test SID");const auto sddl=L"D:P(A;;FA;;;"+std::wstring(sid)+L")";LocalFree(sid);
    PSECURITY_DESCRIPTOR sd=nullptr;Check(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&sd,nullptr)!=FALSE,"Build test DACL");
    const auto ok=SetFileSecurityW(p.c_str(),DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,sd);LocalFree(sd);Check(ok!=FALSE,"Apply test DACL");
}
}
int main(int argc,char** argv){try{
    if(argc!=2)throw std::runtime_error("Fixtures directory required");const fs::path fixtures=fs::path(argv[1]);
    const auto dir=fs::current_path()/"export-test"/std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());fs::create_directories(dir);
    const auto sc=dir/L"中文发送.sc",whs=dir/L"中文仓储.whs";
    for(const bool send:{true,false}){const auto rows=ReadEditorXml(fixtures/(send?"editor-send.sc":"editor-stores.whs"),send);const auto file=send?sc:whs;
        WriteEditorXml(file,rows,send);Check(Read(file)==Read(fixtures/(send?"export-original.sc":"export-original.whs")),"Export differs from original C# bytes");Check(ReadEditorXml(file,send)==rows,"Import/export data changed");
        auto bad=rows;bad[0]["Buffer"]=nullptr;const auto original=Read(file);Throws([&]{WriteEditorXml(file,bad,send);}); // null buffer is intentionally rejected below
        Check(Read(file)==original,"Failed export destroyed old file");
    }
    for(const bool send:{true,false}){const auto file=dir/(send?"edge.sc":"edge.whs");WriteEditorXml(file,ReadEditorXml(fixtures/"export-edge"/(send?"editor-send.sc":"editor-stores.whs"),send),send);Check(Read(file)==Read(fixtures/"export-edge"/(send?"export-original.sc":"export-original.whs")),"XML edge bytes differ from original");}
    Restrict(sc);const auto acl=Dacl(sc);WriteEditorXml(sc,ReadEditorXml(fixtures/"editor-send.sc",true),true);Check(Dacl(sc)==acl,"Replacement widened original file permissions");
    std::vector<Json> events;DataService service(dir/"db.sqlite",[&](std::string name,Json data){events.push_back({{"name",name},{"data",data}});});
    auto call=[&](const std::string& method,Json args=Json::object()){return service.Call(method,args);};
    auto sid=call("addSend")["id"],wid=call("addWareHouse")["id"];
    call("openSendEdit",{{"id",sid}});call("importSendCollection",{{"_filePath",Path(fixtures/"editor-send.sc")}});
    auto before=call("getSendCollection");auto plan=call("__prepareEditorExport",{{"method","exportSendCollection"},{"args",Json::object()}});
    const auto id=before["rows"][0]["Id"];call("savePacketEdit",{{"list","send"},{"id",id},{"buffer","qqs="},{"socket",99}});
    call("sendCollectionAction",{{"action",0},{"ids",Json::array({before["rows"][2]["Id"]})}});
    events.clear();call("__writeEditorExport",{{"plan",plan},{"_filePath",Path(sc)}});auto exported=ReadEditorXml(sc,true);
    Check(exported.size()==3&&exported[0]["Socket"]==99&&exported[0]["Buffer"]==Json::binary({0xaa,0xab}),"Export must retain membership/order but share edited PacketInfo fields");
    Check(events.size()==1&&events[0]["name"]=="notify"&&events[0]["data"]["level"]==2,"Export notification missing or feed mutated");
    Throws([&]{call("__writeEditorExport",{{"plan",plan},{"_filePath",Path(sc)}});});
    call("sendCollectionAction",{{"action",0},{"ids",Json::array({id})}});
    call("exportSendCollection",{{"_filePath",Path(sc)}});Check(ReadEditorXml(sc,true)[0]["Socket"]==99,"Export ignored current unsaved draft");
    auto after=call("getSendCollection");call("exportSendCollection",{{"_filePath",""}});Check(call("getSendCollection")==after,"Cancel export changed draft");
    std::vector<Json> plans;for(int i=0;i<16;++i)plans.push_back(call("__prepareEditorExport",{{"method","exportSendCollection"},{"args",Json::object()}}));
    Throws([&]{call("__prepareEditorExport",{{"method","exportSendCollection"},{"args",Json::object()}});});
    for(const auto& pending:plans)call("__discardEditorExport",{{"token",pending["token"]}});
    Throws([&]{call("__writeEditorExport",{{"plan",plans[0]},{"_filePath",Path(sc)}});});
    plan=call("__prepareEditorExport",{{"method","exportSendCollection"},{"args",Json::object()}});call("clearSendCollection");
    call("__writeEditorExport",{{"plan",plan},{"_filePath",Path(sc)}});Check(ReadEditorXml(sc,true).size()==3,"Clearing draft changed pending export membership");
    plan=call("__prepareEditorExport",{{"method","exportSendCollection"},{"args",Json::object()}});Check(plan["rowCount"]==0&&!plan.contains("token"),"Empty export retained resources");
    call("storesCommand",{{"wid",wid},{"action",8},{"_filePath",Path(fixtures/"editor-stores.whs")}});auto rows=call("getStoreRows",{{"wid",wid}})["rows"];
    call("storesAction",{{"wid",wid},{"action",5},{"ids",Json::array({rows[1]["Id"],rows[0]["Id"],rows[0]["Id"]})},{"_filePath",Path(whs)}});
    Check(ReadEditorXml(whs,false).size()==2,"Selected export duplicates or omitted entries");Check(ReadEditorXml(whs,false)[0]["Buffer"]==ReadEditorXml(fixtures/"editor-stores.whs",false)[0]["Buffer"],"Selection not in original table order");
    const auto contents=Read(whs);call("storesAction",{{"wid",wid},{"action",5},{"ids",Json::array({"missing"})},{"_filePath",Path(whs)}});Check(Read(whs)==contents,"Stale selection overwrote file");
    call("storesCommand",{{"wid",wid},{"action",5},{"_filePath",Path(whs)}});Check(Read(whs)==Read(fixtures/"export-original.whs"),"All store export differs");
    HANDLE held=CreateFileW(whs.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);Check(held!=INVALID_HANDLE_VALUE,"Cannot lock fixture");
    bool denied=false;try{call("storesCommand",{{"wid",wid},{"action",5},{"_filePath",Path(whs)}});}catch(const std::exception&){denied=true;}CloseHandle(held);
    Check(denied&&Read(whs)==Read(fixtures/"export-original.whs"),"Locked destination changed");
    for(const auto& f:fs::directory_iterator(dir))Check(!f.path().filename().wstring().starts_with(L".wpe-export-"),"Temporary export leaked");
    Check(DataService::NeedsSaveFile("storesAction",{{"action",5}})&&!DataService::NeedsSaveFile("storesAction",{{"action",6}}),"save chooser routing");
    // Leave canonical native exports for an independent original-loader check.
    WriteEditorXml(dir/"native.sc",ReadEditorXml(fixtures/"editor-send.sc",true),true);WriteEditorXml(dir/"native.whs",ReadEditorXml(fixtures/"editor-stores.whs",false),false);
    std::cout<<"PASS: "<<checks<<" export checks; original byte golden, snapshot, selected/all, cancel, replacement failure; "<<dir.string()<<'\n';return 0;
}catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<'\n';return 1;}}
