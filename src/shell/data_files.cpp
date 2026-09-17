#include "data_service.h"
#include "data_util.h"
#include "editor_xml.h"
#include "config_xml.h"
#include "xml_crypto.h"
namespace wpe::shell {
using namespace data_detail;
namespace {
const std::array<std::string,4> kinds={"fp","sp","rp","whp"};
const std::array<std::string,4> imports={"importFilters","importSends","importRobots","importWareHouses"};
const std::array<std::string,4> exports={"exportFilters","exportSends","exportRobots","exportWareHouses"};
const std::array<std::string,4> actions={"filterListAction","sendListAction","robotListAction","wareHouseListAction"};
const std::array<std::string,4> parts={"filterList","sendList","robotList","wareHouse"};
std::filesystem::path Path(const std::string& p){return std::filesystem::path(std::u8string(p.begin(),p.end()));}
int List(const std::string& kind){const auto i=std::find(kinds.begin(),kinds.end(),kind);return i==kinds.end()?-1:8+static_cast<int>(i-kinds.begin());}
Json BackupResult(const Json& p){return {{"language",p["language"]},{"isDark",p["isDark"]},{"themeMode",p["themeMode"]},{"scanLine",p["scanLine"]}};}
void CheckBackupParts(const Json& args){for(const auto* key:{"proxyMapping","wpcServer","wpcNotice"})if(B(args,key))throw std::runtime_error("尚未实现备份分组："+std::string(key)+"；已取消整次导出，不会生成缺项备份");}
Json ExportBatchRows(const Json& args){
    Json rows=Json::array();const auto it=args.find("rows");if(it==args.end()||!it->is_array())return rows;
    for(const auto& source:*it){if(!source.is_object())continue;const auto user=S(source,"UserName"),password=S(source,"Password");if(!user.empty()&&!password.empty())rows.push_back({{"UserName",Trim(user)},{"Password",Trim(password)}});}return rows;
}
std::string ExportBatchExpiry(const Json& args){if(const auto value=DateTimeText(S(args,"expiryTime")))return *value;const auto value=AddDateTimeYears(LocalDateTime(),100);if(!value)throw std::runtime_error("批量账号过期时间超出范围");return *value;}
std::string Today(){SYSTEMTIME now{};GetLocalTime(&now);char value[11]{};sprintf_s(value,"%04u-%02u-%02u",now.wYear,now.wMonth,now.wDay);return value;}
}
std::string DataService::FileKind(const std::string& method,const Json& args){
    if(method=="ipRuleAction")return B(args,"black")?"bl":"wl";
    if(method=="importAutoStores"||method=="exportAutoStores"||method=="autoStoresAction")return "pas";
    if(method=="exportBatchAccounts")return "xls";
    if(method=="importAccounts"||method=="exportAccounts"||method=="exportSelectedAccounts")return "pa";
    for(std::size_t i=0;i<kinds.size();++i)if(method==imports[i]||method==exports[i]||(method==actions[i]&&N(args,"action",-1)==5))return kinds[i];
    if(method=="importBackup"||method=="exportBackup")return "sb";
    if(method=="importSendCollection"||method=="exportSendCollection"||method=="sendCollectionAction")return "sc";return "whs";
}
bool DataService::NeedsOpenFile(const std::string& method,const Json& args){return method=="importAccounts"||method=="importAutoStores"||std::find(imports.begin(),imports.end(),method)!=imports.end()||method=="importBackup"||method=="importSendCollection"||(method=="storesCommand"&&N(args,"action",-1)==8)||(method=="ipRuleAction"&&N(args,"action",-1)==8)||(method=="autoStoresAction"&&N(args,"action",-1)==8);}
bool DataService::NeedsSaveFile(const std::string& method,const Json& args){
    return method=="exportAccounts"||method=="exportSelectedAccounts"||method=="exportBatchAccounts"||method=="exportAutoStores"||std::find(exports.begin(),exports.end(),method)!=exports.end()||method=="exportBackup"||method=="exportSendCollection"||((std::find(actions.begin(),actions.end(),method)!=actions.end()||method=="sendCollectionAction"||method=="storesAction"||method=="storesCommand"||method=="ipRuleAction"||method=="autoStoresAction")&&N(args,"action",-1)==5);
}
Json DataService::FileInfo(const std::string& kind,bool save)const{
    const auto prefix=save?"Export":"Import";std::string key,name;
    if(kind=="sc"){key=std::string(prefix)+"SendCollection";name="发送集";}else if(kind=="whs"){key=std::string(prefix)+"Stores";name="仓储数据";}
    else if(kind=="sb"){key="BackUpSettingsForm."+std::string(prefix);name="系统备份";}
    else if(kind=="pa"){key=std::string(prefix)+"ProxyAccountList";name="代理账号列表";}
    else if(kind=="xls"){key="ExcelFile";name="Excel";}else if(kind=="pas"){key=std::string("AutoStores.")+(save?"Export":"Import");name="自动入库";}
    else if(kind=="wl"||kind=="bl"){const bool black=kind=="bl";key=std::string("FireWallSetting.")+(black?"BlackListFile":"WhiteListFile")+'.'+prefix;name=black?"黑名单":"白名单";}
    else if(kind=="whp"){key="WareHouseList."+std::string(prefix);name="仓库列表";}
    else{const int list=List(kind);if(list<8)throw std::invalid_argument("未知配置文件类型");key=std::string(prefix)+tables[list-8]+"List";name=list==8?"滤镜列表":list==9?"发送列表":"机器人列表";}
    const auto fallback=std::string(save?"导出":"导入")+name;
    auto successKey=kind=="xls"?"ExportToExcel.Success":key+".Success";if(kind=="sc"&&!save)successKey="InjectModeForm.ImportSendCollection.Success";
    Json info{{"kind",kind},{"title",Text(key,fallback)},{"success",Text(successKey,kind=="xls"?"导出到Excel成功":fallback+"成功")}};if(kind=="xls")info.update({{"plain",true},{"defaultName",Today()}});return info;
}
Json DataService::PrepareParentExport(const std::string& method,const Json& args){
    const auto kind=FileKind(method,args);auto plan=FileInfo(kind,true);plan["rows"]=Json::array();plan["result"]=Good();plan["send"]=false;
    if(kind=="sb"){
        CheckBackupParts(args);bool selected=B(args,"systemConfig")||B(args,"proxySet")||B(args,"proxyAccount")||B(args,"injectSet")||B(args,"whiteList")||B(args,"blackList")||B(args,"autoStores");for(const auto& part:parts)selected=selected||B(args,part.c_str());
        if(!selected){emit_("toast",{{"level",3},{"text",Text("BackUpSettingsForm.NothingSelected","请先勾选要备份的内容")}});return plan;}
        plan["parts"]=args;plan["rows"].push_back(true);return plan; // Backup reads live state after the password dialog, like upstream.
    }
    if(kind=="xls"){plan["rows"]=ExportBatchRows(args);plan["expiryTime"]=ExportBatchExpiry(args);return plan;}
    if(kind=="pa"){std::set<std::string> ids;if(method=="exportSelectedAccounts")for(const auto& id:args.value("ids",Json::array()))if(id.is_string())ids.insert(Upper(id.get<std::string>()));for(const auto& row:lists_[5])if(method!="exportSelectedAccounts"||ids.contains(Upper(S(row,"GUID"))))plan["rows"].push_back(row);return plan;}
    if(kind=="pas"){plan["rows"]=lists_[12];return plan;}
    if(kind=="wl"||kind=="bl"){plan["rows"]=lists_[kind=="bl"?16:15];return plan;}
    const auto list=List(kind);const bool selected=method==actions[list-8];std::set<std::string> ids;
    if(selected){for(const auto& id:args.value("ids",Json::array()))if(id.is_string())ids.insert(Upper(id.get<std::string>()));plan["result"]={{"ok",!ids.empty()},{"delta",0}};}
    for(const auto& row:lists_[list])if(!selected||ids.contains(S(row,"GUID")))plan["rows"].push_back(row);return plan;
}
void DataService::RefreshExportAliases(int list){
    for(auto& [token,plan]:export_plans_)if(List(S(plan,"kind"))==list)for(auto& row:plan["rows"])if(auto live=Find(list,S(row,"GUID"));live&&S(*live,"_objectId")==S(row,"_objectId"))row=*live;
}
std::optional<Json> DataService::CallFiles(const std::string& method,const Json& args){
    if(method=="__fileInfo")return FileInfo(S(args,"kind"),B(args,"save"));
    if(method=="__discardImport"){import_plans_.erase(S(args,"token"));return Good();}
    if(method=="__prepareImport"){
        if(import_plans_.size()>=16)throw std::runtime_error("等待导入的文件过多");const auto m=S(args,"method");const auto a=args.at("args");auto bytes=ReadXmlFileBytes(Path(S(a,"_filePath")));bool encrypted=false;
        try{(void)ParseXml(bytes);}catch(const std::runtime_error&){encrypted=true;}
        auto info=FileInfo(FileKind(m,a),false);const auto token=Guid();import_plans_.emplace(token,ImportPlan{m,std::move(bytes),a});info["token"]=token;info["encrypted"]=encrypted;return info;
    }
    if(method=="__verifyImportPassword"){
        const auto it=import_plans_.find(S(args,"token"));if(it==import_plans_.end()||S(args,"password").empty())return Json{{"ok",false}};
        try{(void)ParseXml(CryptXml(it->second.bytes,S(args,"password"),false));return Json{{"ok",true}};}catch(const std::exception&){return Json{{"ok",false}};}
    }
    if(method=="__applyImport"){
        auto item=import_plans_.extract(S(args,"token"));if(item.empty())throw std::runtime_error("导入已取消或完成");auto& plan=item.mapped();
        if(!S(args,"password").empty())plan.bytes=CryptXml(plan.bytes,S(args,"password"),false);return ApplyImport(plan.method,plan.args,plan.bytes);
    }
    if(NeedsOpenFile(method,args)){
        const auto path=S(args,"_filePath");if(path.empty())return method=="importBackup"?BackupResult(Prefs()):Good();
        auto bytes=ReadXmlFileBytes(Path(path));if(!S(args,"_password").empty())bytes=CryptXml(bytes,S(args,"_password"),false);return ApplyImport(method,args,bytes);
    }return std::nullopt;
}
Json DataService::ApplyImport(const std::string& method,const Json& args,std::string_view bytes){
    const auto kind=FileKind(method,args);auto info=FileInfo(kind,false);
    if(kind=="sc"){
        if(send_edit_.is_null())return Good();auto imported=RuntimeChildren(ReadEditorXmlContent(bytes,true),9,packet_id_);auto next=send_edit_;for(auto& child:imported)next["_children"].push_back(std::move(child));send_edit_=std::move(next);
    }else if(kind=="whs"){
        const auto live=Find(11,S(args,"wid"));if(!live)return Good();auto rows=lists_[11];auto& row=*std::find_if(rows.begin(),rows.end(),[&](const Json& r){return r["GUID"]==(*live)["GUID"];});
        for(auto& child:RuntimeChildren(ReadEditorXmlContent(bytes,false),11,packet_id_))row["_children"].push_back(std::move(child));TrimStores(row["_children"]);SaveList(11,rows);
    }else{
        const auto root=ParseXml(bytes);
        if(kind=="sb"){
            if(root.LocalName()!="WPE64_BackUp")throw std::runtime_error("不是原版系统备份文件");
            for(const auto& n:root.nodes)if(n.name!="SystemConfig"&&n.name!="ProxyMode"&&n.name!="ProxyAccountList"&&n.name!="InjectMode"&&n.name!="WhiteList"&&n.name!="BlackList"&&n.name!="FilterList"&&n.name!="SendList"&&n.name!="RobotList"&&n.name!="WareHouseList"&&n.name!="AutoStores")throw std::runtime_error("尚未实现备份分组："+n.name+"；已取消整次导入，未修改数据库");
            auto config=config_,proxy=proxy_config_,inject=inject_config_;if(const auto* node=root.Get("SystemConfig"))config=ParseSystemConfig(*node,config);
            if(const auto* node=root.Get("ProxyMode"))proxy=ParseProxyMode(*node,proxy);if(const auto* node=root.Get("InjectMode"))inject=ParseInjectMode(*node,inject);std::map<int,Json> changed;
            for(int list=8;list<=11;++list){const auto name=list==11?"WareHouseList":tables[list-8]+"List";if(const auto* node=root.Get(name))changed[list]=ParseParentList(list,*node,{},packet_id_,config);}
            if(const auto* node=root.Get("ProxyAccountList"))changed[5]=ParseAccountList(*node,Json::array());
            if(const auto* node=root.Get("AutoStores"))changed[12]=ParseAutoStores(*node,Json::array(),false);
            if(const auto* node=root.Get("WhiteList"))changed[15]=ParseIpRuleList(false,*node,Json::array());if(const auto* node=root.Get("BlackList"))changed[16]=ParseIpRuleList(true,*node,Json::array());
            db_.Transaction([&]{if(root.Get("SystemConfig"))db_.Replace("SystemConfig",Json::array({config}));if(root.Get("ProxyMode"))db_.Replace("ProxyMode",Json::array({proxy}));if(root.Get("InjectMode"))db_.Replace("InjectMode",Json::array({inject}));for(const auto& [list,rows]:changed)if(list==5)PersistAccounts(rows);else if(list==12)PersistAutoStores(rows);else if(list>=15)PersistIpRules(list,rows);else PersistList(list,rows);});
            config_=std::move(config);proxy_config_=std::move(proxy);inject_config_=std::move(inject);for(auto& [list,rows]:changed)lists_[list]=std::move(rows);PublishAll();
        }else if(kind=="pas"){
            auto rows=ParseAutoStores(root,lists_[12],true);db_.Transaction([&]{PersistAutoStores(rows);});lists_[12]=std::move(rows);Publish(12);
        }else if(kind=="wl"||kind=="bl"){
            const int list=kind=="bl"?16:15;SaveIpRules(list,ParseIpRuleList(list==16,root,lists_[list]));
        }else if(kind=="pa"){
            SaveAccounts(ParseAccountList(root,lists_[5]));
        }else{
            const auto list=List(kind);std::set<std::string> ids;for(const auto& row:lists_[list])ids.insert(S(row,"GUID"));auto imported=ParseParentList(list,root,ids,packet_id_,config_);auto rows=lists_[list];for(auto& row:imported)rows.push_back(std::move(row));SaveList(list,rows);
        }
    }
    emit_("notify",{{"level",2},{"title",info.at("success")},{"content",S(args,"_filePath")}});return method=="importBackup"?BackupResult(Prefs()):Good();
}
}
