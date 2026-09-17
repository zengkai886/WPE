#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include "data_service.h"
#include "data_schema.h"
#include "data_l10n.h"
#include <algorithm>
#include <charconv>
#include <iomanip>
#include <regex>
#include <sstream>

namespace wpe::shell {
namespace {
const std::array<std::string,4> tables={"Filter","Send","Robot","WareHouse"};
const std::array<std::string,4> children={"","SendCollection","RobotInstruction","WareHouseData"};
std::string S(const Json& j,const char* key,std::string fallback={}){
    const auto it=j.find(key);if(it==j.end()||it->is_null())return fallback;
    return it->is_string()?it->get<std::string>():it->dump();
}
int N(const Json& j,const char* key,int fallback=0){const auto it=j.find(key);return it==j.end()||it->is_null()?fallback:it->get<int>();}
bool B(const Json& j,const char* key,bool fallback=false){const auto it=j.find(key);return it==j.end()||it->is_null()?fallback:it->is_boolean()?it->get<bool>():it->get<int>()!=0;}
std::string Upper(std::string s){for(auto& c:s)if(c>='a'&&c<='z')c=static_cast<char>(c-32);return s;}
std::string Trim(const std::string& s){
    if(s.empty())return {};
    if(s.size()>static_cast<std::size_t>(INT_MAX))throw std::length_error("Text exceeds Windows conversion limit");
    const auto size=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0);
    if(!size)throw std::invalid_argument("Invalid UTF-8 text");
    std::wstring text(static_cast<std::size_t>(size),L'\0');MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),text.data(),size);
    // .NET Framework 4.8 Char.IsWhiteSpace, not the C locale's ASCII isspace.
    auto space=[](wchar_t c){return (c>=9&&c<=13)||c==0x20||c==0x85||c==0xA0||c==0x1680||
        (c>=0x2000&&c<=0x200A)||c==0x2028||c==0x2029||c==0x202F||c==0x205F||c==0x3000;};
    std::size_t from=0,to=text.size();while(from<to&&space(text[from]))++from;while(to>from&&space(text[to-1]))--to;
    if(from==to)return {};
    const auto length=static_cast<int>(to-from);const auto bytes=WideCharToMultiByte(CP_UTF8,0,text.data()+from,length,nullptr,0,nullptr,nullptr);
    std::string result(static_cast<std::size_t>(bytes),'\0');WideCharToMultiByte(CP_UTF8,0,text.data()+from,length,result.data(),bytes,nullptr,nullptr);return result;
}
std::string Guid(){GUID guid{};if(FAILED(CoCreateGuid(&guid)))throw std::runtime_error("GUID generation failed");wchar_t text[40]{};StringFromGUID2(guid,text,40);std::string out;for(int i=1;i<37;++i)out+=static_cast<char>(text[i]);return Upper(out);}
const std::string zero_guid="00000000-0000-0000-0000-000000000000";
std::string NormalGuid(const std::string& s){
    if(std::regex_match(s,std::regex("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")))return Upper(s);
    return zero_guid;
}
Json Good(){return {{"ok",true}};}
Json Bad(const std::string& message){return {{"ok",false},{"error",message}};}
std::vector<std::string> Split(const std::string& s,char separator){std::vector<std::string> result;std::istringstream input(s);std::string item;while(std::getline(input,item,separator))result.push_back(item);return result;}
bool Integer(const std::string& s,int& number){const auto t=Trim(s);auto [end,ec]=std::from_chars(t.data(),t.data()+t.size(),number);return !t.empty()&&ec==std::errc{}&&end==t.data()+t.size();}
int Mask(const std::string& s){int value=0,i=0;for(const auto& part:Split(s,':')){if(i>=12)break;if(part=="1")value|=1<<i;++i;}return value;}
std::string Function(int mask){std::string s;for(int i=0;i<12;++i){if(i)s+=':';s+=(mask&(1<<i))?'1':'0';}return s;}
std::string Color(const Json& j,const char* key){std::ostringstream out;out<<'#'<<std::uppercase<<std::hex<<std::setw(6)<<std::setfill('0')<<(static_cast<std::uint32_t>(N(j,key))&0xFFFFFF);return out.str();}
std::string Hex(const Json& binary,std::size_t limit=60){
    if(!binary.is_binary())return {};const auto& b=binary.get_binary();const char digits[]="0123456789ABCDEF";std::string out;
    for(std::size_t i=0;i<std::min(b.size(),limit);++i){if(i)out+=' ';out+=digits[b[i]>>4];out+=digits[b[i]&15];}if(b.size()>limit)out+=" ...";return out;
}
std::size_t Size(const Json& binary){return binary.is_binary()?binary.get_binary().size():0;}
Json RuntimeChildren(Json rows,int list,std::uint64_t& packet_id){
    for(auto& child:rows)child["_id"]=list==11?Guid():std::to_string(++packet_id);return rows;
}
}

DataService::DataService(const std::filesystem::path& path,Emit emit):db_(path),emit_(std::move(emit)){
    for(auto& list:lists_)list=Json::array();
    db_.Transaction([&]{db_.Execute(data_schema);});
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
    for(int list=8;list<=11;++list){
        auto rows=db_.Query("SELECT * FROM "+tables[list-8]+" ORDER BY rowid");
        for(auto& row:rows){
            row["GUID"]=Upper(S(row,"GUID"));
            if(list>8)row["_children"]=RuntimeChildren(db_.Query("SELECT * FROM "+children[list-8]+" WHERE GUID=? COLLATE NOCASE ORDER BY rowid",Json::array({row["GUID"]})),list,packet_id_);
        }lists_[list]=std::move(rows);
    }
}
std::vector<std::string> DataService::Methods(){return {
    "getPrefs","setAppearance","setLanguage","saveActionColor","getSystemSetting","saveSystemSetting","getLogSetting","saveLogSetting",
    "enterProxyMode","enterInjectMode","getStats","getClientConnections","clearLogs","getCountryTable",
    "getFilterExecute","getFilterEdit","saveFilterEdit","getExecuteTargets","addFilter","setFilterEnable","setAllFilterEnable","resetFilterCount","filterListAction","clearFilters",
    "getSendMeta","addSend","setSendEnable","setAllSendEnable","resetSendCount","sendListAction","clearSends","openSendEdit","closeSendEdit","getSendCollection","saveSendEdit",
    "getRobotMeta","addRobot","setRobotEnable","setAllRobotEnable","resetRobotCount","robotListAction","clearRobots",
    "addWareHouse","wareHouseListAction","clearWareHouses","openWareHouseEdit","getStoreRows","getStorePreviews","copyStoresHex","saveWareHouseName"
};}
bool DataService::NeedsConfirmation(const std::string& method,const Json& args){
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
void DataService::SaveConfig(const Json& changes){
    if(changes.empty())return;
    auto next=config_;for(auto it=changes.begin();it!=changes.end();++it){if(!next.contains(it.key()))throw std::invalid_argument("Unknown setting");next[it.key()]=it.value();}
    // Preserve every untouched upstream column. Commit before changing the live mirror.
    db_.Transaction([&]{db_.Replace("SystemConfig",Json::array({next}));});config_=std::move(next);
}
Json DataService::NewRow(int list){
    Json row{{"GUID",Guid()},{"Name",""}};
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
void DataService::SaveList(int list,const Json& rows){
    Json parents=rows,child=Json::array();
    for(auto& row:parents){
        if(row.contains("_children")){
            for(auto item:row["_children"]){item.erase("_id");item["GUID"]=row["GUID"];child.push_back(std::move(item));}
            row.erase("_children");
        }
    }
    db_.Transaction([&]{
        if(list>8)db_.Execute("DELETE FROM "+children[list-8]);
        db_.Replace(tables[list-8],parents);
        if(list>8)db_.Replace(children[list-8],child);
    });
    lists_[list]=rows;Publish(list);
}
Json DataService::Rows(int list)const{
    Json result=Json::array();
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
            row["GUID"]=Guid();if(list<11)row["IsEnable"]=false;
            auto name=Text("CopyName","{0} - 副本");const auto pos=name.find("{0}");if(pos!=name.npos)name.replace(pos,3,S(row,"Name"));row["Name"]=name;
            if(list>8)row["_children"]=RuntimeChildren(row["_children"],list,packet_id_);rows.push_back(std::move(row));continue;
        }
        if((action==1&&index==0)||(action==2&&index+1==rows.size()))continue;
        rows.erase(it);if(action==6)continue;
        const auto target=action==0?0:action==1?index-1:action==2?index+1:rows.size();rows.insert(rows.begin()+static_cast<Json::difference_type>(target),std::move(row));
    }
    const auto delta=static_cast<std::int64_t>(rows.size())-before;SaveList(list,rows);return {{"ok",true},{"delta",delta}};
}

Json DataService::Call(const std::string& method,const Json& args){
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
    if(method=="getLogSetting")return {{"autoClear",B(config_,"LogList_AutoClear",true)},{"autoClearValue",N(config_,"LogList_AutoClear_Value",5000)}};
    if(method=="saveLogSetting"){
        Json changes=Json::object();if(args.contains("autoClear"))changes["LogList_AutoClear"]=B(args,"autoClear");
        if(args.contains("autoClearValue")){const int v=N(args,"autoClearValue");if(v<100||v>500000)return Bad(Text("ListSettingsForm.Range","保留条数需在 100 ~ 500000 之间"));changes["LogList_AutoClear_Value"]=v;}
        SaveConfig(changes);return Good();
    }
    if(method=="getFilterExecute")return {{"mode",N(config_,"FilterExecute",1)}};
    if(method=="getSendMeta")return {{"systemSocket",0},{"running",false},{"listExecute",N(config_,"ListExecute",1)}};
    if(method=="getRobotMeta")return {{"running",false},{"listExecute",N(config_,"ListExecute",1)}};
    if(method=="enterProxyMode"){PublishAll();return Good();}
    if(method=="enterInjectMode")return {{"ok",true},{"lastInject",nullptr}};
    if(method=="getClientConnections")return {{"rows",Json::array()}};
    if(method=="getStats")return {{"queue",0},{"list",0},{"total",0},{"proxyRunning",false},{"tcpReq",0},{"tcpResp",0},{"udpReq",0},{"udpResp",0},{"httpReq",0},{"httpResp",0},{"filterExecute",0},{"filterProxy",0},{"tcpConn",0},{"udpConn",0},{"onlineInfo",""},{"totalRequest",0},{"totalResponse",0},{"speedUp",0},{"speedDown",0}};
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
        auto row=Find(9,S(args,"id"));send_edit_=row?*row:Json{};
        if(!row)return {{"Id",""},{"Name",""},{"UseSystemSocket",false},{"LoopCount",0},{"LoopInterval",0},{"Notes",""},{"SystemSocket",0}};
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
    throw std::runtime_error("尚未实现的方法: "+method);
}
}
