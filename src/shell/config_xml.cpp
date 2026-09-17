#include "config_xml.h"
#include "config_xml_fields.h"
#include "data_util.h"
#include "editor_xml.h"
namespace wpe::shell {
using namespace data_detail;
namespace {
std::vector<std::string> ExactFields(const std::string& text,char separator){std::vector<std::string> fields;std::size_t start=0;for(;;){const auto end=text.find(separator,start);fields.push_back(text.substr(start,end-start));if(end==text.npos)return fields;start=end+1;}}
const std::map<std::string,std::vector<std::string>> enums={
    {"Mode",{"Normal","Advanced"}},{"Action",{"Replace","Intercept","NoModify_Display","NoModify_NoDisplay","None","Change"}},
    {"ExecuteType",{"Send","Robot","None","Filter","WareHouse"}},{"StartFrom",{"Head","Position"}},
    {"ListExecute",{"Together","Sequence"}},{"FilterExecute",{"Priority","Sequence"}},
    {"Instruction",{"SendSendList","Delay","LoopStart","LoopEnd","KeyBoard","Mouse","SendPacketList","SetSystemSocket","Switch"}},
    {"Packet",{"WS1_Send","WS2_Send","WS1_SendTo","WS2_SendTo","WS1_Recv","WS2_Recv","WS1_RecvFrom","WS2_RecvFrom","WSASend","WSASendTo","WSARecv","WSARecvEx","WSARecvFrom","TCP_Req","UDP_Req","TCP_Resp","UDP_Resp","HTTP_Req","HTTP_Resp","HTTPS_Req","HTTPS_Resp","WebSocket_Req","WebSocket_Resp"}}
};
std::string EnumText(const std::string& type,int n){const auto& names=enums.at(type);return n>=0&&static_cast<std::size_t>(n)<names.size()?names[n]:std::to_string(n);}
int EnumNumber(const std::string& type,const std::string& s){const auto text=Trim(s);int n=0;if(Integer(text,n))return n;const auto& names=enums.at(type);
    // Enum.Parse permits comma-separated combinations even without [Flags].
    int combined=0;for(const auto& part:ExactFields(text,',')){const auto key=Trim(part);auto found=std::find(names.begin(),names.end(),key);if(found==names.end())return type=="ListExecute"?1:0;combined|=static_cast<int>(found-names.begin());}return combined;
}
bool Boolean(const std::string& s){const auto text=Upper(Trim(s));if(text=="TRUE")return true;if(text=="FALSE")return false;throw std::runtime_error("XML 布尔字段无效，未应用导入");}
int Int(const std::string& s){int n=0;if(!Integer(s,n))throw std::runtime_error("XML 整数字段无效，未应用导入");return n;}
std::string Flags(const std::string& s){int mask=0;const auto fields=ExactFields(s,':');for(std::size_t i=0;i<12;++i){if(i>=fields.size())break;int n=0;if(!Integer(fields[i],n))break;if(n)mask|=1<<i;if(i==7&&fields.size()<=8){mask|=0xf00;break;}}return Function(mask);}
XmlNode Field(const XmlField& f,const Json& row,bool system){
    const std::string key=f.db;std::string value;
    if(std::string(f.type)=="TEXT"&&row.contains(key)&&row.at(key).is_null())return XmlNode(f.xml);
    if(enums.contains(key))value=EnumText(key,N(row,f.db));
    else if(std::string(f.type)=="BOOLEAN")value=B(row,f.db)?(system?"true":"True"):(system?"false":"False");
    else value=S(row,f.db);
    return XmlNode(f.xml,value);
}
void ReadFields(Json& row,const XmlNode& node,const auto& fields){
    for(const auto& f:fields){const auto* n=node.Get(f.xml);if(!n)continue;const auto value=n->text.value_or("");const std::string key=f.db;
        if(key=="GUID")continue;
        if(enums.contains(key))row[key]=EnumNumber(key,value);
        else if(key=="Function"||key=="CheckType_Value")row[key]=Flags(value);
        else if(key=="ExecuteGUID")row[key]=TryGuid(value).value_or(zero_guid);
        else if(std::string(f.type)=="BOOLEAN")row[key]=Boolean(value);
        else if(std::string(f.type)=="INTEGER"&&key!="SocketContent"&&key!="PortContent"){const auto number=Int(value);if(key=="Remote_Port"&&(number<0||number>65535))throw std::runtime_error("远程端口超出原版 UInt16 范围");row[key]=number;}
        else row[key]=value;
    }
}
enum class SettingType{Boolean,Integer,Port,Text};
struct SettingField{const char* xml;const char* db;SettingType type;};
constexpr std::array<SettingField,15> injectModeFields={
    SettingField{"HookWS1_Send","HookWS1_Send",SettingType::Boolean},{"HookWS1_SendTo","HookWS1_SendTo",SettingType::Boolean},
    {"HookWS1_Recv","HookWS1_Recv",SettingType::Boolean},{"HookWS1_RecvFrom","HookWS1_RecvFrom",SettingType::Boolean},
    {"HookWS2_Send","HookWS2_Send",SettingType::Boolean},{"HookWS2_SendTo","HookWS2_SendTo",SettingType::Boolean},
    {"HookWS2_Recv","HookWS2_Recv",SettingType::Boolean},{"HookWS2_RecvFrom","HookWS2_RecvFrom",SettingType::Boolean},
    {"HookWSA_Send","HookWSA_Send",SettingType::Boolean},{"HookWSA_SendTo","HookWSA_SendTo",SettingType::Boolean},
    {"HookWSA_Recv","HookWSA_Recv",SettingType::Boolean},{"HookWSA_RecvFrom","HookWSA_RecvFrom",SettingType::Boolean},
    {"PacketList_AutoRoll","PacketList_AutoRoll",SettingType::Boolean},{"PacketList_AutoClear","PacketList_AutoClear",SettingType::Boolean},
    {"PacketList_AutoClear_Value","PacketList_AutoClear_Value",SettingType::Integer}
};
constexpr std::array<SettingField,39> proxyModeFields={
    SettingField{"ProxyIP_Auto","ProxyIP_Auto",SettingType::Boolean},{"Enable_SOCKS5","Enable_SOCKS5",SettingType::Boolean},
    {"Enable_HTTP","Enable_HTTP",SettingType::Boolean},{"ProxyIP","ProxyIP",SettingType::Text},
    {"SOCKS5_Port","SOCKS5_Port",SettingType::Port},{"HTTP_Port","HTTP_Port",SettingType::Port},
    {"Enable_Auth","EnableAuth",SettingType::Boolean},{"MaxConnectionNumber","MaxConnectionNumber",SettingType::Integer},
    {"Enable_UnPack","Enable_UnPack",SettingType::Boolean},{"UnPack_Head","UnPack_Head",SettingType::Text},
    {"UnPack_Length","UnPack_Length",SettingType::Text},{"Enable_MapLocal","Enable_MapLocal",SettingType::Boolean},
    {"Enable_MapRemote","Enable_MapRemote",SettingType::Boolean},{"Enable_ExternalProxy","Enable_ExternalProxy",SettingType::Boolean},
    {"ExternalProxy_IP","ExternalProxy_IP",SettingType::Text},{"ExternalProxy_Port","ExternalProxy_Port",SettingType::Port},
    {"Enable_ExternalProxy_AppointPort","Enable_ExternalProxy_AppointPort",SettingType::Boolean},{"ExternalProxy_AppointPort","ExternalProxy_AppointPort",SettingType::Text},
    {"Enable_ExternalProxy_Auth","Enable_ExternalProxy_Auth",SettingType::Boolean},{"ExternalProxy_UserName","ExternalProxy_UserName",SettingType::Text},
    {"ExternalProxy_PassWord","ExternalProxy_PassWord",SettingType::Text},{"MustTCP","MustTCP",SettingType::Boolean},
    {"MustTCP_IP","MustTCP_IP",SettingType::Text},{"MustTCP_Port","MustTCP_Port",SettingType::Port},
    {"MustTCP_Auth","MustTCP_Auth",SettingType::Boolean},{"MustTCP_UserName","MustTCP_UserName",SettingType::Text},
    {"MustTCP_PassWord","MustTCP_PassWord",SettingType::Text},{"MustTCP_AppointPort","MustTCP_AppointPort",SettingType::Boolean},
    {"MustTCP_AppointPortContent","MustTCP_AppointPortContent",SettingType::Text},{"EnableFireWall","EnableFireWall",SettingType::Boolean},
    {"Only_WPC_Client","Only_WPC_Client",SettingType::Boolean},{"WhiteListMode","WhiteListMode",SettingType::Boolean},
    {"FireWall_AutoWhiteList_AuthSuccess","FireWall_AutoWhiteList_AuthSuccess",SettingType::Boolean},
    {"FireWall_AutoBlackList_UnSupport","FireWall_AutoBlackList_UnSupport",SettingType::Boolean},
    {"FireWall_AutoBlackList_AuthFail","FireWall_AutoBlackList_AuthFail",SettingType::Boolean},
    {"FireWall_AutoBlackList_Minutes","FireWall_AutoBlackList_Minutes",SettingType::Integer},
    {"FireWall_AutoClear_Expiry","FireWall_AutoClear_Expiry",SettingType::Boolean},{"DriverType","DriverType",SettingType::Integer},
    {"SelectProcessNames","SelectProcessNames",SettingType::Text}
};
template<std::size_t Count>XmlNode SettingsXml(const char* name,const Json& settings,const std::array<SettingField,Count>& fields){
    XmlNode root(name);for(const auto& field:fields){std::string value;if(field.type==SettingType::Boolean)value=B(settings,field.db)?"true":"false";else if(field.type==SettingType::Integer||field.type==SettingType::Port)value=std::to_string(N(settings,field.db));else value=S(settings,field.db);root.nodes.emplace_back(field.xml,value);}return root;
}
template<std::size_t Count>Json ParseSettings(const XmlNode& node,const Json& current,const std::array<SettingField,Count>& fields){
    auto next=current;for(const auto& field:fields){const auto* value=node.Get(field.xml);if(!value)continue;const auto text=value->text.value_or("");if(field.type==SettingType::Boolean)next[field.db]=Boolean(text);else if(field.type==SettingType::Text)next[field.db]=text;else{const auto number=Int(text);if(field.type==SettingType::Port&&(number<0||number>65535))throw std::runtime_error("代理端口超出原版 UInt16 范围");if(std::string(field.db)=="DriverType"&&(number<0||number>2))continue;next[field.db]=number;}}return next;
}
}
XmlNode SystemConfigXml(const Json& config){XmlNode root("SystemConfig");for(const auto& f:systemFields)root.nodes.push_back(Field(f,config,true));return root;}
Json ParseSystemConfig(const XmlNode& node,const Json& current){auto next=current;ReadFields(next,node,systemFields);return next;}
XmlNode InjectModeXml(const Json& config){return SettingsXml("InjectMode",config,injectModeFields);}
Json ParseInjectMode(const XmlNode& node,const Json& current){return ParseSettings(node,current,injectModeFields);}
XmlNode ProxyModeXml(const Json& config){return SettingsXml("ProxyMode",config,proxyModeFields);}
Json ParseProxyMode(const XmlNode& node,const Json& current){return ParseSettings(node,current,proxyModeFields);}
XmlNode IpRuleListXml(bool black,const Json& rows){
    XmlNode root(black?"BlackList":"WhiteList");const char* itemName=black?"Black":"White";
    for(const auto& row:rows){XmlNode item(itemName);item.nodes.emplace_back("IPAddress",S(row,"IPAddress"));item.nodes.emplace_back("IsExpiry",B(row,"IsExpiry")?"true":"false");item.nodes.emplace_back("ExpiryTime",XmlDate(S(row,"ExpiryTime","8888-12-31 00:00:00")));item.nodes.emplace_back("CreateTime",XmlDate(S(row,"CreateTime")));root.nodes.push_back(std::move(item));}
    return root;
}
Json ParseIpRuleList(bool,const XmlNode& root,const Json& current){
    Json rows=current;std::set<std::string> existing;for(const auto& row:rows)existing.insert(Upper(S(row,"IPAddress")));
    for(const auto& item:root.nodes){const auto ip=Trim(item.Value("IPAddress"));if(ip.empty()||existing.contains(Upper(ip)))continue;const auto range=IpRuleRange(ip);const bool expiry=item.Get("IsExpiry")?Boolean(item.Value("IsExpiry")):false;
        const auto now=LocalDateTime();auto date=[&](const char* key,const std::string& fallback){const auto* node=item.Get(key);if(!node)return fallback;const auto parsed=DateTimeText(node->text.value_or(""));if(!parsed)throw std::runtime_error("IP 名单日期字段无效，未应用导入");return *parsed;};
        const auto expires=date("ExpiryTime",now),created=date("CreateTime",now);
        rows.push_back({{"IPAddress",ip},{"StartIP",range?static_cast<std::int64_t>(range->first):-1},{"EndIP",range?static_cast<std::int64_t>(range->second):-1},{"IsExpiry",expiry},{"ExpiryTime",expires},{"CreateTime",created},{"IPLocation",""},{"EffectCount",0}});existing.insert(Upper(ip));
    }return rows;
}
XmlNode AccountListXml(const Json& rows){
    XmlNode root("ProxyAccountList");for(const auto& row:rows){XmlNode account("ProxyAccount");
        account.nodes.emplace_back("IsEnable",B(row,"IsEnable")?"True":"False");account.nodes.emplace_back("ID",Upper(S(row,"GUID")));account.nodes.emplace_back("UserName",S(row,"UserName"));account.nodes.emplace_back("PassWord",S(row,"PassWord"));
        account.nodes.emplace_back("IsLimitLinks",B(row,"IsLimitLinks")?"true":"false");account.nodes.emplace_back("LimitLinks",std::to_string(N(row,"LimitLinks",1)));account.nodes.emplace_back("IsLimitDevices",B(row,"IsLimitDevices")?"true":"false");account.nodes.emplace_back("LimitDevices",std::to_string(N(row,"LimitDevices",1)));
        account.nodes.emplace_back("IsExpiry",B(row,"IsExpiry")?"true":"false");account.nodes.emplace_back("ExpiryTime",XmlDate(S(row,"ExpiryTime")));account.nodes.emplace_back("CreateTime",XmlDate(S(row,"CreateTime")));
        if(row.contains("_logins")&&!row.at("_logins").empty()){XmlNode logins("AccountIPInfo");for(const auto& login:row.at("_logins")){XmlNode item("IPInfo");auto time=S(login,"LoginTime");std::replace(time.begin(),time.end(),' ','T');item.nodes.emplace_back("LoginTime",time);item.nodes.emplace_back("LoginIP",S(login,"LoginIP"));logins.nodes.push_back(std::move(item));}account.nodes.push_back(std::move(logins));}
        root.nodes.push_back(std::move(account));
    }return root;
}
Json ParseAccountList(const XmlNode& root,const Json& current){
    Json rows=current;std::set<std::string> ids,users;for(const auto& row:rows){ids.insert(Upper(S(row,"GUID")));users.insert(S(row,"UserName"));}
    for(const auto& node:root.nodes){const auto user=node.Value("UserName"),password=node.Value("PassWord");if(user.empty()||password.empty()||users.contains(user))continue;
        auto id=TryGuid(node.Value("ID")).value_or(Guid());if(id==zero_guid||ids.contains(id))id=Guid();const auto now=LocalDateTime();
        auto date=[&](const char* key,const std::string& fallback){const auto* value=node.Get(key);if(!value)return fallback;const auto parsed=DateTimeText(value->text.value_or(""));if(!parsed)throw std::runtime_error("代理账号日期字段无效，未应用导入");return *parsed;};
        Json logins=Json::array();std::map<std::string,std::size_t> positions;if(const auto* list=node.Get("AccountIPInfo")){for(const auto& item:list->nodes){const auto ip=item.Value("LoginIP");if(ip.empty())continue;const auto parsed=DateTimeText(item.Value("LoginTime","0001-01-01 00:00:00"));if(!parsed)throw std::runtime_error("账号登录日期字段无效，未应用导入");const auto found=positions.find(ip);if(found==positions.end()){positions[ip]=logins.size();logins.push_back({{"LoginTime",*parsed},{"LoginIP",ip},{"IPLocation",""}});}else if(S(logins[found->second],"LoginTime")<*parsed)logins[found->second]["LoginTime"]=*parsed;}}
        const bool limitLinks=node.Get("IsLimitLinks")?Boolean(node.Value("IsLimitLinks")):false,limitDevices=node.Get("IsLimitDevices")?Boolean(node.Value("IsLimitDevices")):true;
        const auto links=Int(node.Value("LimitLinks","1")),devices=Int(node.Value("LimitDevices","1"));Json row{{"GUID",id},{"IsEnable",node.Get("IsEnable")?Boolean(node.Value("IsEnable")):false},{"UserName",user},{"PassWord",password},{"IsLimitLinks",limitLinks},{"LimitLinks",limitLinks?std::max(1,links):links},{"IsLimitDevices",limitDevices},{"LimitDevices",limitDevices?std::max(1,devices):devices},{"IsExpiry",node.Get("IsExpiry")?Boolean(node.Value("IsExpiry")):false},{"ExpiryTime",date("ExpiryTime",now)},{"CreateTime",date("CreateTime",now)},{"IsOnLine",false},{"_logins",std::move(logins)}};
        ids.insert(id);users.insert(user);rows.push_back(std::move(row));
    }return rows;
}
XmlNode AutoStoresXml(const Json& rows){
    XmlNode root("AutoStores");for(const auto& row:rows){XmlNode rule("Rule");rule.nodes={XmlNode("IsEnable",B(row,"IsEnable")?"true":"false"),XmlNode("PacketHead",S(row,"PacketHead")),XmlNode("WID",Upper(S(row,"WID")))};root.nodes.push_back(std::move(rule));}return root;
}
Json ParseAutoStores(const XmlNode& root,const Json& current,bool append){
    if(root.LocalName()!="AutoStores")throw std::runtime_error("不是原版自动入库文件");Json rows=append?current:Json::array();
    for(const auto& node:root.nodes){
        const auto wid=NormalGuid(node.Value("WID"));if(wid==zero_guid)continue;
        const auto head=node.Value("PacketHead");if(head.empty())continue;
        bool enabled=false;if(const auto field=node.Get("IsEnable")){const auto value=Upper(field->text.value_or(""));if(value=="TRUE")enabled=true;else if(value!="FALSE")throw std::runtime_error("自动入库 IsEnable 不是有效布尔值");}
        rows.push_back({{"IsEnable",enabled},{"PacketHead",head},{"WID",wid},{"_id",Guid()}});
    }return rows;
}
XmlNode MapListXml(bool remote,const Json& rows){
    XmlNode root(remote?"MapRemote":"MapLocal");for(const auto& row:rows){XmlNode item(remote?"Remote":"Local");item.nodes.emplace_back("IsEnable",B(row,"IsEnable")?"True":"False");
        if(!remote)item.nodes.insert(item.nodes.end(),{XmlNode("ProtocolType",S(row,"ProtocolType","Http")),XmlNode("Host",S(row,"Host")),XmlNode("Port",std::to_string(N(row,"Port",80))),XmlNode("RemotePath",S(row,"RemotePath")),XmlNode("LocalPath",S(row,"LocalPath"))});
        else item.nodes.insert(item.nodes.end(),{XmlNode("ProtocolType_From",S(row,"ProtocolType_From","Http")),XmlNode("Host_From",S(row,"Host_From")),XmlNode("Port_From",std::to_string(N(row,"Port_From",80))),XmlNode("Path_From",S(row,"Path_From")),XmlNode("ProtocolType_To",S(row,"ProtocolType_To","Http")),XmlNode("Host_To",S(row,"Host_To")),XmlNode("Port_To",std::to_string(N(row,"Port_To",80))),XmlNode("Path_To",S(row,"Path_To"))});root.nodes.push_back(std::move(item));
    }return root;
}
Json ParseMapList(bool remote,const XmlNode& root,const Json& current,bool append){
    if(root.LocalName()!=(remote?"MapRemote":"MapLocal"))throw std::runtime_error("不是原版代理映射文件");Json rows=append?current:Json::array();for(const auto& item:root.nodes){const bool enabled=item.Get("IsEnable")?Boolean(item.Value("IsEnable")):false;
        if(!remote){const auto host=item.Value("Host"),local=item.Value("LocalPath");const int port=Int(item.Value("Port","80"));if(host.empty()||port<=0)continue;rows.push_back({{"IsEnable",enabled},{"ProtocolType",item.Value("ProtocolType","Http")},{"Host",host},{"Port",port},{"RemotePath",item.Value("RemotePath")},{"LocalPath",local},{"_id",Guid()}});}
        else{const auto from=item.Value("Host_From"),to=item.Value("Host_To");const int fromPort=Int(item.Value("Port_From","80")),toPort=Int(item.Value("Port_To","80"));if(from.empty()||to.empty()||fromPort<=0||toPort<=0)continue;rows.push_back({{"IsEnable",enabled},{"ProtocolType_From",item.Value("ProtocolType_From","Http")},{"Host_From",from},{"Port_From",fromPort},{"Path_From",item.Value("Path_From")},{"ProtocolType_To",item.Value("ProtocolType_To","Http")},{"Host_To",to},{"Port_To",toPort},{"Path_To",item.Value("Path_To")},{"_id",Guid()}});}
    }return rows;
}
XmlNode ServerListXml(const Json& rows){
    XmlNode root("ServerList");for(const auto& row:rows){XmlNode server("Server");server.nodes={XmlNode("IsEnable",B(row,"IsEnable")?"true":"false"),XmlNode("ServerName",S(row,"ServerName")),XmlNode("ServerIP",S(row,"ServerIP")),XmlNode("ServerPort",std::to_string(N(row,"ServerPort",1080))),XmlNode("ForgotURL",S(row,"ForgotURL")),XmlNode("RegisterURL",S(row,"RegisterURL")),XmlNode("VerifyURL",S(row,"VerifyURL"))};XmlNode rules("Rules");for(const auto& rowRule:row.at("_rules")){XmlNode rule("Rule");rule.nodes={XmlNode("IsEnable",B(rowRule,"IsEnable")?"true":"false"),XmlNode("RType",std::to_string(N(rowRule,"RuleType"))),XmlNode("RArgument",S(rowRule,"RuleArgument")),XmlNode("RAction",std::to_string(N(rowRule,"RuleAction")))};rules.nodes.push_back(std::move(rule));}server.nodes.push_back(std::move(rules));root.nodes.push_back(std::move(server));}return root;
}
Json ParseServerList(const XmlNode& root){
    Json rows=Json::array();for(const auto& node:root.nodes){const auto name=node.Value("ServerName");if(name.empty())continue;Json rules=Json::array();if(const auto* ruleNodes=node.Get("Rules"))for(const auto& item:ruleNodes->nodes)rules.push_back({{"RID",Guid()},{"IsEnable",item.Get("IsEnable")?Boolean(item.Value("IsEnable")):false},{"RuleType",Int(item.Value("RType","0"))},{"RuleArgument",item.Value("RArgument")},{"RuleAction",Int(item.Value("RAction","0"))}});rows.push_back({{"SID",Guid()},{"IsEnable",node.Get("IsEnable")?Boolean(node.Value("IsEnable")):false},{"ServerName",name},{"ServerIP",node.Value("ServerIP")},{"ServerPort",Int(node.Value("ServerPort","0"))},{"ForgotURL",node.Value("ForgotURL")},{"RegisterURL",node.Value("RegisterURL")},{"VerifyURL",node.Value("VerifyURL")},{"_rules",std::move(rules)}});}return rows;
}
XmlNode NoticeListXml(const Json& rows){
    XmlNode root("NoticeList");for(const auto& row:rows){auto time=S(row,"NoticeTime");std::replace(time.begin(),time.end(),' ','T');if(time.size()==19)time+=".0000000";XmlNode notice("Notice");notice.nodes={XmlNode("NoticeType",std::to_string(N(row,"NoticeType",1))),XmlNode("NoticeTitle",S(row,"NoticeTitle")),XmlNode("NoticeContent",S(row,"NoticeContent")),XmlNode("NoticeMore",S(row,"NoticeMore")),XmlNode("NoticeTime",time)};root.nodes.push_back(std::move(notice));}return root;
}
Json ParseNoticeList(const XmlNode& root){
    Json rows=Json::array();for(const auto& node:root.nodes){const auto title=node.Value("NoticeTitle");if(title.empty())continue;auto raw=node.Value("NoticeTime");if(raw.size()>=19)raw=raw.substr(0,19);auto time=DateTimeText(raw).value_or(LocalDateTime());rows.push_back({{"NID",Guid()},{"NoticeType",Int(node.Value("NoticeType","0"))},{"NoticeTitle",title},{"NoticeContent",node.Value("NoticeContent")},{"NoticeMore",node.Value("NoticeMore")},{"NoticeTime",time}});}return rows;
}
XmlNode ParentListXml(int list,const Json& rows){
    XmlNode root(list==11?"WareHouseList":tables[list-8]+"List");
    for(const auto& row:rows){XmlNode parent(tables[list-8]);
        if(list==8){for(const auto& f:filterFields)parent.nodes.push_back(Field(f,row,false));}
        else{
            if(list<11)parent.nodes.emplace_back("IsEnable",B(row,"IsEnable")?"True":"False");parent.nodes.emplace_back("ID",Upper(S(row,"GUID")));parent.nodes.emplace_back("Name",S(row,"Name"));
            if(list==9){parent.nodes.emplace_back("SystemSocket","False");parent.nodes.emplace_back("LoopCNT",std::to_string(N(row,"LoopCNT",1)));parent.nodes.emplace_back("LoopINT",std::to_string(N(row,"LoopINT",1000)));parent.nodes.emplace_back("Notes",S(row,"Notes"));}
            if(!row.at("_children").empty()){
                XmlNode childrenNode(list==9?"SendCollection":list==10?"Instructions":"Stores");
                for(const auto& child:row.at("_children")){
                    XmlNode item(list==9?"Collection":list==10?"Inst":"Data");
                    if(list==9){if(!child.at("Buffer").is_binary())throw std::runtime_error("发送封包 Buffer 无效");item.nodes={XmlNode("Socket",std::to_string(N(child,"Socket"))),XmlNode("Type",EnumText("Packet",N(child,"Type"))),XmlNode("IPTo",S(child,"IPTo")),XmlNode("Buffer",Hex(child["Buffer"],SIZE_MAX))};}
                    else if(list==10){item.attributes.emplace_back("Type",EnumText("Instruction",N(child,"Type")));if(child.contains("Content")&&!child["Content"].is_null())item.text=S(child,"Content");}
                    else{if(!child.at("Buffer").is_binary())throw std::runtime_error("仓储封包 Buffer 无效");item.nodes.emplace_back("PacketData",Hex(child["Buffer"],SIZE_MAX));}childrenNode.nodes.push_back(std::move(item));
                }parent.nodes.push_back(std::move(childrenNode));
            }
        }root.nodes.push_back(std::move(parent));
    }return root;
}
Json ParseParentList(int list,const XmlNode& root,std::set<std::string> existing,std::uint64_t& packetId,const Json& config){
    // The original parent-list loaders enumerate Root.Elements() regardless
    // of root name or namespace. The chosen native import method selects the model.
    Json rows=Json::array();
    for(const auto& node:root.nodes){Json row{{"Name",node.Value("Name")},{"_objectId",Guid()}};const auto parsedId=TryGuid(node.Value("ID"));auto id=parsedId?*parsedId:Guid();if(existing.contains(id))id=Guid();row["GUID"]=id;
        if(list<11)row["IsEnable"]=node.Get("IsEnable")?Boolean(node.Value("IsEnable")):false;
        if(list==8){for(const auto& f:filterFields){const std::string key=f.db;if(row.contains(key))continue;row[key]=std::string(f.type)=="BOOLEAN"?Json(false):std::string(f.type)=="INTEGER"?Json(0):Json("");}
            row["Action"]=2;row["ExecuteGUID"]=zero_guid;row["Function"]=Function(0);row["ProgressionStep"]=1;row["ProgressionCarryNumber"]=1;row["SocketContent"]="";row["PortContent"]="";ReadFields(row,node,filterFields);
        }else{
            row["_children"]=Json::array();const auto* child=node.Get(list==9?"SendCollection":list==10?"Instructions":"Stores");
            if(list==9){row.update({{"SystemSocket",false},{"LoopCNT",std::max(1,Int(node.Value("LoopCNT","1")))},{"LoopINT",std::max(0,Int(node.Value("LoopINT","1000")))},{"Notes",node.Value("Notes")}});}
            if(child){
                if(list==10){for(const auto& n:child->nodes){const auto a=std::find_if(n.attributes.begin(),n.attributes.end(),[](const auto& x){return x.first=="Type";});if(a==n.attributes.end())throw std::runtime_error("机器人指令缺少 Type，未应用导入");row["_children"].push_back({{"Type",EnumNumber("Instruction",a->second)},{"Content",n.text.value_or("")}});}}
                else row["_children"]=ReadEditorXmlNode(*child,list==9);
            }
            if(list==11&&B(config,"StoresLimit",true)&&N(config,"StoresLimit_Value",5000)>0){auto& items=row["_children"];const auto max=static_cast<std::size_t>(N(config,"StoresLimit_Value",5000));if(items.size()>max)items.erase(items.begin(),items.begin()+static_cast<Json::difference_type>(items.size()-max));}
            row["_children"]=RuntimeChildren(std::move(row["_children"]),list,packetId);
        }
        if(S(row,"Name").empty()||(list>8&&id==zero_guid))continue;existing.insert(id);rows.push_back(std::move(row));
    }return rows;
}
}
