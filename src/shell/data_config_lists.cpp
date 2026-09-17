#include "data_service.h"
#include "data_util.h"
#include <algorithm>
#include <set>

namespace wpe::shell {
using namespace data_detail;
namespace {
Json GoodResult(){return {{"ok",true}};}
Json BadResult(const std::string& error){return {{"ok",false},{"error",error}};}

void MoveRows(Json& rows,int action,const std::vector<std::string>& picked,const char* key){
    for(const auto& id:picked){
        auto it=std::find_if(rows.begin(),rows.end(),[&](const Json& row){return Upper(S(row,key))==Upper(id);});
        if(it==rows.end())continue;const auto index=static_cast<std::size_t>(it-rows.begin());auto row=*it;
        if((action==1&&index==0)||(action==2&&index+1==rows.size()))continue;
        if(action<0||action>3)continue;rows.erase(it);const auto target=action==0?0:action==1?index-1:action==2?index+1:rows.size();rows.insert(rows.begin()+static_cast<Json::difference_type>(target),std::move(row));
    }
}
std::vector<std::string> PickRows(const Json& rows,const Json& args,const char* key){
    std::set<std::string> wanted;for(const auto& id:args.value("ids",Json::array()))if(id.is_string())wanted.insert(Upper(id.get<std::string>()));
    std::vector<std::string> picked;for(const auto& row:rows)if(wanted.contains(Upper(S(row,key))))picked.push_back(S(row,key));return picked;
}
Json* FindBy(Json& rows,const char* key,const std::string& id){for(auto& row:rows)if(Upper(S(row,key))==Upper(id))return &row;return nullptr;}
std::string RuleName(int type){
    static constexpr const char* names[]={"DOMAIN","DOMAIN-SUFFIX","DOMAIN-KEYWORD","DOMAIN-REGEX","GEOIP","GEOSITE","IP-CIDR","IP-CIDR6","SRC-IP-CIDR","SRC-PORT","DST-PORT","PROCESS-NAME","PROCESS-PATH","NETWORK","RULE-SET","MATCH","AND","OR","NOT","SUB-RULE","IN-PORT","UI-EX","COMMAND","DEVICE-NAME"};
    return type>=0&&type<static_cast<int>(std::size(names))?names[type]:std::to_string(type);
}
std::vector<std::string> RuleArguments(const std::string& text){std::vector<std::string> out;for(auto part:Split(text,';')){part=Trim(part);if(!part.empty())out.push_back(std::move(part));}return out;}
}

void DataService::PersistMap(int list,const Json& rows){
    if(list!=13&&list!=14)throw std::invalid_argument("Invalid map list");Json stored=rows;for(auto& row:stored)row.erase("_id");db_.Replace(list==13?"ProxyMapLocal":"ProxyMapRemote",stored);
}
void DataService::PersistServers(const Json& rows){
    Json servers=Json::array(),rules=Json::array();for(auto server:rows){const auto sid=Upper(S(server,"SID"));for(auto rule:server.at("_rules")){rule["RID"]=Guid();rule["SID"]=sid;rules.push_back(std::move(rule));}server.erase("_rules");servers.push_back(std::move(server));}
    db_.Execute("DELETE FROM ServerRuleInfo");db_.Replace("ServerInfo",servers);db_.Replace("ServerRuleInfo",rules);
}
void DataService::PersistNotices(const Json& rows){db_.Replace("NoticeInfo",rows);}

std::optional<Json> DataService::CallConfigLists(const std::string& method,const Json& args){
    if(method=="getMapSetting")return Json{{"enableLocal",B(proxy_config_,"Enable_MapLocal")},{"enableRemote",B(proxy_config_,"Enable_MapRemote")}};
    if(method=="saveMapSetting"){
        SaveProxyConfig({{"Enable_MapLocal",B(args,"enableLocal")},{"Enable_MapRemote",B(args,"enableRemote")}});
        emit_("toast",{{"level",2},{"text",Text("MapSettingsForm.Success","映射设置保存成功")}});return GoodResult();
    }
    if(method=="saveMapLocal"||method=="saveMapRemote"){
        const bool remote=method=="saveMapRemote";const int list=remote?14:13;auto rows=lists_[list];const auto id=S(args,"id");auto* row=id.empty()?nullptr:FindBy(rows,"_id",id);
        if(!id.empty()&&!row)return Json{{"error",Text("MapSettingsForm.Gone","这条映射已经不在列表里了")}};
        if(!remote){const auto host=Trim(S(args,"host")),local=Trim(S(args,"localPath"));if(host.empty()||local.empty())return Json{{"error",Text("MapLocalForm.Empty","映射数据为空")}};
            if(N(args,"port",80)>0){Json next{{"IsEnable",row?B(*row,"IsEnable"):false},{"ProtocolType","Http"},{"Host",host},{"Port",N(args,"port",80)},{"RemotePath",Trim(S(args,"remotePath"))},{"LocalPath",local},{"_id",row?S(*row,"_id"):Guid()}};if(row)*row=std::move(next);else rows.push_back(std::move(next));}
        }else{const auto from=Trim(S(args,"hostFrom")),to=Trim(S(args,"hostTo"));if(from.empty()||to.empty())return Json{{"error",Text("MapRemoteForm.Empty","映射数据为空")}};
            if(N(args,"portFrom",80)>0&&N(args,"portTo",80)>0){Json next{{"IsEnable",row?B(*row,"IsEnable"):false},{"ProtocolType_From","Http"},{"Host_From",from},{"Port_From",N(args,"portFrom",80)},{"Path_From",Trim(S(args,"pathFrom"))},{"ProtocolType_To","Http"},{"Host_To",to},{"Port_To",N(args,"portTo",80)},{"Path_To",Trim(S(args,"pathTo"))},{"_id",row?S(*row,"_id"):Guid()}};if(row)*row=std::move(next);else rows.push_back(std::move(next));}
        }
        db_.Transaction([&]{PersistMap(list,rows);});lists_[list]=std::move(rows);Publish(list);return Json{{"error",""}};
    }
    if(method=="setMapEnable"){
        const int list=B(args,"remote")?14:13;auto rows=lists_[list];auto* row=FindBy(rows,"_id",S(args,"id"));if(!row)return Json{{"ok",false}};(*row)["IsEnable"]=B(args,"enable");db_.Transaction([&]{PersistMap(list,rows);});lists_[list]=std::move(rows);Publish(list);return GoodResult();
    }
    if(method=="mapAction"){
        const int list=B(args,"remote")?14:13,action=N(args,"action",-1);auto rows=lists_[list];const auto id=S(args,"id");auto* row=FindBy(rows,"_id",id);if(!row)return Json{{"ok",false}};
        if(action==6)rows.erase(std::remove_if(rows.begin(),rows.end(),[&](const Json& item){return S(item,"_id")==id;}),rows.end());else MoveRows(rows,action,{id},"_id");
        db_.Transaction([&]{PersistMap(list,rows);});lists_[list]=std::move(rows);Publish(list);return GoodResult();
    }
    if(method=="mapCommand"){
        const int list=B(args,"remote")?14:13,action=N(args,"action",-1);if(action==5||action==8)return GoodResult();if(action!=7)return Json{{"ok",false}};
        db_.Transaction([&]{PersistMap(list,Json::array());});lists_[list]=Json::array();Publish(list);return GoodResult();
    }

    if(method=="saveServer"){
        auto rows=lists_[17];const auto id=S(args,"id"),name=Trim(S(args,"name")),ip=Trim(S(args,"ip"));const int port=N(args,"port");
        if(name.empty())return Json{{"error",Text("WPCConfig.ServerList.Name.Empty","服务器名称为空")}};if(ip.empty())return Json{{"error",Text("WPCConfig.ServerList.IP.Empty","服务器 IP 为空")}};if(port<1||port>65535)return Json{{"error",Text("WPCConfig.ServerList.Port.Error","端口号不正确")}};
        auto* row=id.empty()?nullptr:FindBy(rows,"SID",id);if(!id.empty()&&!row)return Json{{"error",Text("WPCConfig.ServerList.Gone","这台服务器已经不在列表里了")}};
        Json next{{"SID",row?S(*row,"SID"):Guid()},{"IsEnable",B(args,"enable")},{"ServerName",name},{"ServerIP",ip},{"ServerPort",port},{"ForgotURL",Trim(S(args,"forgotUrl"))},{"RegisterURL",Trim(S(args,"registerUrl"))},{"VerifyURL",Trim(S(args,"verifyUrl"))},{"_rules",row?row->at("_rules"):Json::array()}};if(row)*row=std::move(next);else rows.push_back(std::move(next));
        db_.Transaction([&]{PersistServers(rows);});lists_[17]=std::move(rows);Publish(17);return Json{{"error",""}};
    }
    if(method=="setServerEnable"){
        auto rows=lists_[17];auto* row=FindBy(rows,"SID",S(args,"id"));if(!row)return Json{{"ok",false}};(*row)["IsEnable"]=B(args,"enable");db_.Transaction([&]{PersistServers(rows);});lists_[17]=std::move(rows);Publish(17);return GoodResult();
    }
    if(method=="serverListAction"){
        auto rows=lists_[17];const int action=N(args,"action",-1);const auto picked=PickRows(rows,args,"SID");if(picked.empty())return Json{{"ok",false},{"delta",0}};const auto before=rows.size();
        if(action==6)for(const auto& id:picked)rows.erase(std::remove_if(rows.begin(),rows.end(),[&](const Json& row){return Upper(S(row,"SID"))==Upper(id);}),rows.end());else MoveRows(rows,action,picked,"SID");
        db_.Transaction([&]{PersistServers(rows);});lists_[17]=std::move(rows);Publish(17);return Json{{"ok",true},{"delta",static_cast<std::int64_t>(lists_[17].size())-static_cast<std::int64_t>(before)}};
    }
    if(method=="clearServers"){db_.Transaction([&]{PersistServers(Json::array());});lists_[17]=Json::array();Publish(17);return GoodResult();}
    if(method=="getRuleTypes"){Json rows=Json::array();for(int i=0;i<24;++i)rows.push_back({{"Value",i},{"Name",RuleName(i)}});return Json{{"rows",rows}};}
    if(method=="getServerRules"){
        Json out=Json::array();auto rows=lists_[17];if(auto* server=FindBy(rows,"SID",S(args,"sid")))for(const auto& rule:server->at("_rules")){const int type=N(rule,"RuleType");out.push_back({{"Id",S(rule,"RID")},{"IsEnable",B(rule,"IsEnable")},{"Type",type},{"TypeName",RuleName(type)},{"Argument",S(rule,"RuleArgument")},{"Action",N(rule,"RuleAction")}});}return Json{{"rows",out}};
    }
    if(method=="saveServerRule"){
        auto rows=lists_[17];auto* server=FindBy(rows,"SID",S(args,"sid"));if(!server)return Json{{"error",Text("WPCConfig.ServerList.Gone","这台服务器已经不在列表里了")}};const int type=N(args,"type"),action=N(args,"ruleAction");if(type<0||type>23||action<0||action>2)return Json{{"error",Text("WPCConfig.RuleList.Error","规则类型或动作不正确")}};
        auto& rules=server->at("_rules");const auto rid=S(args,"id"),arg=Trim(S(args,"argument"));auto parts=RuleArguments(arg);if(rid.empty()){if(parts.empty())parts.push_back(arg);for(const auto& part:parts)rules.push_back({{"RID",Guid()},{"IsEnable",B(args,"enable")},{"RuleType",type},{"RuleArgument",part},{"RuleAction",action}});}else{auto* rule=FindBy(rules,"RID",rid);if(!rule)return Json{{"error",Text("WPCConfig.ServerList.Gone","这台服务器已经不在列表里了")}};rule->update({{"IsEnable",B(args,"enable")},{"RuleType",type},{"RuleArgument",parts.empty()?arg:parts[0]},{"RuleAction",action}});}
        db_.Transaction([&]{PersistServers(rows);});lists_[17]=std::move(rows);Publish(17);return Json{{"error",""}};
    }
    if(method=="setServerRuleEnable"){
        auto rows=lists_[17];auto* server=FindBy(rows,"SID",S(args,"sid"));auto* rule=server?FindBy(server->at("_rules"),"RID",S(args,"id")):nullptr;if(!rule)return Json{{"ok",false}};(*rule)["IsEnable"]=B(args,"enable");db_.Transaction([&]{PersistServers(rows);});lists_[17]=std::move(rows);Publish(17);return GoodResult();
    }
    if(method=="serverRuleAction"){
        auto rows=lists_[17];auto* server=FindBy(rows,"SID",S(args,"sid"));if(!server)return Json{{"ok",false},{"delta",0}};auto& rules=server->at("_rules");const auto picked=PickRows(rules,args,"RID");if(picked.empty())return Json{{"ok",false},{"delta",0}};const auto before=rules.size();const int action=N(args,"action",-1);
        if(action==6)for(const auto& id:picked)rules.erase(std::remove_if(rules.begin(),rules.end(),[&](const Json& row){return Upper(S(row,"RID"))==Upper(id);}),rules.end());else MoveRows(rules,action,picked,"RID");const auto delta=static_cast<std::int64_t>(rules.size())-static_cast<std::int64_t>(before);
        db_.Transaction([&]{PersistServers(rows);});lists_[17]=std::move(rows);Publish(17);return Json{{"ok",true},{"delta",delta}};
    }
    if(method=="clearServerRules"){
        auto rows=lists_[17];auto* server=FindBy(rows,"SID",S(args,"sid"));if(server)server->at("_rules")=Json::array();db_.Transaction([&]{PersistServers(rows);});lists_[17]=std::move(rows);Publish(17);return GoodResult();
    }

    if(method=="saveNotice"){
        auto rows=lists_[18];auto id=S(args,"id"),title=Trim(S(args,"title")),content=Trim(S(args,"content")),more=Trim(S(args,"more"));int type=N(args,"type",1);if(type<1||type>5)type=1;
        if(title.empty())return Json{{"error",Text("WPCConfig.NoticeList.Title.Empty","公告标题为空")}};if(content.empty())return Json{{"error",Text("WPCConfig.NoticeList.Content.Empty","公告内容为空")}};auto* row=id.empty()?nullptr:FindBy(rows,"NID",id);if(!id.empty()&&!row)return Json{{"error",Text("WPCConfig.NoticeList.Gone","这条公告已经不在列表里了")}};
        Json next{{"NID",row?S(*row,"NID"):Guid()},{"NoticeType",type},{"NoticeTitle",title},{"NoticeContent",content},{"NoticeMore",more},{"NoticeTime",LocalDateTime()}};if(row)*row=std::move(next);else rows.push_back(std::move(next));db_.Transaction([&]{PersistNotices(rows);});lists_[18]=std::move(rows);Publish(18);return Json{{"error",""}};
    }
    if(method=="noticeListAction"){
        auto rows=lists_[18];const auto picked=PickRows(rows,args,"NID");if(picked.empty())return Json{{"ok",false},{"delta",0}};const auto before=rows.size();const int action=N(args,"action",-1);if(action==6)for(const auto& id:picked)rows.erase(std::remove_if(rows.begin(),rows.end(),[&](const Json& row){return Upper(S(row,"NID"))==Upper(id);}),rows.end());else MoveRows(rows,action,picked,"NID");db_.Transaction([&]{PersistNotices(rows);});lists_[18]=std::move(rows);Publish(18);return Json{{"ok",true},{"delta",static_cast<std::int64_t>(lists_[18].size())-static_cast<std::int64_t>(before)}};
    }
    if(method=="clearNotices"){db_.Transaction([&]{PersistNotices(Json::array());});lists_[18]=Json::array();Publish(18);return GoodResult();}
    return std::nullopt;
}
}
