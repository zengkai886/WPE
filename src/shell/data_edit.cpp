#include "data_service.h"
#include "data_util.h"
#include "editor_xml.h"
namespace wpe::shell {
using namespace data_detail;
namespace {
// C# String.Split retains trailing empty fields (e.g. LeftClick|).
std::vector<std::string> Fields(const std::string& s,char delimiter){
    std::vector<std::string> out;std::size_t start=0;
    for(;;){auto end=s.find(delimiter,start);out.push_back(s.substr(start,end-start));if(end==s.npos)return out;start=end+1;}
}
std::string Fmt(std::string format,const std::string& arg){const auto p=format.find("{0}");if(p!=format.npos)format.replace(p,3,arg);return format;}
std::string ParsedGuid(std::string s){
    // Guid.TryParse also accepts the hexadecimal X form. Whitespace is ignored
    // inside that form, but not inside the ordinary D/N/B/P representations.
    if(s.find("0x")!=s.npos||s.find("0X")!=s.npos){
        const auto compact=Trim(s,true);
        std::smatch match;static const std::regex x(R"(\{0[xX]([0-9a-fA-F]+),0[xX]([0-9a-fA-F]+),0[xX]([0-9a-fA-F]+),\{0[xX]([0-9a-fA-F]+),0[xX]([0-9a-fA-F]+),0[xX]([0-9a-fA-F]+),0[xX]([0-9a-fA-F]+),0[xX]([0-9a-fA-F]+),0[xX]([0-9a-fA-F]+),0[xX]([0-9a-fA-F]+),0[xX]([0-9a-fA-F]+)\}\})");
        if(!std::regex_match(compact,match,x))return {};
        s.clear();for(std::size_t i=1;i<match.size();++i){const std::size_t width=i==1?8:i<4?4:2;auto part=match[i].str();const auto start=part.find_first_not_of('0');part=start==part.npos?"0":part.substr(start);if(part.size()>width)return {};s+=std::string(width-part.size(),'0')+part;}
    }
    s=Trim(s);if(s.size()>1&&((s.front()=='{'&&s.back()=='}')||(s.front()=='('&&s.back()==')'))){if(s.size()!=38)return {};s=s.substr(1,s.size()-2);}
    if(std::regex_match(s,std::regex("[0-9a-fA-F]{32}")))s=s.substr(0,8)+'-'+s.substr(8,4)+'-'+s.substr(12,4)+'-'+s.substr(16,4)+'-'+s.substr(20);
    const auto id=NormalGuid(s);return id==zero_guid?std::string{}:id;
}
const std::array<const char*,5> keys={"Press","Down","Up","Combine","Text"};
const std::array<const char*,12> mice={"LeftClick","RightClick","LeftDBClick","RightDBClick","LeftDown","LeftUp","RightDown","RightUp","WheelUp","WheelDown","MoveTo","MoveBy"};
Json Decode64(const std::string& text){
    std::string s;for(char c:text)if(c!=' '&&c!='\r'&&c!='\n'&&c!='\t')s+=c;
    std::vector<std::uint8_t> out;if(s.size()%4)return Json::binary(out);
    auto value=[](char c){return c>='A'&&c<='Z'?c-'A':c>='a'&&c<='z'?c-'a'+26:c>='0'&&c<='9'?c-'0'+52:c=='+'?62:c=='/'?63:-1;};
    for(std::size_t i=0;i<s.size();i+=4){const int a=value(s[i]),b=value(s[i+1]),c=value(s[i+2]),d=value(s[i+3]);
        if(a<0||b<0||(c<0&&s[i+2]!='=')||(d<0&&s[i+3]!='=')||(s[i+2]=='='&&s[i+3]!='=')||((s[i+2]=='='||s[i+3]=='=')&&i+4!=s.size()))return Json::binary(std::vector<std::uint8_t>{});
        out.push_back(static_cast<std::uint8_t>((a<<2)|(b>>4)));if(c>=0){out.push_back(static_cast<std::uint8_t>((b<<4)|(c>>2)));if(d>=0)out.push_back(static_cast<std::uint8_t>((c<<6)|d));}
    }return Json::binary(out);
}
std::string Encode64(const Json& binary){
    if(!binary.is_binary())return {};const auto& b=binary.get_binary();std::string out;
    const char chars[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for(std::size_t i=0;i<b.size();i+=3){const auto a=b[i];const auto c=i+1<b.size()?b[i+1]:0,d=i+2<b.size()?b[i+2]:0;
        out+=chars[a>>2];out+=chars[((a&3)<<4)|(c>>4)];out+=i+1<b.size()?chars[((c&15)<<2)|(d>>6)]:'=';out+=i+2<b.size()?chars[d&63]:'=';}
    return out;
}
// Snapshot identities before mutating. Upstream walks selections in list order,
// including Top's reversal and Down's interaction with adjacent selections.
void Reorder(Json& items,int action,const std::vector<std::string>& picked,const std::function<Json(Json)>& copy){
    for(const auto& id:picked){
        auto it=std::find_if(items.begin(),items.end(),[&](const Json& x){return S(x,"_id")==id;});if(it==items.end())continue;
        const auto index=static_cast<std::size_t>(it-items.begin());auto row=*it;
        if(action==4){if(copy)items.push_back(copy(std::move(row)));continue;}
        if(action!=0&&action!=1&&action!=2&&action!=3&&action!=6)continue;
        if((action==1&&index==0)||(action==2&&index+1==items.size()))continue;
        items.erase(it);if(action==6)continue;
        const auto target=action==0?0:action==1?index-1:action==2?index+1:items.size();
        items.insert(items.begin()+static_cast<Json::difference_type>(target),std::move(row));
    }
}
std::vector<std::string> Pick(const Json& rows,const Json& args,bool indexes){
    std::set<std::string> ids;std::set<int> positions;
    if(indexes){for(const auto& i:args.value("indexes",Json::array()))positions.insert(i.get<int>());}
    else for(const auto& i:args.value("ids",Json::array()))if(i.is_string())ids.insert(Upper(i.get<std::string>()));
    std::vector<std::string> picked;for(std::size_t i=0;i<rows.size();++i)if(indexes?positions.contains(static_cast<int>(i)):ids.contains(Upper(S(rows[i],"_id"))))picked.push_back(S(rows[i],"_id"));return picked;
}
}
bool DataService::NeedsOpenFile(const std::string& method,const Json& args){return method=="importSendCollection"||(method=="storesCommand"&&N(args,"action",-1)==8);}
void DataService::TrimStores(Json& items)const{
    const auto max=N(config_,"StoresLimit_Value",5000);if(!B(config_,"StoresLimit",true)||max<=0)return;
    if(items.size()>static_cast<std::size_t>(max))items.erase(items.begin(),items.begin()+static_cast<Json::difference_type>(items.size()-max));
}
Json* DataService::EditPacket(const std::string& id){if(!send_edit_.is_null())for(auto& item:send_edit_["_children"])if(S(item,"_id")==id)return &item;return nullptr;}
std::string DataService::ValidateInstruction(int type,const std::string& content){
    const auto parts=Fields(content,'|');int a=0,b=0;bool ok=true;std::string error;
    switch(type){
    case 0:{const auto id=ParsedGuid(content);auto row=Find(9,id);ok=row&&!S(*row,"Name").empty();error="SendList";break;}
    case 1:{if(content.find('-')!=content.npos){const auto range=Fields(content,'-');ok=range.size()==2&&Integer(range[0],a)&&Integer(range[1],b)&&a>=0&&b>=a;}else ok=Integer(content,a)&&a>=0;error="Delay";break;}
    case 2:ok=Integer(content,a)&&a>=1;error="LoopINST";break;
    case 7:ok=content=="PacketConfig.List"||content=="FilterSocket"||(parts.size()==2&&parts[0]=="Customize"&&Integer(parts[1],a)&&a>0);error="Socket";break;
    case 8:{ok=parts.size()==3&&(parts[0]=="Enable"||parts[0]=="Disable");
        if(ok){const int list=parts[1]=="SendList"?9:parts[1]=="RobotList"?10:parts[1]=="FilterList"?8:-1;ok=list>=0&&Find(list,ParsedGuid(parts[2]));}error="Switch";break;}
    case 4:ok=parts.size()==2&&std::find(keys.begin(),keys.end(),parts[0])!=keys.end()&&!parts[1].empty();error="KeyBoard";break;
    case 5:{ok=parts.size()==2&&std::find(mice.begin(),mice.end(),parts[0])!=mice.end();
        if(ok&&(parts[0]=="WheelUp"||parts[0]=="WheelDown"))ok=Integer(parts[1],a)&&a>0;
        else if(ok&&(parts[0]=="MoveTo"||parts[0]=="MoveBy")){const auto xy=Fields(parts[1],',');ok=xy.size()==2&&Integer(Trim(xy[0]),a)&&Integer(Trim(xy[1]),b);}error="Mouse";break;}
    default:break;
    }
    if(ok)return {};
    const std::map<std::string,std::string> fallback={{"SendList","发送列表不正确"},{"Delay","延迟时间不正确"},{"LoopINST","循环指令不正确"},{"Socket","系统套接字不正确"},{"Switch","开关指令不正确"},{"KeyBoard","键盘指令不正确"},{"Mouse","鼠标指令不正确"}};
    return Text("RobotEditForm."+error+".Error",fallback.at(error));
}
Json DataService::InstructionRows(){
    Json rows=Json::array();if(robot_edit_.is_null())return rows;
    const std::array<const char*,9> names={"Send","Delay","LoopBegin","LoopEnd","KeyBoard","Mouse","Send","Set","Switch"};
    const std::array<const char*,9> fallback={"发送","延迟","循环开始","循环结束","键盘","鼠标","发送","设置","开关"};
    for(const auto& item:robot_edit_["_children"]){const int type=N(item,"Type");const auto content=S(item,"Content");const auto parts=Fields(content,'|');std::string desc;
        auto tr=[&](const std::string& key,const std::string& def,const std::string& arg){return Fmt(Text("RobotEditForm.INST."+key,def),arg);};
        if(type==0&&!content.empty()){if(!ParsedGuid(content).empty()){auto target=Find(9,ParsedGuid(content));desc=tr("Send.SendList","发送列表 - [{0}]",target?S(*target,"Name"):"");}}
        else if(type==1&&!content.empty())desc=tr("Socket.Millisecond","{0} 毫秒",content);
        else if(type==2&&!content.empty())desc=tr("Loop.Begin","循环 {0} 次",content);
        else if(type==3)desc=tr("Loop.End","循环结束","");
        else if(type==6)desc=tr("PacketList.Select","[封包列表] 选中的封包","");
        else if(type==7){if(content=="PacketConfig.List")desc=tr("Socket.SelectPacket","系统套接字 = 选中封包的套接字","");else if(content=="FilterSocket")desc=tr("Socket.CallFilter","系统套接字 = 调用滤镜的套接字","");else if(content.find("Customize")!=content.npos&&parts.size()>1)desc=tr("Socket.Customize","系统套接字 = {0}",parts[1]);}
        else if(type==8&&parts.size()==3){const int list=parts[1]=="SendList"?9:parts[1]=="RobotList"?10:parts[1]=="FilterList"?8:-1;auto row=list<0?nullptr:Find(list,ParsedGuid(parts[2]));
            if(row){const auto state=parts[0]=="Enable"?Text("Enable","启用"):parts[0]=="Disable"?Text("Disable","禁用"):"";desc=state+" - "+Text(parts[1],list==9?"发送列表":list==10?"机器人列表":"滤镜列表")+" [ "+S(*row,"Name")+" ]";}}
        else if(type==4&&parts.size()>1&&!parts[0].empty()){
            const auto it=std::find(keys.begin(),keys.end(),parts[0]);const auto n=it==keys.end()?0:it-keys.begin();
            const std::array<const char*,5> def={"按键 {0}","按下 {0}","弹起 {0}","组合按键 {0}","输入文本 {0}"};desc=tr("Key"+std::string(keys[n]),def[n],parts[1]);
        }else if(type==5&&parts.size()>1&&!parts[0].empty()){
            const auto it=std::find(mice.begin(),mice.end(),parts[0]);const auto n=it==mice.end()?0:it-mice.begin();
            const std::array<const char*,12> def={"左键单击","右键单击","左键双击","右键双击","左键按下","左键弹起","右键按下","右键弹起","向上滚动 {0}","向下滚动 {0}","移动到 ( {0} )","相对移动 ( {0} )"};desc=tr(mice[n],def[n],parts[1]);
        }
        rows.push_back({{"Index",rows.size()},{"Type",type},{"TypeName",type>=0&&type<9?Text("RobotEditForm.INST."+std::string(names[type]),fallback[type]):""},{"Text",desc},{"Content",content}});
    }return rows;
}
Json DataService::SaveRobot(const Json& args){
    auto error=[&](const std::string& message,int index=-1){return Json{{"error",message},{"badIndex",index}};};
    auto live=robot_edit_.is_null()?nullptr:Find(10,S(robot_edit_,"GUID"));if(!live)return error(Text("RobotEditForm.Gone","这条机器人已经不在列表里了"));
    const auto name=Trim(S(args,"name"));if(name.empty())return error(Text("RobotEditForm.RName.Empty","机器人名称为空"));
    const auto& items=robot_edit_["_children"];std::vector<int> starts,ends;int bad=-1;
    for(std::size_t i=0;i<items.size();++i){const auto type=N(items[i],"Type");if(type==2)starts.push_back(static_cast<int>(i));if(type==3)ends.push_back(static_cast<int>(i));
        if(type==0&&!S(items[i],"Content").empty()){auto target=Find(9,ParsedGuid(S(items[i],"Content")));if(!target||S(*target,"Name").empty()){bad=static_cast<int>(i);break;}}}
    if(bad<0){if(starts.size()!=ends.size())bad=!starts.empty()?starts[0]:ends[0];else for(std::size_t i=0;i<starts.size();++i)if(starts[i]>=ends[i]){bad=ends[i];break;}}
    if(bad>=0){const int type=N(items[bad],"Type");return error(Fmt(Text("RobotEditForm.INST","指令 {0}"),std::to_string(bad+1))+": "+Text(type==2||type==3?"RobotEditForm.LoopINST.Error":"RobotEditForm.SendList.Error",type==2||type==3?"循环指令不正确":"发送列表不正确"),bad);}
    auto next=robot_edit_;next["Name"]=name;next["IsEnable"]=(*live)["IsEnable"];auto rows=lists_[10];for(auto& row:rows)if(row["GUID"]==next["GUID"])row=next;
    SaveList(10,rows);robot_edit_=std::move(next);return error("");
}
std::optional<Json> DataService::CallEditor(const std::string& method,const Json& args){
    if(method=="openRobotEdit"){auto row=Find(10,S(args,"id"));if(!row)return Json{{"Id",""},{"Name",""}};robot_edit_=*row;return Json{{"Id",(*row)["GUID"]},{"Name",(*row)["Name"]}};}
    if(method=="closeRobotEdit"){robot_edit_=nullptr;return Good();}
    if(method=="getRobotInstructions")return Json{{"rows",InstructionRows()}};
    if(method=="addRobotInstruction"){
        if(robot_edit_.is_null())return Json{{"error",Text("RobotEditForm.Gone","这条机器人已经不在列表里了")}};
        const int type=N(args,"type",-1);if(type<0||type>8)return Json{{"error",Text("RobotEditForm.INST.Error","指令类型不正确")}};
        const auto content=Trim(S(args,"content")),error=ValidateInstruction(type,content);if(!error.empty())return Json{{"error",error}};
        auto& items=robot_edit_["_children"];const int at=N(args,"insertAt",-1);auto row=Json{{"_id",Guid()},{"Type",type},{"Content",content}};
        if(at>=0&&static_cast<std::size_t>(at)<items.size())items.insert(items.begin()+at,std::move(row));else items.push_back(std::move(row));return Json{{"error",""}};
    }
    if(method=="saveRobotEdit")return SaveRobot(args);
    if(method=="robotInstructionAction"||method=="sendCollectionAction"){
        const bool robot=method=="robotInstructionAction";auto& edit=robot?robot_edit_:send_edit_;const int action=N(args,"action",-1);
        if(action<0||(!robot&&args.value("ids",Json::array()).empty()))return Json{{"ok",false},{"delta",0}};
        if(edit.is_null())return Json{{"ok",true},{"delta",0}};
        if(!robot&&(action==5||action==8))throw std::runtime_error("尚未实现：发送集动作的导入导出分支，请使用已接通的导入按钮");
        auto& items=edit["_children"];const auto before=static_cast<std::int64_t>(items.size());
        if(action==7)items.clear();else Reorder(items,action,Pick(items,args,robot),robot?std::function<Json(Json)>{}:std::function<Json(Json)>{[&](Json row){row["_id"]=std::to_string(++packet_id_);return row;}});
        return Json{{"ok",true},{"delta",static_cast<std::int64_t>(items.size())-before}};
    }
    if(method=="clearSendCollection"){if(!send_edit_.is_null())send_edit_["_children"]=Json::array();return Good();}
    if(method=="importSendCollection"){
        if(send_edit_.is_null())return Good();const auto path=S(args,"_filePath");if(path.empty())return Good();
        auto imported=RuntimeChildren(ReadEditorXml(std::filesystem::path(std::u8string(path.begin(),path.end())),true),9,packet_id_);auto next=send_edit_;
        for(auto& row:imported)next["_children"].push_back(std::move(row));send_edit_=std::move(next);
        emit_("notify",{{"level",2},{"title",Text("InjectModeForm.ImportSendCollection.Success","导入发送集成功")},{"content",path}});return Good();
    }
    if(method=="openPacketEdit"||method=="savePacketEdit"){
        const auto list=S(args,"list","proxy");if(list!="send")throw std::runtime_error("尚未实现：代理/注入封包来源；本版仅接通发送集封包编辑");
        // JS supplies a number; the original bridge converts it to Int64.
        const auto id=args.value("id",Json(0)).is_string()?S(args,"id"):std::to_string(args.value("id",std::int64_t{0}));auto packet=EditPacket(id);
        if(method=="openPacketEdit")return Json{{"Id",packet?id:""},{"List",packet?"send":""},{"Socket",packet?N(*packet,"Socket"):0},{"Type",packet?N(*packet,"Type"):0},{"From",packet?S(*packet,"IPFrom"):""},{"To",packet?S(*packet,"IPTo"):""},{"Buffer",packet?Encode64((*packet)["Buffer"]):""},{"CanSendBySession",false},{"SystemSocket",0}};
        const auto bytes=Decode64(S(args,"buffer"));if(Size(bytes)==0)return Json{{"error",Text("PacketEditForm.Packet.Empty","封包数据为空")}};
        if(!packet)return Json{{"error",Text("PacketEditForm.Gone","这条封包已经不在列表里了")}};
        (*packet)["Socket"]=N(args,"socket");(*packet)["Buffer"]=bytes;
        // Preserve upstream's observable shallow-copy behavior: the list draft is
        // isolated, but editing a pre-existing PacketInfo changes its aliases in
        // memory, even if the parent dialog is later cancelled. No DB write here.
        for(auto& row:lists_[9])for(auto& child:row["_children"])if(S(child,"_id")==id){child["Socket"]=N(args,"socket");child["Buffer"]=bytes;}
        return Json{{"error",""}};
    }
    if(method=="storesAction"||method=="storesCommand"){
        const int action=N(args,"action",-1);const bool command=method=="storesCommand";
        if(!command&&(action<0||args.value("ids",Json::array()).empty()))return Json{{"ok",false},{"delta",0}};
        auto row=Find(11,S(args,"wid"));if(!row)return command?Good():Json{{"ok",true},{"delta",0}};
        if(action==5||(!command&&action==8))throw std::runtime_error("尚未实现：仓库条目导出");
        auto rows=lists_[11];auto& next=*std::find_if(rows.begin(),rows.end(),[&](const Json& x){return x["GUID"]==(*row)["GUID"];});auto& items=next["_children"];const auto before=static_cast<std::int64_t>(items.size());
        if(command){
            if(action==7)items.clear();else if(action==8){const auto path=S(args,"_filePath");if(path.empty())return Good();for(auto child:ReadEditorXml(std::filesystem::path(std::u8string(path.begin(),path.end())),false)){child["_id"]=Guid();items.push_back(std::move(child));TrimStores(items);}}else return Good();
        }else{
            const auto picked=Pick(items,args,false);
            if(action==4){std::vector<Json> copies;for(const auto& id:picked)for(const auto& child:items)if(S(child,"_id")==id)copies.push_back(child);
                for(auto child:copies){child["_id"]=Guid();items.push_back(std::move(child));TrimStores(items);}}
            else Reorder(items,action,picked,{});
        }
        const auto delta=static_cast<std::int64_t>(items.size())-before;SaveList(11,rows);
        if(command&&action==8)emit_("notify",{{"level",2},{"title",Text("ImportStores.Success","导入仓储数据成功")},{"content",S(args,"_filePath")}});
        return command?Good():Json{{"ok",true},{"delta",delta}};
    }
    return std::nullopt;
}
}
