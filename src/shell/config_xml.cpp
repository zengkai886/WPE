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
}
XmlNode SystemConfigXml(const Json& config){XmlNode root("SystemConfig");for(const auto& f:systemFields)root.nodes.push_back(Field(f,config,true));return root;}
Json ParseSystemConfig(const XmlNode& node,const Json& current){auto next=current;ReadFields(next,node,systemFields);return next;}
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
