#include "shell/data_service.h"
#include "shell/editor_xml.h"
#include <chrono>
#include <fstream>
#include <iostream>
using namespace wpe::shell;
namespace fs=std::filesystem;
namespace {
int checks=0;
void Require(bool condition,const std::string& message){++checks;if(!condition)throw std::runtime_error(message);}
std::string Utf8(const fs::path& path){auto s=path.u8string();return std::string(s.begin(),s.end());}
void Replace(std::string& value,const std::string& from,const std::string& to){std::size_t at=0;while((at=value.find(from,at))!=value.npos){value.replace(at,from.size(),to);at+=to.size();}}
class Aliases {
    std::map<std::string,std::string> values_;
public:
    Json Normalize(Json value,const std::string& key={}){
        if(value.is_object()){for(auto it=value.begin();it!=value.end();++it)it.value()=Normalize(it.value(),it.key());}
        else if(value.is_array())for(auto& v:value)v=Normalize(v,key);
        else if(value.is_string()){
            auto s=value.get<std::string>();if((key=="Id"||key=="id")&&!s.empty()){if(!values_.contains(s))values_[s]="$id"+std::to_string(values_.size()+1);return Json(values_[s]);}
            std::vector<std::pair<std::string,std::string>> pairs(values_.begin(),values_.end());std::sort(pairs.begin(),pairs.end(),[](const auto& a,const auto& b){return a.first.size()>b.first.size();});
            for(const auto& [from,to]:pairs){if(from.size()<32)continue;Replace(s,from,to);auto lower=from;for(auto& c:lower)if(c>='A'&&c<='Z')c=static_cast<char>(c+32);Replace(s,lower,to);}value=s;
        }return value;
    }
    Json Resolve(const Json& value){
        auto text=value.dump();std::vector<std::pair<std::string,std::string>> pairs(values_.begin(),values_.end());std::sort(pairs.begin(),pairs.end(),[](const auto& a,const auto& b){return a.second.size()>b.second.size();});
        for(const auto& [to,from]:pairs)Replace(text,from,to);return Json::parse(text);
    }
};
template<class F> void Throws(F&& action){bool threw=false;try{action();}catch(const std::exception&){threw=true;}Require(threw,"expected import/database error");}
void Write(const fs::path& file,const std::string& text){std::ofstream out(file,std::ios::binary);out<<text;if(!out)throw std::runtime_error("cannot write isolated fixture");}
}
int main(int argc,char** argv){try{
    if(argc!=2)throw std::runtime_error("fixture directory required");const fs::path fixtures=fs::path(argv[1]);
    const auto dir=fs::current_path()/"editor-test"/std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());fs::create_directories(dir);
    Json golden;{std::ifstream input(fixtures/"editor-sequence.json");input>>golden;}
    DataService service(dir/"oracle.db",[](std::string,Json){});Aliases aliases;std::size_t index=0;
    for(const auto& item:golden["cases"]){
        const auto method=item.at("method").get<std::string>();auto args=aliases.Resolve(item.at("args"));
        if(method=="importSendCollection")args["_filePath"]=Utf8(fixtures/"editor-send.sc");
        if(method=="storesCommand"&&args.value("action",-1)==8)args["_filePath"]=Utf8(fixtures/"editor-stores.whs");
        const auto actual=aliases.Normalize(service.Call(method,args));
        if(actual!=item["result"]){Write(dir/"actual.json",actual.dump(2));Write(dir/"expected.json",item["result"].dump(2));throw std::runtime_error("C# parity case "+std::to_string(index)+" "+method+"; files "+dir.string()+"; actual="+actual.dump()+" expected="+item["result"].dump());}
        ++checks;++index;
    }
    const auto db=dir/L"中文编辑.db";std::string sid,rid,wid;
    auto call=[](DataService& s,const std::string& name,Json args=Json::object()){return s.Call(name,args);};
    {
        std::map<int,Json> feeds;int notifications=0;DataService s(db,[&](std::string name,Json data){if(name=="notify"){Require(data["level"]==2&&!data["title"].get<std::string>().empty()&&!data["content"].get<std::string>().empty(),"import notification");++notifications;return;}Require(name=="feed:replace","unexpected feed");feeds[data["list"].get<int>()]=data["rows"];});
        sid=call(s,"addSend")["id"];rid=call(s,"addRobot")["id"];wid=call(s,"addWareHouse")["id"];
        call(s,"openSendEdit",{{"id",sid}});call(s,"importSendCollection",{{"_filePath",Utf8(fixtures/"editor-send.sc")}});
        Require(call(s,"getSendCollection")["rows"].size()==3,"send import rows");Require(feeds[9][0]["PacketCount"]==0,"draft import mutated parent");
        call(s,"closeSendEdit");call(s,"openSendEdit",{{"id",sid}});Require(call(s,"getSendCollection")["rows"].empty(),"cancel did not discard imported draft");
        call(s,"importSendCollection",{{"_filePath",Utf8(fixtures/"editor-send.sc")}});call(s,"saveSendEdit",{{"name","持久化发送"},{"loopCount",2},{"loopInterval",7}});
        auto first=call(s,"getSendCollection")["rows"][0]["Id"];Require(call(s,"savePacketEdit",{{"list","send"},{"id",first},{"socket",99},{"buffer","gP8="}})["error"]=="","packet save");
        call(s,"saveSendEdit",{{"name","持久化发送"},{"loopCount",2},{"loopInterval",7}});
        call(s,"openRobotEdit",{{"id",rid}});
        std::string compact;for(char c:sid)if(c!='-')compact+=c;
        std::string x="{0x00"+compact.substr(0,8)+",0x"+compact.substr(8,4)+",0x"+compact.substr(12,4)+",{";
        for(std::size_t i=16;i<32;i+=2){if(i!=16)x+=',';x+="　0x00"+compact.substr(i,2);}x+="}}";
        for(const auto& text:{sid,compact,"{"+sid+"}","("+sid+")",x})Require(call(s,"addRobotInstruction",{{"type",0},{"content",text}})["error"]=="","valid Guid.TryParse form rejected");
        for(const auto& text:{"{"+compact+"}","("+compact+")"})Require(call(s,"addRobotInstruction",{{"type",0},{"content",text}})["error"]!="","bracketed N GUID accepted");
        call(s,"addRobotInstruction",{{"type",1},{"content","　25 "}});call(s,"closeRobotEdit");call(s,"openRobotEdit",{{"id",rid}});
        Require(call(s,"getRobotInstructions")["rows"].empty(),"robot cancel changed parent");
        call(s,"addRobotInstruction",{{"type",2},{"content","3"}});call(s,"addRobotInstruction",{{"type",1},{"content","25"}});
        Require(call(s,"saveRobotEdit",{{"name","bad"}})["badIndex"]==0,"unclosed loop bad index");
        call(s,"addRobotInstruction",{{"type",3},{"content",""}});call(s,"setRobotEnable",{{"id",rid},{"enable",true}});
        {Database locked(db);locked.Execute("BEGIN IMMEDIATE");Throws([&]{call(s,"saveRobotEdit",{{"name","持久化机器人"}});});locked.Execute("ROLLBACK");}
        Require(feeds[10][0]["InstructionCount"]==0,"failed save changed parent");Require(call(s,"getRobotInstructions")["rows"].size()==3,"failed save destroyed draft");
        Require(call(s,"saveRobotEdit",{{"name","持久化机器人"}})["error"]=="","robot save");Require(feeds[10][0]["IsEnable"]==true,"save lost live enable flag");
        call(s,"storesCommand",{{"wid",wid},{"action",8},{"_filePath",Utf8(fixtures/"editor-stores.whs")}});auto rows=call(s,"getStoreRows",{{"wid",wid}})["rows"];
        call(s,"storesAction",{{"wid",wid},{"action",6},{"ids",Json::array({rows[1]["Id"]})}});Require(feeds[11][0]["DataCount"]==2,"warehouse count feed");
        const auto before=call(s,"getSendCollection");const auto invalid=dir/"invalid.sc";
        Write(invalid,"<SendCollection><Collection><Socket>3</Socket><Buffer>AA</Buffer></Collection><Collection><Socket>bad</Socket><Buffer>BB</Buffer></Collection></SendCollection>");
        Throws([&]{call(s,"importSendCollection",{{"_filePath",Utf8(invalid)}});});Require(call(s,"getSendCollection")==before,"bad import partially changed draft");
        Write(invalid,"<!DOCTYPE Stores [<!ENTITY x SYSTEM 'file:///not-read'>]><Stores><Data><PacketData>&x;</PacketData></Data></Stores>");Throws([&]{ReadEditorXml(invalid,false);});
        Write(invalid,"<Stores>");Throws([&]{ReadEditorXml(invalid,false);});
        Write(invalid,"<SendCollection><Collection><Type>123invalid</Type><Buffer>AA</Buffer></Collection></SendCollection>");Require(ReadEditorXml(invalid,true)[0]["Type"]==0,"invalid type numeric prefix accepted");
        Require(notifications==3,"missing or duplicate successful import notifications");
        const auto large=dir/"large.whs";{std::ofstream f(large,std::ios::binary);f<<"<Stores>";const std::string padding(1024*1024,' ');for(int i=0;i<65;++i)f<<padding;f<<"<Data><PacketData>AB</PacketData></Data></Stores>";if(!f)throw std::runtime_error("large XML fixture write failed");}
        auto largeRows=ReadEditorXml(large,false);Require(largeRows.size()==1&&largeRows[0]["Buffer"]==Json::binary(std::vector<std::uint8_t>{0xAB}),"large valid XML import rejected");
        Require(DataService::NeedsConfirmation("robotInstructionAction",{{"action",7}}),"robot clear confirmation missing");Require(!DataService::NeedsConfirmation("robotInstructionAction",{{"action",6}}),"robot item delete added extra confirmation");
        Require(!DataService::NeedsConfirmation("storesAction",{{"action",6}}),"store item delete added extra confirmation");Require(DataService::NeedsOpenFile("storesCommand",{{"action",8}}),"import chooser missing");
    }
    {DataService s(db,[](std::string,Json){});call(s,"openSendEdit",{{"id",sid}});auto first=call(s,"getSendCollection")["rows"][0];Require(first["Socket"]==99&&first["Preview"]=="80 FF","packet DB roundtrip");
        call(s,"openRobotEdit",{{"id",rid}});auto instructions=call(s,"getRobotInstructions")["rows"];Require(instructions.size()==3&&instructions[1]["Content"]=="25","instruction DB roundtrip");
        Require(call(s,"getStoreRows",{{"wid",wid}})["rows"].size()==2,"warehouse mutation did not persist");}
    std::cout<<"PASS: "<<checks<<" editor checks; "<<index<<" original C# calls; XML, drafts, packet aliases, rollback and reopen; "<<dir.string()<<'\n';return 0;
}catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<'\n';return 1;}}
