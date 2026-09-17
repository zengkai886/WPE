#include "shell/data_service.h"
#include "shell/data_worker.h"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>
using namespace wpe::shell;
namespace fs=std::filesystem;
namespace {
int checks=0;
void Require(bool condition,const char* message){++checks;if(!condition)throw std::runtime_error(message);}
template<class F> void Throws(F&& f){bool threw=false;try{f();}catch(const std::exception&){threw=true;}Require(threw,"expected exception");}
Json Call(DataService& service,const std::string& method,Json args=Json::object()){return service.Call(method,args);}
}
int main(int argc,char** argv){
    try{
        const auto dir=fs::current_path()/"data-test"/std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());fs::create_directories(dir);
        const auto file=dir/L"中文持久化.db";std::map<int,Json> feeds;std::string id,sid,wid,accountId;
        auto emit=[&](std::string event,Json data){if(event=="toast")return;Require(event=="feed:replace","wrong feed event");feeds[data.at("list").get<int>()]=data.at("rows");};
        {
            DataService service(file,emit);
            auto prefs=Call(service,"getPrefs");Require(prefs["isDark"]==true&&prefs["scanLine"]==true,"fresh defaults");
            Require(prefs["systemColor"]=="#1677FF","system color differs from original");
            Require(prefs["filter"]["replace"]["fore"]=="#FFB0F8"&&prefs["filter"]["replace"]["back"]=="#4E1C56","replace color differs from original");
            Require(prefs["filter"]["intercept"]["back"]=="#511C2B"&&prefs["filter"]["display"]["fore"]=="#8AEAFF","action colors differ from original");
            Call(service,"setAppearance",{{"mode","system"},{"isDark",false},{"scan",false}});
            Call(service,"setAppearance",{{"isDark",true}});Require(Call(service,"getPrefs")["themeMode"]=="system","partial appearance lost mode");
            for(const auto* language:{"zh-CN","zh-TW","en-US","ja-JP","ko-KR","ru-RU","vi-VN"})Require(Call(service,"setLanguage",{{"language",language}})["language"]==language,"language roundtrip");
            Require(Call(service,"setLanguage",{{"language","zh-HK"}})["language"]=="zh-TW","traditional normalization");
            Require(Call(service,"setLanguage",{{"language","invalid"}})["language"]=="zh-CN","language fallback");
            Call(service,"saveActionColor",{{"action","replace"},{"fore","#112233"},{"back","bad"}});
            auto colors=Call(service,"getPrefs")["filter"];Require(colors["replace"]["fore"]=="#112233"&&colors["replace"]["back"]=="#4E1C56","partial color update");
            auto settings=Call(service,"getLogSetting");Require(Call(service,"saveLogSetting",{{"autoClear",false},{"autoClearValue",99}})["ok"]==false,"invalid limit accepted");
            Require(Call(service,"getLogSetting")==settings,"invalid save partially changed state");
            Call(service,"saveLogSetting",{{"autoClearValue",1234}});Call(service,"saveLogSetting",{{"autoClear",false}});Require(Call(service,"getLogSetting")["autoClearValue"]==1234,"partial log save");
            Call(service,"saveSystemSetting",{{"speedMode",true},{"listExecute",0},{"filterExecute",1}});
            Call(service,"enterProxyMode");Require(feeds[8].empty(),"fresh filter list");Require(Call(service,"getStats")["proxyRunning"]==false,"proxy falsely running");
            Require(feeds.contains(5)&&feeds[5].empty(),"fresh account feed");
            Require(Call(service,"saveAccount",{{"userName"," 账号持久化 "},{"password"," P@ss'中 "},{"isEnable",true},{"isLimitLinks",true},{"limitLinks",3},{"isLimitDevices",false},{"limitDevices",7},{"isExpiry",true},{"expiryTime","2030-01-02 03:04:05"}})["ok"]==true,"account save");
            Require(feeds[5].size()==1&&!feeds[5][0].contains("PassWord")&&feeds[5][0]["LoginCount"]==0,"account feed shape or secret leak");
            accountId=feeds[5][0]["Id"].get<std::string>();Require(Call(service,"getAccountPassword",{{"id",accountId}})["password"]=="P@ss'中","account password mapping");
            Require(Call(service,"setAccountEnable",{{"id",accountId},{"enable",false}})["ok"]==true&&feeds[5][0]["IsEnable"]==false,"account enable");
            Require(Call(service,"adjustAccountLimit",{{"ids",Json::array({accountId})},{"devices",true},{"on",true},{"value",2}})["count"]==1&&feeds[5][0]["LimitDevices"]==2,"account device adjustment");
            Require(Call(service,"adjustAccountExpiry",{{"ids",Json::array({accountId})},{"addType",0},{"hours",25}})["count"]==1&&feeds[5][0]["ExpiryTime"]=="2030-01-03 04:04:05","account expiry adjustment");
            id=Call(service,"addFilter")["id"].get<std::string>();Require(feeds[8].size()==1&&feeds[8][0]["Id"]==id,"new filter not pushed");
            auto row=Call(service,"getFilterEdit",{{"id",id}})["row"];
            Require(row["Name"]=="滤镜 1"&&row["FunctionMask"]==4095&&row["ExecuteType"]==2,"original new filter defaults");
            auto whitespace=row;whitespace["Name"]="　 ";
            Require(Call(service,"saveFilterEdit",{{"row",whitespace}})["ok"]==false,"Unicode whitespace name must be rejected like .NET Trim");
            row["Name"]="  '); DROP TABLE Filter; -- 中文  ";row["Mode"]=1;row["StartFrom"]=1;
            row["Modify"]=Json::array({{{"Index",-1000},{"Value"," AA "},{"Progression",true},{"Random",true}},{{"Index",-1},{"Value",""},{"Random",true}}});
            row["Search"]=Json::array({{{"Index",0},{"Value"," FF "},{"Exclude",true}},{{"Index",-1},{"Value","AB"}}});
            Require(Call(service,"saveFilterEdit",{{"row",row}})["ok"]==true,"filter save");
            auto back=Call(service,"getFilterEdit",{{"id",id}})["row"];Require(back["Modify"][0]["Index"]==-1000&&back["Modify"][0]["Random"]==false,"negative offset or flag precedence");
            Require(back["Search"].size()==1&&back["Search"][0]["Value"]=="FF","search normalization");
            auto invalid=back;invalid["AppointSocket"]=true;invalid["SocketContent"]="1-3";Require(Call(service,"saveFilterEdit",{{"row",invalid}})["ok"]==false,"invalid socket accepted");
            Require(Call(service,"getFilterEdit",{{"id",id}})["row"]==back,"invalid save mutated filter");
            Call(service,"setFilterEnable",{{"id",id},{"enable",true}});Require(feeds[8][0]["IsEnable"]==true,"enable not pushed");
            Require(Call(service,"setAllFilterEnable",{{"enable",true}})["count"]==0,"all-enable counts only changes");
            Require(Call(service,"setAllFilterEnable",{{"enable",false}})["count"]==1,"all-disable count");
            Call(service,"filterListAction",{{"action",4},{"ids",Json::array({id})}});Require(feeds[8].size()==2&&feeds[8][1]["IsEnable"]==false,"copy enabled unexpectedly");
            Require(feeds[8][1]["Name"].get<std::string>().ends_with(" - 副本"),"copy name");
            const auto copy=feeds[8][1]["Id"];
            Call(service,"filterListAction",{{"action",0},{"ids",Json::array({id,copy})}});Require(feeds[8][0]["Id"]==copy,"original Top multi-selection reversal");
            Call(service,"filterListAction",{{"action",6},{"ids",Json::array({copy})}});Require(feeds[8].size()==1,"delete");
            Require(Call(service,"setFilterEnable",{{"id","missing"},{"enable",true}})["ok"]==false,"missing ID succeeded");
            sid=Call(service,"addSend")["id"].get<std::string>();auto send=Call(service,"openSendEdit",{{"id",sid}});Require(send["LoopCount"]==1&&send["LoopInterval"]==1000,"send defaults");
            Call(service,"setSendEnable",{{"id",sid},{"enable",true}});
            Require(Call(service,"saveSendEdit",{{"name","序列 中文"},{"loopCount",0},{"loopInterval",-1},{"notes"," note "}})["error"]=="","send save");
            Require(feeds[9][0]["IsEnable"]==true&&feeds[9][0]["LoopCount"]==1&&feeds[9][0]["LoopInterval"]==0,"send edit toggle or range");Call(service,"closeSendEdit");
            Require(Call(service,"saveSendEdit",{{"name","lost"}})["error"]!="","closed edit accepted");
            auto robot=Call(service,"addRobot")["id"];Require(feeds[10][0]["InstructionCount"]==0,"new robot");
            Require(Call(service,"getExecuteTargets",{{"type",1},{"excludeId",robot}})["items"].empty(),"execute target exclusion");
            wid=Call(service,"addWareHouse")["id"].get<std::string>();Call(service,"saveWareHouseName",{{"wid",wid},{"name","仓库持久化"}});Require(feeds[11][0]["Name"]=="仓库持久化","warehouse feed");
            Require(Call(service,"getStoreRows",{{"wid",wid}})["rows"].empty(),"warehouse should be empty");
            Throws([&]{Call(service,"startProxy");});Require(Call(service,"filterListAction",{{"action",5},{"ids",Json::array({id})}})["ok"]==true,"cancelled filter export should preserve original successful cancellation");
        }
        {
            DataService reopened(file,emit);Call(reopened,"enterProxyMode");
            Require(feeds[8].size()==1&&feeds[8][0]["Id"]==id,"filter restart persistence");
            Require(Call(reopened,"getFilterEdit",{{"id",id}})["row"]["Modify"][0]["Index"]==-1000,"offset persistence");
            Require(feeds[9][0]["Name"]=="序列 中文"&&feeds[11][0]["Name"]=="仓库持久化","collection persistence");
            Require(feeds[5].size()==1&&feeds[5][0]["Id"]==accountId&&feeds[5][0]["UserName"]=="账号持久化"&&feeds[5][0]["LimitDevices"]==2,"account restart persistence");
            Require(Call(reopened,"getAccountPassword",{{"id",accountId}})["password"]=="P@ss'中"&&Call(reopened,"getAccountLogins",{{"id",accountId}})["rows"].empty(),"account secret/login restart persistence");
            Require(Call(reopened,"getPrefs")["themeMode"]=="system"&&Call(reopened,"getPrefs")["scanLine"]==false,"appearance persistence");
        }
        {Database schema(file);const auto tables=schema.Query("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('ProxyAccount','ProxyAccountIPInfo')");Require(tables.size()==2,"account schema tables missing");}
        {
            Database db(dir/"rollback.db");db.Execute("CREATE TABLE test (id TEXT PRIMARY KEY,value BLOB)");
            const Json original=Json::array({{{"id","keep"},{"value",Json::binary({0,255,128})}}});
            db.Transaction([&]{db.Replace("test",original);});
            Throws([&]{db.Transaction([&]{db.Replace("test",Json::array({{{"id","duplicate"}},{{"id","duplicate"}}}));});});
            Require(db.Query("SELECT * FROM test")==original,"failed replacement lost old data");
            db.Execute("INSERT INTO test VALUES (?,?)",Json::array({"empty",Json::binary({})}));
            Require(db.Query("SELECT value FROM test WHERE id='empty'")[0]["value"].is_binary(),"empty blob became null");
        }
        {
            Database db(file);
            db.Execute("INSERT INTO WareHouseData (GUID,Buffer) VALUES (?,?)",Json::array({wid,Json::binary({0,255,128})}));
            db.Execute("INSERT INTO WareHouseData (GUID,Buffer) VALUES (?,?)",Json::array({wid,Json::binary(std::vector<std::uint8_t>(61,0xAB))}));
            db.Execute("INSERT INTO WareHouseData (GUID,Buffer) VALUES (?,?)",Json::array({wid,Json::binary({})}));
        }
        {
            DataService service(file,emit);auto rows=Call(service,"getStoreRows",{{"wid",wid}})["rows"];
            Require(rows.size()==3&&rows[0]["Len"]==3&&rows[0]["Preview"]=="","warehouse rows with bytes");
            auto previews=Call(service,"getStorePreviews",{{"wid",wid},{"from",-1},{"count",100}})["items"];
            Require(previews[0]=="00 FF 80","preview must be string, not row DTO");
            Require(previews[1].get<std::string>().ends_with(" ...")&&previews[1].get<std::string>().size()==183,"original preview truncation suffix");
            Require(previews[2]=="","empty warehouse preview");
            Require(Call(service,"copyStoresHex",{{"wid",wid},{"ids",Json::array({rows[0]["Id"],rows[2]["Id"]})}})["text"]=="00 FF 80\r\n\r\n","copy must preserve original CRLF, including empty rows");
        }
        if(argc>1){
            std::ifstream input(argv[1]);const auto fixture=Json::parse(input);DataService service(dir/"oracle-parity.db",emit);const auto fid=Call(service,"addFilter")["id"];
            for(const auto& example:fixture.at("cases")){
                auto row=example.at("input");row["Id"]=fid;auto result=Call(service,"saveFilterEdit",{{"row",row}});
                Require(result.at("ok")==example.at("ok"),"original C# validation differs");
                auto after=Call(service,"getFilterEdit",{{"id",fid}})["row"];after["Id"]="ID";
                if(after!=example.at("after")){std::cerr<<after.dump(2)<<"\nEXPECTED\n"<<example.at("after").dump(2)<<'\n';throw std::runtime_error("original C# edit DTO differs");}++checks;
            }
            Require(fixture.at("cases").size()==120,"oracle cases missing");
        }
        {
            DataWorker worker(dir/"worker.db");int completed=0;const auto ui=std::this_thread::get_id();
            worker.Submit("addFilter",{},[&](Json r,std::string error){Require(error.empty()&&r.contains("id"),"worker result");Require(std::this_thread::get_id()==ui,"completion off UI thread");++completed;});
            worker.Submit("getExecuteTargets",{{"type",3}},[&](Json r,std::string error){Require(error.empty()&&r["items"].size()==1,"worker FIFO");++completed;});
            const auto until=std::chrono::steady_clock::now()+std::chrono::seconds(5);
            while(completed<2&&std::chrono::steady_clock::now()<until){worker.Drain(emit);std::this_thread::sleep_for(std::chrono::milliseconds(2));}Require(completed==2,"worker stalled");
        }
        Require(DataService::NeedsConfirmation("clearFilters",{}),"clear confirmation");
        Require(DataService::NeedsConfirmation("filterListAction",{{"action",6}}),"delete confirmation");
        Require(!DataService::NeedsConfirmation("filterListAction",{{"action",4}}),"copy must not confirm");
        std::cout<<"PASS: "<<checks<<" data checks; original C# fixtures, persistent SQLite, rollback, feeds, worker FIFO; isolated files: "<<dir.string()<<'\n';return 0;
    }catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<'\n';return 1;}
}
