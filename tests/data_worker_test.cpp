#include "shell/data_worker.h"
#include "common/ipc_codec.h"
#include "common/ipc_protocol.h"
#include <chrono>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <thread>
using namespace wpe::shell;
using namespace std::chrono_literals;
namespace {
void Require(bool value,const char* error){if(!value)throw std::runtime_error(error);}
template<class F> void Pump(DataWorker& worker,F predicate,const DataService::Emit& emit=[](std::string,Json){}){
    auto until=std::chrono::steady_clock::now()+5s;
    while(!predicate()&&std::chrono::steady_clock::now()<until){worker.Drain(emit);std::this_thread::sleep_for(2ms);}
    Require(predicate(),"worker deadline exceeded");
}
}
int main(){try{
    const auto root=std::filesystem::current_path()/"worker-test"/std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    {
        DataWorker worker(root/"emit.db");int done=0,errors=0;
        worker.Submit("addFilter",{},[&](Json,std::string error){++done;if(!error.empty())++errors;});
        worker.Submit("getPrefs",{},[&](Json result,std::string error){++done;Require(error.empty()&&result.contains("language"),"later result lost");});
        Pump(worker,[&]{return done==2;},[](std::string,Json){throw std::runtime_error("transport closed");});
        Require(errors==1,"committed write must report failed feed delivery");
        worker.Submit("getPrefs",{},[](Json,std::string){throw std::runtime_error("consumer failed");});
        worker.Submit("getPrefs",{},[&](Json,std::string){++done;});Pump(worker,[&]{return done==3;});
    }
    {
        DataWorker worker(root/"target-events.db");std::string wid;bool stored=false;int done=0;
        worker.Submit("addWareHouse",{},[&](Json value,std::string error){
            Require(error.empty(),"warehouse setup for target event");wid=value.at("id").get<std::string>();
            wpe::IpcWriter writer;writer.U8(static_cast<std::uint8_t>(wpe::IpcEvent::StoreAdded));
            writer.Guid_(wpe::Guid::Parse(wid));writer.Bytes(wpe::Bytes{std::vector<std::uint8_t>{0xAA,0xBB}});
            worker.SubmitStoreEvent(writer.ToArray(),[&](Json result,std::string eventError){
                Require(eventError.empty()&&result["stored"]==true,"target event was not committed");stored=true;++done;});
        });
        Pump(worker,[&]{return stored;});
        worker.Submit("getStoreRows",{{"wid",wid}},[&](Json result,std::string error){
            Require(error.empty()&&result["rows"].size()==1&&result["rows"][0]["Len"]==2,"target event warehouse feed");++done;});
        Pump(worker,[&]{return done==2;});
    }
    {
        auto worker=std::make_unique<DataWorker>(root/"locked.db");bool ready=false;
        worker->Submit("getPrefs",{},[&](Json,std::string error){Require(error.empty(),"worker init");ready=true;});Pump(*worker,[&]{return ready;});
        Database lock(root/"locked.db");lock.Execute("BEGIN IMMEDIATE");int cancelled=0;
        for(int i=0;i<3;++i)worker->Submit("setLanguage",{{"language","en-US"}},[&](Json,std::string error){if(error.find("取消")!=error.npos)++cancelled;});
        std::this_thread::sleep_for(30ms);auto started=std::chrono::steady_clock::now();worker.reset();
        auto elapsed=std::chrono::steady_clock::now()-started;
        Require(elapsed<2200ms,"shutdown drained queued SQLite lock waits");Require(cancelled>=2,"unstarted jobs not cancelled");lock.Execute("ROLLBACK");
        std::cout<<"shutdownMs="<<std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()<<", cancelled="<<cancelled<<'\n';
    }
    {
        auto worker=std::make_unique<DataWorker>(root/"export.db");Json id;bool ready=false;
        worker->Submit("addSend",{},[&](Json value,std::string error){Require(error.empty(),"create export draft");id=value["id"];ready=true;});Pump(*worker,[&]{return ready;});
        const auto input=root/"pending.sc",marker=root/"marker.sc";
        {std::ofstream f(input);f<<"<SendCollection><Collection><Socket>17</Socket><Buffer>AA BB</Buffer></Collection></SendCollection>";}
        const auto path=[](const std::filesystem::path& p){const auto u=p.u8string();return std::string(u.begin(),u.end());};
        worker->Submit("openSendEdit",{{"id",id}},[](Json,std::string){});
        worker->Submit("importSendCollection",{{"_filePath",path(input)}},[](Json,std::string){});
        bool token=false,ownerNull=false;
        worker->Submit("__prepareEditorExport",{{"method","exportSendCollection"},{"args",Json::object()}},[&](Json plan,std::string error){
            token=error.empty()&&plan.contains("token");ownerNull=!worker;
            // Same owner-lifetime guard as Host::DiscardExport: the worker's
            // service already owns destruction of its plans during reset().
            if(worker&&token)worker->ForgetExportPlan(plan["token"].get<std::string>());
        });
        worker->Submit("exportSendCollection",{{"_filePath",path(marker)}},[](Json,std::string){});
        const auto deadline=std::chrono::steady_clock::now()+5s;while(!std::filesystem::exists(marker)&&std::chrono::steady_clock::now()<deadline)std::this_thread::sleep_for(2ms);
        Require(std::filesystem::exists(marker),"undrained export worker deadline");worker.reset();Require(token&&ownerNull,"pending export completion was not tested during reset");
    }
    std::cout<<"PASS: worker shutdown queue cancellation, emit/completion isolation and undrained export token cleanup during owner reset\n";return 0;
}catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<'\n';return 1;}}
