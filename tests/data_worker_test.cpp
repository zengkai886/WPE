#include "shell/data_worker.h"
#include <chrono>
#include <filesystem>
#include <iostream>
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
        auto worker=std::make_unique<DataWorker>(root/"locked.db");bool ready=false;
        worker->Submit("getPrefs",{},[&](Json,std::string error){Require(error.empty(),"worker init");ready=true;});Pump(*worker,[&]{return ready;});
        Database lock(root/"locked.db");lock.Execute("BEGIN IMMEDIATE");int cancelled=0;
        for(int i=0;i<3;++i)worker->Submit("setLanguage",{{"language","en-US"}},[&](Json,std::string error){if(error.find("取消")!=error.npos)++cancelled;});
        std::this_thread::sleep_for(30ms);auto started=std::chrono::steady_clock::now();worker.reset();
        auto elapsed=std::chrono::steady_clock::now()-started;
        Require(elapsed<2200ms,"shutdown drained queued SQLite lock waits");Require(cancelled>=2,"unstarted jobs not cancelled");lock.Execute("ROLLBACK");
        std::cout<<"shutdownMs="<<std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()<<", cancelled="<<cancelled<<'\n';
    }
    std::cout<<"PASS: worker shutdown queue cancellation, emit failure isolation and completion exception isolation\n";return 0;
}catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<'\n';return 1;}}
