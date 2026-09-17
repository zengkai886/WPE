#include "shell/web_bridge.h"
#include <iostream>
#include <stdexcept>

int main() {
    using wpe::shell::Json;
    using wpe::shell::WebBridge;
    try {
        std::vector<Json> sent;
        WebBridge bridge([&](const std::string& text){sent.push_back(Json::parse(text));});
        auto check=[](bool ok){if(!ok)throw std::runtime_error("Bridge contract failure");};
        bridge.Register("echo",[](const Json& args){return args;});
        bridge.Receive("https://app.wpe64.local/index.html",R"({"type":"call","id":"c1","method":"EcHo","args":{"v":"中文"}})");
        check(sent.back()==Json({{"type","result"},{"id","c1"},{"ok",true},{"result",{{"v","中文"}}}}));
        bridge.Receive("https://app.wpe64.local/",R"({"type":"call","id":"c2","method":"notImplemented"})");
        check(sent.back()["ok"]==false && sent.back().contains("error"));
        const auto before=sent.size();
        for(const auto& origin:{"http://app.wpe64.local/","https://app.wpe64.local.evil/","https://app.wpe64.local@evil/","file:///index.html","https://app.wpe64.local:8443/"})
            bridge.Receive(origin,R"({"type":"call","id":"bad","method":"echo"})");
        check(sent.size()==before);
        bridge.Receive("https://app.wpe64.local/","{"); check(sent.size()==before);
        bridge.Receive("https://app.wpe64.local/",R"({"type":"call","id":"bad-args","method":"echo","args":[]})");
        check(sent.back()["ok"]==false);
        int answers=0; Json result;
        auto id=bridge.Ask("confirm",{{"title","test"}},[&](Json value){++answers;result=value;});
        check(sent.back()["type"]=="ask" && sent.back()["id"]==id);
        const auto answer=Json({{"type","answer"},{"id",id},{"ok",true},{"result",true}}).dump();
        bridge.Receive("https://app.wpe64.local/",answer);bridge.Receive("https://app.wpe64.local/",answer);
        check(answers==1 && result==true && bridge.PendingCount()==0);
        bridge.Ask("prompt",Json::object(),[&](Json value){++answers;result=value;},std::chrono::milliseconds(0));
        bridge.Tick(WebBridge::Clock::now()+std::chrono::seconds(1));
        check(answers==2 && result.is_null() && bridge.PendingCount()==0);
        bridge.Ask("confirm",Json::object(),[&](Json value){++answers;result=value;});
        bridge.FailAllPending();check(answers==3 && result.is_null());
        bridge.PushEvent("busy",{{"on",true}});
        check(sent.back()==Json({{"type","event"},{"name","busy"},{"data",{{"on",true}}}}));
        bridge.Register("fail",[](const Json&) -> Json{throw std::runtime_error("intentional");});
        bridge.Receive("https://app.wpe64.local/",R"({"type":"call","id":"e","method":"fail"})");
        check(sent.back()["error"]=="intentional");
        WebBridge broken([](const std::string&){throw std::runtime_error("closed transport");});
        broken.Ask("confirm",{},[&](Json value){++answers;result=value;});
        check(answers==4 && result.is_null() && broken.PendingCount()==0);
        std::cout<<"PASS: five bridge message types, origins, errors, timeout, cancellation, duplicate answer and failed transport\n";
        return 0;
    }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
