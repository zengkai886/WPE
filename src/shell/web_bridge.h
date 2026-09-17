#pragma once
#include <nlohmann/json.hpp>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <string>

namespace wpe::shell {
using Json=nlohmann::json;
// UI-thread confined. The host marshals worker notifications to its message loop.
// No handler may block waiting for Ask; its completion runs on this same thread.
class WebBridge {
public:
    using Clock=std::chrono::steady_clock;
    using Post=std::function<void(const std::string&)>;
    using Handler=std::function<Json(const Json&)>;
    using Answer=std::function<void(Json)>;
    using Completion=std::function<void(Json,std::string)>;
    using AsyncHandler=std::function<void(const Json&,Completion)>;
    explicit WebBridge(Post post);
    ~WebBridge();
    WebBridge(const WebBridge&)=delete;
    WebBridge& operator=(const WebBridge&)=delete;
    static bool IsAllowedSource(std::string_view source);
    void Register(std::string method,Handler handler);
    // Completion must be delivered on the UI thread; late/duplicate completions
    // are ignored after navigation, shutdown, or their first result.
    void RegisterAsync(std::string method,AsyncHandler handler);
    void Receive(std::string_view source,std::string_view raw);
    std::string Ask(std::string method,Json args,Answer answer,std::chrono::milliseconds timeout=std::chrono::minutes(5));
    // Unlike legacy Ask, a transport failure is distinct from a successful null answer.
    std::string AskResult(std::string method,Json args,Completion answer,std::chrono::milliseconds timeout=std::chrono::minutes(5));
    void PushEvent(std::string name,Json data);
    // Optional UI notification must never prevent the RPC result. Navigation
    // invalidates the notification along with the originating call.
    Completion WithErrorToast(Completion done);
    void Tick(Clock::time_point now=Clock::now());
    void FailAllPending();
    std::size_t PendingCount() const noexcept{return pending_.size();}
private:
    struct Pending {Clock::time_point deadline;Completion complete;};
    void Reply(const Json& id,bool ok,Json value,const std::string& error={});
    void Complete(const std::string& id,Json value,std::string error={});
    static std::string Key(std::string value);
    Post post_;
    std::map<std::string,AsyncHandler> methods_;
    std::map<std::string,Pending> pending_;
    std::uint64_t sequence_{};
    bool closed_{};
    bool cancelling_{};
    std::shared_ptr<int> call_epoch_=std::make_shared<int>(0);
};
} // namespace wpe::shell
