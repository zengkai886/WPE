#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <windowsx.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <shlwapi.h>
#include <dwmapi.h>
#include <wrl.h>
#include <WebView2.h>
#include "web_bridge.h"
#include "data_worker.h"
#include "clipboard_worker.h"
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <deque>

using Microsoft::WRL::Callback;
using Microsoft::WRL::ComPtr;
using wpe::shell::Json;
using wpe::shell::WebBridge;
namespace fs=std::filesystem;
namespace {
constexpr UINT app_ready=WM_APP+1, app_drag=WM_APP+2, app_test=WM_APP+3, app_failure=WM_APP+4, app_file=WM_APP+5;
constexpr wchar_t origin[]=L"https://app.wpe64.local/index.html";
void Check(HRESULT result,const char* operation){
    if(FAILED(result)){std::ostringstream text;text<<operation<<" HRESULT=0x"<<std::hex<<static_cast<unsigned long>(result);throw std::runtime_error(text.str());}
}
std::wstring Wide(std::string_view text){
    if(text.empty())return {};
    const auto count=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),nullptr,0);
    if(count==0)throw std::runtime_error("Invalid UTF-8");
    std::wstring result(static_cast<std::size_t>(count),L'\0');
    MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),result.data(),count);return result;
}
std::string Utf8(std::wstring_view text){
    if(text.empty())return {};
    const auto count=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),nullptr,0,nullptr,nullptr);
    if(count==0)throw std::runtime_error("Invalid UTF-16");
    std::string result(static_cast<std::size_t>(count),'\0');
    WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),result.data(),count,nullptr,nullptr);return result;
}
struct CoString {LPWSTR value{};~CoString(){CoTaskMemFree(value);} };
bool IsAdmin(){
    SID_IDENTIFIER_AUTHORITY authority=SECURITY_NT_AUTHORITY;
    PSID sid=nullptr;BOOL member=FALSE;
    if(AllocateAndInitializeSid(&authority,2,SECURITY_BUILTIN_DOMAIN_RID,DOMAIN_ALIAS_RID_ADMINS,0,0,0,0,0,0,&sid)){
        CheckTokenMembership(nullptr,sid,&member);FreeSid(sid);
    }
    return member!=FALSE;
}
struct Options {fs::path assets,data,report;bool test{};};
Options Arguments(){
    std::wstring path(32768,L'\0');const auto count=GetModuleFileNameW(nullptr,path.data(),static_cast<DWORD>(path.size()));
    if(count==0||count==path.size())throw std::runtime_error("Cannot determine executable path");path.resize(count);
    const auto folder=fs::path(path).parent_path();
    Options result{folder/L"wwwroot",folder/L"runtime",{},false};
    int argc=0;auto argv=CommandLineToArgvW(GetCommandLineW(),&argc);
    if(!argv)throw std::runtime_error("Cannot read command line");
    std::unique_ptr<wchar_t*,decltype(&LocalFree)> owner(argv,LocalFree);
    for(int i=1;i<argc;++i){
        const std::wstring arg=argv[i];
        if(i+1>=argc)throw std::runtime_error("Expected a value after command option");
        if(arg==L"--assets")result.assets=argv[++i];
        else if(arg==L"--data-dir")result.data=argv[++i];
        else if(arg==L"--self-test"){result.test=true;result.report=argv[++i];}
        else throw std::runtime_error("Unknown option");
    }
    result.assets=fs::absolute(result.assets);result.data=fs::absolute(result.data);
    if(!fs::is_regular_file(result.assets/L"index.html"))throw std::runtime_error("Missing original wwwroot/index.html; use --assets");
    if(result.test){result.report=fs::absolute(result.report);fs::create_directories(result.report);}
    fs::create_directories(result.data);
    return result;
}
class Host {
public:
    explicit Host(Options options):options_(std::move(options)),exit_code_(options_.test?1:0){}
    ~Host(){
        closing_=true;lifetime_.reset();
        clipboard_.reset();data_.reset();
        // Complete callbacks while the report/window state they capture still exists.
        if(bridge_){bridge_->FailAllPending();bridge_.reset();}
        if(controller_)controller_->Close();
        if(IsWindow(window_))DestroyWindow(window_);
    }
    int Run();
private:
    static LRESULT CALLBACK WindowProc(HWND window,UINT message,WPARAM wparam,LPARAM lparam);
    LRESULT Message(UINT message,WPARAM wparam,LPARAM lparam);
    template<class F> HRESULT Guard(F&& action){try{action();return S_OK;}catch(const std::exception& e){Fail(e.what());return E_FAIL;}}
    void Initialize();
    void Configure();
    void RegisterMethods();
    void Resize();
    void State();
    void Script(const std::wstring& script);
    void BeginTest();
    void CaptureAndFinish();
    void Fail(const std::string& message);
    void Finish(bool success);
    void PickImportFile();
    void CancelFileJobs();
    void DiscardExport(const Json& plan){if(data_&&plan.is_object()&&plan.contains("token"))data_->ForgetExportPlan(plan.at("token").get<std::string>());}
    void DrainClipboard();
    std::unique_ptr<wpe::shell::ClipboardWorker> clipboard_;
    struct FileJob {std::string method;Json args;WebBridge::Completion done;Json export_plan=nullptr;Json file_info=nullptr;};
    void BeginImport(FileJob job,const fs::path& path,std::uint64_t epoch);
    void ReleaseImport(const std::string& token){if(data_)data_->ForgetImportPlan(token);if(token==import_token_){import_token_.clear();import_path_.clear();}}
    std::string import_token_,import_path_;
    std::deque<FileJob> file_jobs_;
    ComPtr<IFileDialog> file_dialog_;
    std::uint64_t file_epoch_{};
    bool test_cancel_file_{},test_encrypted_import_{},file_prompt_pending_{};
    Options options_;
    HWND window_{};
    ComPtr<ICoreWebView2Environment> environment_;
    ComPtr<ICoreWebView2Controller> controller_;
    ComPtr<ICoreWebView2> view_;
    std::unique_ptr<WebBridge> bridge_;
    std::unique_ptr<wpe::shell::DataWorker> data_;
    bool native_drag_{},ready_{},revealed_{},closing_{},done_{},failure_posted_{};
    int exit_code_;
    std::uint64_t messages_{};
    Json report_=Json::object();
    std::chrono::steady_clock::time_point started_=std::chrono::steady_clock::now();
    // All WebView2 callbacks run on this STA. Expiration guards queued completions
    // after the host is destroyed, without creating a host/controller reference cycle.
    std::shared_ptr<int> lifetime_=std::make_shared<int>(0);
};
LRESULT CALLBACK Host::WindowProc(HWND window,UINT message,WPARAM wparam,LPARAM lparam){
    Host* self=reinterpret_cast<Host*>(GetWindowLongPtrW(window,GWLP_USERDATA));
    if(message==WM_NCCREATE){self=static_cast<Host*>(reinterpret_cast<CREATESTRUCTW*>(lparam)->lpCreateParams);self->window_=window;SetWindowLongPtrW(window,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(self));}
    if(!self)return DefWindowProcW(window,message,wparam,lparam);
    try{return self->Message(message,wparam,lparam);}catch(const std::exception& error){self->Fail(error.what());return 0;}
}
LRESULT Host::Message(UINT message,WPARAM wparam,LPARAM lparam){
    switch(message){
    case WM_NCCALCSIZE:if(wparam)return 0;break;
    case WM_ERASEBKGND:return 1;
    case WM_GETMINMAXINFO:{auto info=reinterpret_cast<MINMAXINFO*>(lparam);info->ptMinTrackSize={900,600};
        MONITORINFO monitor{sizeof(MONITORINFO)};if(GetMonitorInfoW(MonitorFromWindow(window_,MONITOR_DEFAULTTONEAREST),&monitor)){
            info->ptMaxPosition={monitor.rcWork.left-monitor.rcMonitor.left,monitor.rcWork.top-monitor.rcMonitor.top};
            info->ptMaxSize={monitor.rcWork.right-monitor.rcWork.left,monitor.rcWork.bottom-monitor.rcWork.top};}return 0;}
    case WM_NCHITTEST:if(!IsZoomed(window_)){
        RECT r{};GetWindowRect(window_,&r);const int x=GET_X_LPARAM(lparam),y=GET_Y_LPARAM(lparam),edge=3;
        const bool left=x<r.left+edge,right=x>=r.right-edge,top=y<r.top+edge,bottom=y>=r.bottom-edge;
        if(top)return left?HTTOPLEFT:right?HTTOPRIGHT:HTTOP;
        if(bottom)return left?HTBOTTOMLEFT:right?HTBOTTOMRIGHT:HTBOTTOM;
        if(left)return HTLEFT;if(right)return HTRIGHT;
    }break;
    case WM_DPICHANGED:{auto r=reinterpret_cast<RECT*>(lparam);SetWindowPos(window_,nullptr,r->left,r->top,r->right-r->left,r->bottom-r->top,SWP_NOZORDER|SWP_NOACTIVATE);return 0;}
    case WM_SIZE:Resize();State();return 0;
    case WM_TIMER:
        if(bridge_)bridge_->Tick();
        if(!closing_)DrainClipboard();
        if(data_&&bridge_&&!closing_)data_->Drain([this](std::string name,Json value){bridge_->PushEvent(std::move(name),std::move(value));});
        if(options_.test && std::chrono::steady_clock::now()-started_>std::chrono::seconds(90))Fail("WebView2 self-test timed out");
        if(!options_.test && !revealed_ && std::chrono::steady_clock::now()-started_>std::chrono::seconds(4)){revealed_=true;ShowWindow(window_,SW_SHOW);}
        if(!options_.test && !ready_ && std::chrono::steady_clock::now()-started_>std::chrono::seconds(30))Fail("原 Vue 页面未在 30 秒内完成初始化，请检查 WebView2 Runtime 和 wwwroot 资源。");
        return 0;
    case app_ready:
        if(!ready_){ready_=true;if(!options_.test){revealed_=true;ShowWindow(window_,SW_SHOW);}else BeginTest();}
        return 0;
    case app_drag:ReleaseCapture();SendMessageW(window_,WM_NCLBUTTONDOWN,HTCAPTION,0);return 0;
    case app_test:CaptureAndFinish();return 0;
    case app_file:PickImportFile();return 0;
    case app_failure:
        // Posted from WebView2 callbacks: no nested modal pump in those callbacks.
        if(!options_.test)MessageBoxW(window_,Wide(report_.value("error",std::string("Native host failed"))).c_str(),L"WPE C++ 宿主错误",MB_OK|MB_ICONERROR);
        Finish(false);return 0;
    case WM_CLOSE:
        CancelFileJobs();
        closing_=true;if(bridge_)bridge_->FailAllPending();
        if(controller_)controller_->Close();view_.Reset();controller_.Reset();
        DestroyWindow(window_);return 0;
    case WM_DESTROY:KillTimer(window_,1);PostQuitMessage(exit_code_);return 0;
    }
    return DefWindowProcW(window_,message,wparam,lparam);
}
int Host::Run(){
    const auto instance=GetModuleHandleW(nullptr);
    WNDCLASSEXW type{sizeof(WNDCLASSEXW)};type.lpfnWndProc=WindowProc;type.hInstance=instance;type.hCursor=LoadCursorW(nullptr,IDC_ARROW);type.lpszClassName=L"Wpe64NativeHost";
    if(!RegisterClassExW(&type))throw std::runtime_error("Window class registration failed");
    window_=CreateWindowExW(0,type.lpszClassName,L"WPE x64 C++ development host",WS_OVERLAPPEDWINDOW,100,100,1200,820,nullptr,nullptr,instance,this);
    if(!window_)throw std::runtime_error("Window creation failed");
    const MARGINS margins{1,1,1,1};DwmExtendFrameIntoClientArea(window_,&margins);
    SetTimer(window_,1,100,nullptr);
    Initialize();
    MSG message{};BOOL status;
    while((status=GetMessageW(&message,nullptr,0,0))>0){TranslateMessage(&message);DispatchMessageW(&message);}
    bridge_.reset();view_.Reset();controller_.Reset();environment_.Reset();
    if(status<0)throw std::runtime_error("Window message loop failed");
    return static_cast<int>(message.wParam);
}
void Host::Initialize(){
    Check(CreateCoreWebView2EnvironmentWithOptions(nullptr,options_.data.c_str(),nullptr,
        Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>([this,alive=std::weak_ptr(lifetime_)](HRESULT result,ICoreWebView2Environment* environment)->HRESULT{
            if(alive.expired()||closing_)return S_OK;
            return Guard([&]{Check(result,"Create WebView2 environment");environment_=environment;
                CoString version;Check(environment_->get_BrowserVersionString(&version.value),"Runtime version");report_["webview2Runtime"]=Utf8(version.value);
                Check(environment_->CreateCoreWebView2Controller(window_,Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>([this,alive=std::weak_ptr(lifetime_)](HRESULT hr,ICoreWebView2Controller* controller)->HRESULT{
                    if(alive.expired()||closing_)return S_OK;
                    return Guard([&]{Check(hr,"Create controller");controller_=controller;Check(controller_->get_CoreWebView2(&view_),"Get WebView2");Configure();});
                }).Get()),"Create controller async");
            });
        }).Get()),"Create environment async");
}
void Host::Configure(){
    ComPtr<ICoreWebView2_3> resources;Check(view_.As(&resources),"WebView2 resource mapping interface");
    Check(resources->SetVirtualHostNameToFolderMapping(L"app.wpe64.local",options_.assets.c_str(),COREWEBVIEW2_HOST_RESOURCE_ACCESS_KIND_DENY),"Map original wwwroot");
    ComPtr<ICoreWebView2Settings> settings;Check(view_->get_Settings(&settings),"Get settings");
    Check(settings->put_IsWebMessageEnabled(TRUE),"Enable web messages");
    Check(settings->put_AreHostObjectsAllowed(FALSE),"Disable host objects");
    Check(settings->put_AreDefaultScriptDialogsEnabled(FALSE),"Disable script dialogs");
    Check(settings->put_AreDevToolsEnabled(options_.test?TRUE:FALSE),"Configure devtools");
    ComPtr<ICoreWebView2Settings9> nonclient;
    native_drag_=SUCCEEDED(settings.As(&nonclient)) && SUCCEEDED(nonclient->put_IsNonClientRegionSupportEnabled(TRUE));
    ComPtr<ICoreWebView2Controller2> background;if(SUCCEEDED(controller_.As(&background)))background->put_DefaultBackgroundColor(COREWEBVIEW2_COLOR{255,10,10,15});
    bridge_=std::make_unique<WebBridge>([this](const std::string& text){if(closing_)throw std::runtime_error("Host is closing");Check(view_->PostWebMessageAsJson(Wide(text).c_str()),"Post web message");});
    RegisterMethods();
    EventRegistrationToken token{};
    Check(view_->add_WebMessageReceived(Callback<ICoreWebView2WebMessageReceivedEventHandler>([this](ICoreWebView2*,ICoreWebView2WebMessageReceivedEventArgs* args)->HRESULT{
        return Guard([&]{CoString source,raw;Check(args->get_Source(&source.value),"Message source");Check(args->get_WebMessageAsJson(&raw.value),"Message JSON");++messages_;bridge_->Receive(Utf8(source.value),Utf8(raw.value));});
    }).Get(),&token),"Register web messages");
    Check(view_->add_NavigationStarting(Callback<ICoreWebView2NavigationStartingEventHandler>([this](ICoreWebView2*,ICoreWebView2NavigationStartingEventArgs* args)->HRESULT{
        return Guard([&]{CoString uri;Check(args->get_Uri(&uri.value),"Navigation URI");if(!WebBridge::IsAllowedSource(Utf8(uri.value)))Check(args->put_Cancel(TRUE),"Block navigation");else {CancelFileJobs();bridge_->FailAllPending();}});
    }).Get(),&token),"Register navigation");
    Check(view_->add_NewWindowRequested(Callback<ICoreWebView2NewWindowRequestedEventHandler>([](ICoreWebView2*,ICoreWebView2NewWindowRequestedEventArgs* args)->HRESULT{return args->put_Handled(TRUE);}).Get(),&token),"Block new windows");
    Check(view_->add_PermissionRequested(Callback<ICoreWebView2PermissionRequestedEventHandler>([](ICoreWebView2*,ICoreWebView2PermissionRequestedEventArgs* args)->HRESULT{return args->put_State(COREWEBVIEW2_PERMISSION_STATE_DENY);}).Get(),&token),"Block web permissions");
    Check(view_->add_ProcessFailed(Callback<ICoreWebView2ProcessFailedEventHandler>([this](ICoreWebView2*,ICoreWebView2ProcessFailedEventArgs*)->HRESULT{bridge_->FailAllPending();Fail("WebView2 renderer failed");return S_OK;}).Get(),&token),"Register process failures");
    Check(view_->add_NavigationCompleted(Callback<ICoreWebView2NavigationCompletedEventHandler>([this](ICoreWebView2*,ICoreWebView2NavigationCompletedEventArgs* args)->HRESULT{
        return Guard([&]{BOOL ok=FALSE;Check(args->get_IsSuccess(&ok),"Navigation status");if(!ok)Fail("Original frontend navigation failed");});
    }).Get(),&token),"Register navigation completion");
    Resize();Check(view_->Navigate(origin),"Navigate original frontend");
}
void Host::Resize(){if(controller_){RECT bounds{};GetClientRect(window_,&bounds);if(!IsZoomed(window_)){InflateRect(&bounds,-3,-3);}controller_->put_Bounds(bounds);}}
void Host::State(){if(bridge_&&!closing_)bridge_->PushEvent("window:state",{{"maximized",IsZoomed(window_)!=FALSE}});}
void Host::RegisterMethods(){
    const auto db=options_.data/L"2.3.0"/L"WPE.db";
    data_=std::make_unique<wpe::shell::DataWorker>(db);
    for(const auto& method:wpe::shell::DataService::Methods()){
        bridge_->RegisterAsync(method,[this,method](const Json& args,WebBridge::Completion done){
            if(wpe::shell::DataService::NeedsOpenFile(method,args)||wpe::shell::DataService::NeedsSaveFile(method,args)){
                if(file_jobs_.size()>=8){done(nullptr,"文件选择请求过多");return;}
                auto safe=args;safe.erase("_filePath");safe.erase("_password"); // Only the native chooser may grant a file path.
                if(wpe::shell::DataService::NeedsSaveFile(method,args)){
                    // Snapshot selection on the data worker BEFORE opening the
                    // picker, just as the original constructs its List<T> first.
                    auto complete=bridge_->WithErrorToast(std::move(done));
                    data_->Submit("__prepareEditorExport",{{"method",method},{"args",safe}},[this,method,safe,complete,epoch=file_epoch_](Json plan,std::string error){
                        if(closing_||epoch!=file_epoch_){DiscardExport(plan);complete(nullptr,"文件选择已取消");return;}
                        if(!error.empty()){complete(nullptr,std::move(error));return;}
                        if(plan.at("rowCount")==0){complete(plan.at("result"),{});return;}
                        if(file_jobs_.size()>=8){DiscardExport(plan);complete(nullptr,"文件选择请求过多");return;}
                        file_jobs_.push_back({method,safe,complete,std::move(plan)});PostMessageW(window_,app_file,0,0);
                    });return;
                }
                auto complete=bridge_->WithErrorToast(std::move(done));
                data_->Submit("__fileInfo",{{"kind",wpe::shell::DataService::FileKind(method,safe)},{"save",false}},[this,method,safe,complete,epoch=file_epoch_](Json info,std::string error){
                    if(closing_||epoch!=file_epoch_){complete(nullptr,"文件选择已取消");return;}
                    if(!error.empty()){complete(nullptr,std::move(error));return;}
                    if(file_jobs_.size()>=8){complete(nullptr,"文件选择请求过多");return;}
                    file_jobs_.push_back({method,safe,complete,nullptr,std::move(info)});PostMessageW(window_,app_file,0,0);
                });return;
            }
            auto submit=[this,method,args,done]{data_->Submit(method,args,done);};
            if(wpe::shell::DataService::NeedsConfirmation(method,args)){
                bridge_->Ask("confirm",{{"title","确认操作"},{"content","确定删除选中的数据吗？此操作不可撤销。"},{"icon",2}},
                    [submit=std::move(submit),done](Json answer){if(answer==true)submit();else done({{"ok",true},{"delta",0}},{});});
            }else submit();
        });
    }
    bridge_->RegisterAsync("verifyEncryptPassword",[this](const Json& args,WebBridge::Completion done){
        if(import_token_.empty()||import_path_.empty()||!args.contains("path")||args["path"]!=import_path_){done({{"ok",false}},{});return;}
        data_->Submit("__verifyImportPassword",{{"token",import_token_},{"password",args.value("password",std::string{})}},[this,done,token=import_token_,epoch=file_epoch_](Json value,std::string error){
            if(!error.empty()||epoch!=file_epoch_||token!=import_token_){done({{"ok",false}},{});return;}done(std::move(value),{});
        });
    });
    bridge_->RegisterAsync("getSystemCheck",[this,db](const Json&,WebBridge::Completion done){
        data_->Submit("getPrefs",Json::object(),[this,db,done](Json prefs,std::string error){
            if(!error.empty()){done(nullptr,std::move(error));return;}
            done(Json{
                {"isAdmin",IsAdmin()},{"version","C++ DATA-dev"},{"isBeta",false},{"language",prefs["language"]},
                {"themeMode",prefs["themeMode"]},{"isDark",prefs["isDark"]},{"scanLine",prefs["scanLine"]},{"nativeDrag",native_drag_},
                {"dbDir",Utf8(db.parent_path().wstring())},{"dbFile","WPE.db"},{"dbFull",Utf8(db.wstring())},{"dbInstance","default"},{"lastInjection",""},{"lastInject",nullptr},
                {"socks5Port",0},{"socks5Addr",""},{"httpAddr",""},{"geoVersion","未实现"},{"geoCount",0}},{});
        });
    });
    bridge_->Register("uiReady",[this](const Json&){PostMessageW(window_,app_ready,0,0);return Json{{"ok",true}};});
    bridge_->Register("minimizeWindow",[this](const Json&){ShowWindow(window_,SW_MINIMIZE);return Json{{"ok",true}};});
    bridge_->Register("toggleMaximize",[this](const Json&){ShowWindow(window_,IsZoomed(window_)?SW_RESTORE:SW_MAXIMIZE);return Json{{"maximized",IsZoomed(window_)!=FALSE}};});
    bridge_->Register("closeWindow",[this](const Json&){PostMessageW(window_,WM_CLOSE,0,0);return Json{{"ok",true}};});
    bridge_->Register("setTopMost",[this](const Json& args){
        const bool on=args.value("on",false);if(!SetWindowPos(window_,on?HWND_TOPMOST:HWND_NOTOPMOST,0,0,0,0,SWP_NOMOVE|SWP_NOSIZE|SWP_NOACTIVATE))throw std::runtime_error("Cannot change window z-order");
        if(options_.test)report_["topmostCalls"].push_back({{"on",on},{"style",GetWindowLongPtrW(window_,GWL_EXSTYLE)},{"visible",IsWindowVisible(window_)!=FALSE}});
        return Json{{"topMost",(GetWindowLongPtrW(window_,GWL_EXSTYLE)&WS_EX_TOPMOST)!=0}};});
    bridge_->Register("startDragWindow",[this](const Json&){PostMessageW(window_,app_drag,0,0);return Json{{"ok",true}};});
    clipboard_=std::make_unique<wpe::shell::ClipboardWorker>(options_.test);
    bridge_->RegisterAsync("clipboardRead",[this](const Json&,WebBridge::Completion done){
        clipboard_->Submit(false,{},[done](bool ok,std::wstring value){std::string text;try{if(ok)text=Utf8(value);}catch(...){}done({{"text",text}},{});});
    });
    bridge_->RegisterAsync("clipboardWrite",[this](const Json& args,WebBridge::Completion done){
        std::wstring text;try{if(args.contains("text")&&!args["text"].is_null())text=Wide(args.at("text").get<std::string>());}catch(...){done({{"ok",false}},{});return;}
        clipboard_->Submit(true,std::move(text),[done](bool ok,std::wstring){done({{"ok",ok}},{});});
    });
    if(options_.test){
        bridge_->Register("__testStage",[this](const Json& args){report_["lastStage"]=args;return Json{{"ok",true}};});
        bridge_->Register("__testCancelNextFile",[this](const Json&){test_cancel_file_=true;return Json{{"ok",true}};});
        bridge_->Register("__testUseLastEncryptedExport",[this](const Json&){
            const auto target=options_.report/L"encrypted-export.sc";fs::copy_file(options_.report/L"export.sc",target,fs::copy_options::overwrite_existing);test_encrypted_import_=true;return Json{{"path",Utf8(target.wstring())}};
        });
        bridge_->Register("__testConfirm",[this](const Json&){
            bridge_->Ask("confirm",{{"title","C++ ↔ 原 Vue 双向桥测试"},{"content","此对话框由原 Vue 渲染，自动测试将点击确定。"},{"icon",2}},[this](Json answer){report_["originalVueConfirmed"]=answer;bridge_->PushEvent("toast",{{"level",1},{"text","NATIVE_BRIDGE_EVENT_OK"}});});return Json{{"ok",true}};});
        bridge_->Register("__testDone",[this](const Json& args){report_["frontend"]=args;PostMessageW(window_,app_test,0,0);return Json{{"ok",true}};});
    }
}
void Host::CancelFileJobs(){
    // Navigation/close must cancel deferred clipboard writes too.
    if(clipboard_)clipboard_->Cancel();
    ++file_epoch_;file_prompt_pending_=false;if(file_dialog_)file_dialog_->Close(HRESULT_FROM_WIN32(ERROR_CANCELLED));
    const auto token=import_token_;ReleaseImport(token);
    auto cancelled=std::move(file_jobs_);file_jobs_.clear();for(auto& job:cancelled){DiscardExport(job.export_plan);job.done(nullptr,"文件选择已取消");}
}
void Host::PickImportFile(){
    if(closing_||file_dialog_||file_prompt_pending_||file_jobs_.empty())return;
    auto job=std::move(file_jobs_.front());file_jobs_.pop_front();const auto epoch=file_epoch_;
    try{
        fs::path path;const bool save=!job.export_plan.is_null();const auto& info=save?job.export_plan:job.file_info;const auto kind=info.at("kind").get<std::string>();
        if(options_.test){
            // Test-only chooser seam; fixed files under the isolated report dir.
            // The production Windows dialog is never replaced outside --self-test.
            if(!test_cancel_file_)path=options_.report/Wide(std::string(!save&&test_encrypted_import_?"encrypted-export.":save?"export.":"import.")+kind);test_cancel_file_=false;if(!save)test_encrypted_import_=false;
        }else{
            Check(CoCreateInstance(save?CLSID_FileSaveDialog:CLSID_FileOpenDialog,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&file_dialog_)),"Create file dialog");
            DWORD flags=0;Check(file_dialog_->GetOptions(&flags),"Get dialog flags");
            Check(file_dialog_->SetOptions(flags|FOS_FORCEFILESYSTEM|FOS_PATHMUSTEXIST|FOS_NOCHANGEDIR|(save?FOS_OVERWRITEPROMPT:FOS_FILEMUSTEXIST)),"Set dialog flags");
            const auto pattern=Wide("*."+kind),label=Wide(kind=="xls"?"Excel (*.xls)":"WPE (*."+kind+")"),extension=Wide(kind);
            const COMDLG_FILTERSPEC filters[]={{label.c_str(),pattern.c_str()},{L"XML 文件",L"*.xml"},{L"所有文件",L"*.*"}};
            Check(file_dialog_->SetFileTypes(kind=="xls"?1:3,filters),"Set dialog filters");Check(file_dialog_->SetDefaultExtension(extension.c_str()),"Set default extension");
            if(save&&info.contains("defaultName"))Check(file_dialog_->SetFileName(Wide(info.at("defaultName").get<std::string>()).c_str()),"Set default file name");
            Check(file_dialog_->SetTitle(Wide(info.at("title").get<std::string>()).c_str()),"Set dialog title");
            const auto hr=file_dialog_->Show(window_);if(hr!=HRESULT_FROM_WIN32(ERROR_CANCELLED)){Check(hr,"Open file dialog");ComPtr<IShellItem> item;Check(file_dialog_->GetResult(&item),"Get selected file");CoString name;Check(item->GetDisplayName(SIGDN_FILESYSPATH,&name.value),"Get file path");path=name.value;}
            file_dialog_.Reset();
        }
        if(closing_||epoch!=file_epoch_){DiscardExport(job.export_plan);job.done(nullptr,"文件选择已取消");}
        else if(path.empty()){DiscardExport(job.export_plan);if(save)job.done(job.export_plan.at("result"),{});else data_->Submit(job.method,job.args,job.done);}
        else if(save&&job.export_plan.value("plain",false)){
            file_prompt_pending_=true;
            data_->Submit("__writeEditorExport",{{"plan",job.export_plan},{"_filePath",Utf8(path.wstring())},{"_password",""}},[this,job,epoch](Json value,std::string failure){
                DiscardExport(job.export_plan);if(epoch==file_epoch_){file_prompt_pending_=false;job.done(std::move(value),std::move(failure));if(!closing_&&!file_jobs_.empty())PostMessageW(window_,app_file,0,0);}else job.done(nullptr,"导出已取消");
            });
        }
        else if(save){
            file_prompt_pending_=true;
            bridge_->AskResult("prompt",{{"formId","encrypt-export"},{"arg",{{"Title",job.export_plan.at("title")},{"FilePath",nullptr}}}},
                [this,job,epoch,path](Json answer,std::string error){
                    if(closing_||epoch!=file_epoch_){DiscardExport(job.export_plan);job.done(nullptr,"导出已取消");return;}
                    file_prompt_pending_=false;
                    if(!error.empty()){DiscardExport(job.export_plan);job.done(nullptr,"导出已取消："+error);}
                    else if(answer.is_null()||(answer.is_object()&&answer.contains("Password")&&answer["Password"].is_string()&&!answer["Password"].get<std::string>().empty()))
                        data_->Submit("__writeEditorExport",{{"plan",job.export_plan},{"_filePath",Utf8(path.wstring())},{"_password",answer.is_null()?"":answer["Password"].get<std::string>()}},[this,job](Json value,std::string failure){DiscardExport(job.export_plan);job.done(std::move(value),std::move(failure));});
                    else{DiscardExport(job.export_plan);job.done(nullptr,"密码结果无效；未写入文件");}
                    if(!file_jobs_.empty())PostMessageW(window_,app_file,0,0);
                });
        }
        else BeginImport(job,path,epoch);
    }catch(const std::exception& e){file_dialog_.Reset();file_prompt_pending_=false;DiscardExport(job.export_plan);job.done(nullptr,e.what());}
    if(!closing_&&!file_jobs_.empty())PostMessageW(window_,app_file,0,0);
}
void Host::DrainClipboard(){if(clipboard_)clipboard_->Drain();}
void Host::BeginImport(FileJob job,const fs::path& path,std::uint64_t epoch){
    file_prompt_pending_=true;job.args["_filePath"]=Utf8(path.wstring());
    data_->Submit("__prepareImport",{{"method",job.method},{"args",job.args}},[this,job,epoch](Json plan,std::string error){
        const auto token=plan.is_object()?plan.value("token",std::string{}):std::string{};
        auto finish=[this,job,epoch,token](Json value,std::string failure){
            ReleaseImport(token);
            if(epoch==file_epoch_){file_prompt_pending_=false;if(!closing_&&!file_jobs_.empty())PostMessageW(window_,app_file,0,0);}
            job.done(std::move(value),std::move(failure));
        };
        if(closing_||epoch!=file_epoch_){finish(nullptr,"导入已取消");return;}
        if(!error.empty()){finish(nullptr,std::move(error));return;}
        try{
            import_token_=token; // Plain XML must also be cancellable while apply is queued.
            if(!plan.at("encrypted").get<bool>()){data_->Submit("__applyImport",{{"token",token}},finish);return;}
            import_path_=job.args.at("_filePath").get<std::string>();
            bridge_->AskResult("prompt",{{"formId","encrypt-import"},{"arg",{{"Title",plan.at("title")},{"FilePath",import_path_}}}},
                [this,job,epoch,token,finish](Json answer,std::string failure){
                    if(closing_||epoch!=file_epoch_){finish(nullptr,"导入已取消");return;}
                    if(!failure.empty()){finish(nullptr,"导入已取消："+failure);return;}
                    if(answer.is_null()){auto cancelled=job.args;cancelled.erase("_filePath");data_->Submit(job.method,std::move(cancelled),finish);return;}
                    if(!answer.is_object()||!answer.contains("Password")||!answer["Password"].is_string()||answer["Password"].get<std::string>().empty()){finish(nullptr,"密码结果无效；未导入数据");return;}
                    data_->Submit("__applyImport",{{"token",token},{"password",answer.at("Password")}},finish);
                });
        }catch(const std::exception& e){finish(nullptr,e.what());}
    });
}
void Host::Script(const std::wstring& script){
    Check(view_->ExecuteScript(script.c_str(),Callback<ICoreWebView2ExecuteScriptCompletedHandler>([this,alive=std::weak_ptr(lifetime_)](HRESULT hr,LPCWSTR)->HRESULT{
        if(alive.expired()||closing_)return S_OK;
        if(FAILED(hr))Fail("ExecuteScript failed");return S_OK;
    }).Get()),"Execute test script");
}
void Host::BeginTest(){
    // Fixed inputs only for the isolated self-test chooser. No fixtures are
    // inserted into a normal user's database or shipped runtime directory.
    {std::ofstream f(options_.report/L"import.sc",std::ios::binary);f<<"<SendCollection><Collection><Socket>17</Socket><Type>TCP_Req</Type><IPFrom>127.0.0.1</IPFrom><IPTo>127.0.0.2</IPTo><Buffer>00 FF 80 41</Buffer></Collection><Collection><Socket>23</Socket><Type>UDP_Resp</Type><Buffer>01 02 03</Buffer></Collection></SendCollection>";if(!f)throw std::runtime_error("Cannot write send self-test fixture");}
    {std::ofstream f(options_.report/L"import.whs",std::ios::binary);f<<"<Stores><Data><PacketData>00 FF 80</PacketData></Data><Data><PacketData>41 42</PacketData></Data></Stores>";if(!f)throw std::runtime_error("Cannot write warehouse self-test fixture");}
    Script(LR"JS((()=>{
      const w=chrome.webview; let seq=0; const pending=new Map();
      w.addEventListener('message',e=>{const m=e.data;if(m.type==='result'&&pending.has(m.id)){const p=pending.get(m.id);pending.delete(m.id);m.ok?p.resolve(m.result):p.reject(new Error(m.error));}});
      const call=(method,args={})=>new Promise((resolve,reject)=>{const id='selftest-'+(++seq);pending.set(id,{resolve,reject});w.postMessage({type:'call',id,method,args});});
      const wait=async(f)=>{for(let i=0;i<150;i++){if(f())return;await new Promise(r=>setTimeout(r,40));}throw Error('DOM condition timed out');};
      (async()=>{
        const info=await call('getSystemCheck');if(info.version!=='C++ DATA-dev')throw Error('wrong native host');
        await wait(()=>document.querySelector('.win .titlebar')&&document.querySelectorAll('.rack .cd').length>=2);
        // A hidden/background process can fail this platform-dependent probe.
        // Keep its exact result separate from editor acceptance, never fake it.
        const top=await call('setTopMost',{on:true});
        const normal=await call('setTopMost',{on:false});if(normal.topMost)throw Error('topmost reset failed');
        let unsupported=false;try{await call('__unimplemented_capture');}catch(e){unsupported=String(e).includes('尚未实现');}
        if(!unsupported)throw Error('unsupported method falsely succeeded');
        await call('__testConfirm');
        await wait(()=>document.querySelector('[role=alertdialog] .btn.primary'));
        document.querySelector('[role=alertdialog] .btn.primary').click();
        await wait(()=>document.body.textContent.includes('NATIVE_BRIDGE_EVENT_OK'));
        const modeCards=document.querySelectorAll('.rack .cd').length;
        const feeds=new Map(),notices=[];w.addEventListener('message',e=>{const m=e.data;if(m.type==='event'&&m.name==='feed:replace')feeds.set(m.data.list,m.data.rows);else if(m.type==='event'&&m.name==='feed:append')feeds.set(m.data.list,(feeds.get(m.data.list)||[]).concat(m.data.rows||[]));if(m.type==='event'&&m.name==='notify')notices.push(m.data);});
        const dialog=kind=>[...document.querySelectorAll('[role=dialog]')].find(d=>d.querySelector('.sub')?.textContent==='Controls/'+kind);
        const input=(el,value)=>{if(!el)throw Error('editor input missing');Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(el,String(value));el.dispatchEvent(new Event('input',{bubbles:true}));};
        const nav=async label=>{await call('__testStage',{stage:label});const el=[...document.querySelectorAll('.side .sb-item')].find(e=>e.querySelector('.t')?.textContent.trim()===label);if(!el)throw Error('navigation missing: '+label);el.click();await wait(()=>document.querySelector('.list-page .bar .btn.primary'));};
        const openEditor=async(kind)=>{document.querySelector('.list-page .row .ops .op:not(.del)').click();await wait(()=>dialog(kind)?.querySelector('.bd'));return dialog(kind);};
        const closeEditor=async(kind)=>{dialog(kind).querySelector('.ft .btn:not(.primary)').click();await wait(()=>!dialog(kind));};
        const clipEquals=async expected=>{for(let n=0;n<50;n++){if((await call('clipboardRead')).text===expected)return;await new Promise(r=>setTimeout(r,40));}throw Error('clipboard mismatch');};
        const exportPlain=async(d,title)=>{const count=notices.length;[...d.querySelectorAll('.runbar .btn')].find(e=>e.textContent.trim().includes('导出')).click();await wait(()=>document.querySelector('[role=dialog] .ft .btn.plain'));document.querySelector('[role=dialog] .ft .btn.plain').click();await wait(()=>notices.slice(count).some(x=>x.title===title));};
    )JS" LR"JS(
        const editors=async(restart)=>{
          await nav('发送列表');if(!restart){document.querySelector('.list-page .bar .btn.primary').click();await wait(()=>feeds.get(9)?.length===1&&document.querySelector('.list-page .row .name'));}
          let d=await openEditor('SendEdit');
          if(!restart){
            input(d.querySelector('.bd > .row .v input.inp'),'C++ 发送编辑测试');
            const imp=[...d.querySelectorAll('.runbar .btn')].find(e=>e.textContent.trim().includes('导入'));
            if(!imp)throw Error('send import button missing');
            await call('__testCancelNextFile');imp.click();await new Promise(r=>setTimeout(r,250));
            if(d.querySelectorAll('.row2').length)throw Error('cancelled chooser imported data');
            imp.click();await wait(()=>d.querySelectorAll('.row2').length===2&&document.body.textContent.includes('导入发送集成功'));
            d.querySelector('.row2 .op:not(.del)').click();await wait(()=>dialog('PacketEdit')?.querySelector('.fields input'));
            const p=dialog('PacketEdit');input(p.querySelector('.fields input'),99);
            const hex=p.querySelector('.hexed [tabindex="0"]');if(!hex)throw Error('original HexView missing');
            hex.focus();for(const key of ['A','A'])hex.dispatchEvent(new KeyboardEvent('keydown',{key,bubbles:true,cancelable:true}));
            for(const key of ['a','c'])hex.dispatchEvent(new KeyboardEvent('keydown',{key,ctrlKey:true,bubbles:true,cancelable:true}));
            await clipEquals('AA FF 80 41');await call('clipboardWrite',{text:'AA FF 80 42'});
            hex.dispatchEvent(new KeyboardEvent('keydown',{key:'v',ctrlKey:true,bubbles:true,cancelable:true}));
            await wait(()=>hex.querySelector('.hexs .b[data-i="3"]')?.textContent.trim()==='42');
            await call('clipboardWrite',{text:null});await clipEquals('');
            p.querySelector('.ft .btn.primary').click();await wait(()=>!dialog('PacketEdit')&&d.querySelector('.row2 .so')?.textContent==='99');
            if(!d.querySelector('.row2 .dt').textContent.startsWith('AA FF'))throw Error('HexView edit not saved');
            await call('__testCancelNextFile');await call('exportSendCollection',{_filePath:'untrusted-browser-path.sc'});
            await exportPlain(d,'导出发送集成功');
            await call('__testStage',{stage:'encrypted-export'});const secret='test-only-not-a-user-password',encrypted=call('exportSendCollection');
            await wait(()=>document.querySelector('[role=dialog] .ft .btn.plain'));const pw=document.querySelector('[role=dialog] .ft .btn.plain').closest('[role=dialog]');for(const field of pw.querySelectorAll('input'))input(field,secret);await wait(()=>!pw.querySelector('.ft .btn.primary').disabled);pw.querySelector('.ft .btn.primary').click();await encrypted;
            await call('__testStage',{stage:'encrypted-export-complete'});const grant=await call('__testUseLastEncryptedExport');
            if((await call('verifyEncryptPassword',{path:grant.path,password:secret})).ok)throw Error('password verifier accepted unselected file');
            await call('__testStage',{stage:'clear-before-encrypted-import'});d.querySelector('.runbar .btn.danger').click();await wait(()=>document.querySelector('[role=alertdialog] .btn.primary'));document.querySelector('[role=alertdialog] .btn.primary').click();await wait(()=>d.querySelectorAll('.row2').length===0);imp.click();
            await wait(()=>[...document.querySelectorAll('[role=dialog]')].some(e=>e.querySelector('.fld input')&&!e.querySelector('.ft .btn.plain')));
            const unlock=[...document.querySelectorAll('[role=dialog]')].find(e=>e.querySelector('.fld input')&&!e.querySelector('.ft .btn.plain'));
            if((await call('verifyEncryptPassword',{path:grant.path+'.forged',password:secret})).ok)throw Error('forged import path accepted');
            await call('__testStage',{stage:'encrypted-import-wrong-password'});input(unlock.querySelector('input'),'wrong-password');await wait(()=>!unlock.querySelector('.ft .btn.primary').disabled);unlock.querySelector('.ft .btn.primary').click();await wait(()=>unlock.querySelector('.err'));
            if(d.querySelectorAll('.row2').length!==0)throw Error('wrong password imported data');
            input(unlock.querySelector('input'),secret);await wait(()=>!unlock.querySelector('.ft .btn.primary').disabled);unlock.querySelector('.ft .btn.primary').click();await wait(()=>!unlock.isConnected&&d.querySelectorAll('.row2').length===2);
            if((await call('verifyEncryptPassword',{path:grant.path,password:secret})).ok)throw Error('consumed import grant remained usable');
            await exportPlain(d,'导出发送集成功');
            d.querySelector('.ft .btn.primary').click();await wait(()=>!dialog('SendEdit')&&feeds.get(9)?.[0]?.PacketCount===2);
          }else{
            await wait(()=>d.querySelectorAll('.row2').length===2);
            if(d.querySelector('.bd > .row input').value!=='C++ 发送编辑测试'||d.querySelector('.row2 .so').textContent!=='99'||!d.querySelector('.row2 .dt').textContent.startsWith('AA FF'))throw Error('send editor restart data mismatch');
            await closeEditor('SendEdit');
          }
    )JS" LR"JS(
          await nav('仓库列表');if(!restart){document.querySelector('.list-page .bar .btn.primary').click();await wait(()=>feeds.get(11)?.length===1&&document.querySelector('.list-page .row .name'));}
          d=await openEditor('WareHouseEdit');
          if(!restart){
            input(d.querySelector('.bd > .row input'),'C++ 仓储编辑测试');
            [...d.querySelectorAll('.runbar .btn')].find(e=>e.textContent.trim().includes('导入')).click();
            await wait(()=>d.querySelectorAll('.row2').length===2&&document.body.textContent.includes('导入仓储数据成功'));
            await exportPlain(d,'导出仓储数据成功');
            d.querySelector('.row2').click();await wait(()=>[...d.querySelectorAll('.runbar .btn')].some(e=>e.textContent.includes('复制')&&!e.disabled));[...d.querySelectorAll('.runbar .btn')].find(e=>e.textContent.includes('复制')).click();await clipEquals('00 FF 80\r\n');
            d.querySelector('.runbar .btn.danger').click();await wait(()=>document.querySelector('[role=alertdialog] .btn:not(.primary)'));
            document.querySelector('[role=alertdialog] .btn:not(.primary)').click();await wait(()=>!document.querySelector('[role=alertdialog]'));
            if(d.querySelectorAll('.row2').length!==2)throw Error('cancelled store clear lost entries');
            d.querySelector('.ft .btn.primary').click();await wait(()=>!dialog('WareHouseEdit')&&feeds.get(11)?.[0]?.Name==='C++ 仓储编辑测试');
          }else{
            await wait(()=>d.querySelectorAll('.row2').length===2&&d.querySelector('.row2 .dt')?.textContent==='00 FF 80');
            if(d.querySelector('.bd > .row input').value!=='C++ 仓储编辑测试')throw Error('warehouse name restart mismatch');await closeEditor('WareHouseEdit');
          }
          document.querySelector('.list-page .bar .btn.warn').click();
          const autoDialog=()=>[...document.querySelectorAll('[role=dialog]')].find(x=>x.querySelector('.sub')?.textContent==='Auto Store');
          const ruleDialog=()=>[...document.querySelectorAll('[role=dialog]')].find(x=>x.querySelector('.sub')?.textContent==='Auto-Store Rule');
          await wait(()=>autoDialog()?.querySelector('.lbar .mini')&&feeds.has(12));
          if(!restart&&!(feeds.get(12)||[]).some(x=>x.PacketHead==='16 03 01')){
            autoDialog().querySelector('.lbar .mini').click();await wait(()=>ruleDialog()?.querySelector('input.inp'));
            input(ruleDialog().querySelector('input.inp'),'16 03 01');ruleDialog().querySelector('.ft .btn.primary').click();
            await wait(()=>!ruleDialog()&&(feeds.get(12)||[]).some(x=>x.PacketHead==='16 03 01'));
            await wait(()=>autoDialog()?.querySelector('.trow .ck button'));
            autoDialog().querySelector('.trow .ck button').click();await wait(()=>feeds.get(12)[0].IsEnable===true);
            await wait(()=>autoDialog()?.querySelector('.bd > .row .v .chk'));autoDialog().querySelector('.bd > .row .v .chk').click();autoDialog().querySelector('.ft .btn.primary').click();await wait(()=>!autoDialog());
          }else{
            await wait(()=>autoDialog().querySelector('.trow .head')?.textContent.trim()==='16 03 01');
            if(!feeds.get(12)[0].IsEnable||(await call('getAutoStoresMeta')).enable)throw Error('auto-store restart state mismatch');
            autoDialog().querySelector('.ft .btn:not(.primary)').click();await wait(()=>!autoDialog());
          }
          await nav('机器人列表');if(!restart){document.querySelector('.list-page .bar .btn.primary').click();await wait(()=>feeds.get(10)?.length===1&&document.querySelector('.list-page .row .name'));}
          d=await openEditor('RobotEdit');
          if(!restart){
            input(d.querySelector('.wbar input.nm'),'C++ 指令闭环测试');
            for(const [type,value] of [[2,2],[1,25],[3,null]]){d.querySelector('.tile.c'+type).click();await wait(()=>d.querySelector('.pcfg.c'+type));if(value!==null)input(d.querySelector('.pcfg input.inp.num:not(:disabled)'),value);const before=d.querySelectorAll('.flow .blk').length;d.querySelector('.pfoot .btn.ins').click();await wait(()=>d.querySelectorAll('.flow .blk').length===before+1);}
            d.querySelector('.ft .btn.primary').click();await wait(()=>!dialog('RobotEdit')&&feeds.get(10)?.[0]?.InstructionCount===3);
            d=await openEditor('RobotEdit');d.querySelector('.tile.c1').click();await wait(()=>d.querySelector('.pcfg.c1'));d.querySelector('.pfoot .btn.ins').click();await wait(()=>d.querySelectorAll('.flow .blk').length===4);await closeEditor('RobotEdit');
            d=await openEditor('RobotEdit');
          }
          await wait(()=>d.querySelectorAll('.flow .blk').length===3);
          if(d.querySelector('.wbar input.nm').value!=='C++ 指令闭环测试'||!d.querySelector('.flow .blk.c1').textContent.includes('25'))throw Error('robot draft/restart mismatch');
          return {originalEditorButtons:true,originalHexViewEdited:true,originalExportButtons:!restart,originalClipboardButtons:!restart,encryptedExportAndImport:!restart,wrongPasswordRetried:!restart,importGrantRestricted:!restart,clipboardTest:'UI uses isolated memory clipboard; real OS clipboard tested separately in private window station',importNotifications:true,chooserCancelKeptData:true,robotCancelKeptSavedInstructions:true,autoStoresRoundTrip:true,editorRestartPersistence:restart,editorCounts:[feeds.get(9)[0].PacketCount,feeds.get(10)[0].InstructionCount,feeds.get(11)[0].DataCount],chooserTest:'fixed-path seam; production Windows picker UI not automated'};
        };
    )JS" LR"JS(
        const prefs=await call('getPrefs');if(!prefs.isDark||prefs.language!=='zh-CN')throw Error('unexpected fresh DB prefs');
        await call('setLanguage',{language:'ja-JP'});if((await call('getPrefs')).language!=='ja-JP')throw Error('language not saved');
        await call('setLanguage',{language:'zh-CN'});
        document.querySelector('.rack .cd.cy').click();
        await wait(()=>document.querySelector('.side .sb-item')&&feeds.has(8)&&feeds.has(15)&&feeds.has(16));
        const firewallIp='192.0.2.77';
        const settingsButton=[...document.querySelectorAll('.modebar .tb')].find(e=>e.textContent.includes('设置'));
        if(!settingsButton)throw Error('original settings button missing');settingsButton.click();
        await wait(()=>[...document.querySelectorAll('.cm-it')].some(e=>e.querySelector('.tx')?.textContent.trim()==='防火墙设置'));
        const firewallItem=[...document.querySelectorAll('.cm-it')].find(e=>e.querySelector('.tx')?.textContent.trim()==='防火墙设置');
        if(!firewallItem)throw Error('original firewall menu item missing');firewallItem.click();
        const firewallDialog=()=>[...document.querySelectorAll('[role=dialog]')].find(d=>d.querySelector('.sub')?.textContent==='Access Control');
        await wait(()=>firewallDialog()?.querySelector('.lbar .mini'));
        if(!(feeds.get(15)||[]).some(r=>r.IPAddress===firewallIp)){
          firewallDialog().querySelector('.lbar .mini').click();
          const ruleDialog=()=>[...document.querySelectorAll('[role=dialog]')].find(d=>d.querySelector('.sub')?.textContent==='IP Rule');
          await wait(()=>ruleDialog()?.querySelector('input[placeholder="192.168.1.100"]'));
          input(ruleDialog().querySelector('input[placeholder="192.168.1.100"]'),firewallIp);
          ruleDialog().querySelector('.ft .btn.primary').click();
          await wait(()=>!ruleDialog()&&(feeds.get(15)||[]).some(r=>r.IPAddress===firewallIp));
        }
        await wait(()=>[...firewallDialog().querySelectorAll('.trow .ip')].some(e=>e.textContent.trim()===firewallIp));
        firewallDialog().querySelector('.ft .btn:not(.primary)').click();
        await wait(()=>!firewallDialog());
        const firewallIpRuleRoundTrip=true;
        const accountName='C++ 账号闭环测试',accountPassword="P@ss'中";
        const accountNav=[...document.querySelectorAll('.side .sb-item')].find(e=>e.querySelector('.t')?.textContent.trim()==='账号列表');
        if(!accountNav)throw Error('original account navigation missing');accountNav.click();
        await wait(()=>document.querySelector('.list-page.acct .bar .btn.primary')&&feeds.has(5));
        const accountDialog=()=>[...document.querySelectorAll('[role=dialog]')].find(d=>d.querySelector('.sub')?.textContent==='Proxy Account');
        if(!feeds.get(5).some(r=>r.UserName===accountName)){
          document.querySelector('.list-page.acct .bar .btn.primary').click();await wait(()=>accountDialog()?.querySelectorAll('.bd input.inp').length>=2);
          const fields=accountDialog().querySelectorAll('.bd input.inp');input(fields[0],accountName);input(fields[1],accountPassword);
          accountDialog().querySelector('.ft .btn.primary').click();
          await wait(()=>!accountDialog()&&feeds.get(5)?.some(r=>r.UserName===accountName));
        }
        const account=feeds.get(5).find(r=>r.UserName===accountName);if(!account||(await call('getAccountPassword',{id:account.Id})).password!==accountPassword)throw Error('account password round trip failed');
        const batchNames=['C++批量-001','C++批量-002'];
        if(!batchNames.every(name=>feeds.get(5).some(r=>r.UserName===name))){
          const accountButtons=document.querySelectorAll('.list-page.acct .bar .btn');accountButtons[1].click();
          const batchDialog=()=>[...document.querySelectorAll('[role=dialog]')].find(d=>d.querySelector('.sub')?.textContent==='Batch Create');await wait(()=>batchDialog()?.querySelectorAll('.rd').length===2);
          const batch=batchDialog();batch.querySelectorAll('.rd')[1].click();input(batch.querySelector('input.pf'),'C++批量-');const nums=batch.querySelectorAll('input.num');input(nums[0],2);input(nums[1],8);
          [...batch.querySelectorAll('.grp.bar .mini')].find(e=>e.textContent.includes('生成')).click();await wait(()=>batch.querySelectorAll('.drow').length===2);
          const noticeCount=notices.length;[...batch.querySelectorAll('.grp.bar .mini')].find(e=>e.textContent.includes('导出')).click();await wait(()=>notices.length>noticeCount&&notices.at(-1).title==='导出到Excel成功');
          batch.querySelector('.ft .btn.primary').click();await wait(()=>!batchDialog()&&batchNames.every(name=>feeds.get(5).some(r=>r.UserName===name)));
        }
        if(!batchNames.every(name=>feeds.get(5).some(r=>r.UserName===name)))throw Error('batch account restart persistence failed');
        const accountRoundTrip=true;
        const batchAccountRoundTrip=true;
        const filterNav=[...document.querySelectorAll('.side .sb-item')].find(e=>e.querySelector('.t')?.textContent.trim()==='滤镜列表');
        if(!filterNav)throw Error('original filter navigation missing');filterNav.click();
        await wait(()=>document.querySelector('.list-page .bar .btn.primary'));
        if(feeds.get(8).length){
          const old=feeds.get(8);if(old.length!==1||old[0].Name!=='C++ 数据闭环测试'||!old[0].IsEnable)throw Error('restart list persistence failed');
          const restored=(await call('getFilterEdit',{id:old[0].Id})).row;
          if(restored.Modify[0].Index!==-1||!restored.Modify[0].Progression)throw Error('restart editor persistence failed');
          await wait(()=>document.querySelector('.list-page .row .name')?.textContent==='C++ 数据闭环测试');
          const editorResult=await editors(true);await call('__testDone',{ok:true,restartPersistence:true,firewallIpRuleRoundTrip,accountRoundTrip,batchAccountRoundTrip,originalListDom:true,persistentFilterId:old[0].Id,dbFull:info.dbFull,topmostProbe:top.topMost?'passed':'failed-background-request-not-applied',...editorResult});return;
        }
        document.querySelector('.list-page .bar .btn.primary').click();
        await wait(()=>feeds.get(8)?.length===1&&document.querySelector('.list-page .row .name'));
        const id=feeds.get(8)[0].Id;const edit=(await call('getFilterEdit',{id})).row;
        edit.Name='C++ 数据闭环测试';edit.Mode=1;edit.StartFrom=1;
        edit.Search=[{Index:0,Value:'AA',Exclude:true}];edit.Modify=[{Index:-1,Value:'BB',Progression:true,Random:false}];
        const saved=await call('saveFilterEdit',{row:edit});if(!saved.ok)throw Error(saved.error);
        await wait(()=>document.querySelector('.list-page .row .name')?.textContent==='C++ 数据闭环测试');
        document.querySelector('.list-page .row .chk').click();
        await wait(()=>feeds.get(8)?.[0]?.IsEnable===true);
        const back=(await call('getFilterEdit',{id})).row;if(back.Modify[0].Index!==-1)throw Error('negative offset lost');
        const deletion=call('filterListAction',{action:6,ids:[id]});
        await wait(()=>document.querySelector('[role=alertdialog] .btn:not(.primary)'));
        document.querySelector('[role=alertdialog] .btn:not(.primary)').click();await deletion;
        if(!(await call('getFilterEdit',{id})).row)throw Error('cancelled deletion changed data');
        const editorResult=await editors(false);await call('__testDone',{ok:true,titlebar:!!document.querySelector('.titlebar'),modeCards,unsupportedRejected:unsupported,windowRoundTrip:!!top.topMost,topmostProbe:top.topMost?'passed':'failed-background-request-not-applied',firewallIpRuleRoundTrip,accountRoundTrip,batchAccountRoundTrip,originalListDom:true,originalAddAndEnableButtons:true,negativeOffsetRoundTrip:true,cancelledDeletionKeptData:true,persistentFilterId:id,dbFull:info.dbFull,url:location.href,...editorResult});
      })().catch(error=>call('__testDone',{ok:false,error:String(error)}));
    })())JS");
}
void Host::CaptureAndFinish(){
    if(done_)return;
    ComPtr<IStream> output;
    Check(SHCreateStreamOnFileEx((options_.report/L"original-vue.png").c_str(),STGM_CREATE|STGM_WRITE|STGM_SHARE_EXCLUSIVE,FILE_ATTRIBUTE_NORMAL,TRUE,nullptr,&output),"Open preview output");
    Check(view_->CapturePreview(COREWEBVIEW2_CAPTURE_PREVIEW_IMAGE_FORMAT_PNG,output.Get(),Callback<ICoreWebView2CapturePreviewCompletedHandler>([this,output,alive=std::weak_ptr(lifetime_)](HRESULT hr)->HRESULT{
        if(alive.expired()||closing_)return S_OK;
        return Guard([&]{Check(hr,"Capture original Vue preview");Check(output->Commit(STGC_DEFAULT),"Commit preview");Finish(report_.value("originalVueConfirmed",false)&&report_.contains("frontend")&&report_["frontend"].value("ok",false));});
    }).Get()),"Capture preview");
}
void Host::Fail(const std::string& message){
    if(done_||closing_||failure_posted_)return;
    failure_posted_=true;exit_code_=1;
    report_["error"]=message;
    PostMessageW(window_,app_failure,0,0);
}
void Host::Finish(bool success){
    if(done_)return;done_=true;exit_code_=success?0:1;
    report_["result"]=success?"passed":"failed";report_["webMessagesReceived"]=messages_;report_["nativeDrag"]=native_drag_;
    report_["scope"]="Exchange/editor acceptance: original Vue/HexView/export/copy/paste -> native RPC/SQLite/files. UI clipboard uses isolated memory; OS clipboard verified separately on private station. File chooser fixed-path seam. topmostProbe non-gating; no picker UI automation, capture/proxy/injection/execution";
    if(options_.test){std::ofstream file(options_.report/L"host-self-test.json",std::ios::binary);file<<report_.dump(2);file.flush();if(!file)exit_code_=1;}
    PostMessageW(window_,WM_CLOSE,0,0);
}
} // namespace
int WINAPI wWinMain(HINSTANCE,HINSTANCE,PWSTR,int){
    const HRESULT initialized=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    if(FAILED(initialized))return 1;
    int result=1;
    try{Host host(Arguments());result=host.Run();}
    catch(const std::exception& error){
        OutputDebugStringW(Wide(error.what()).c_str());
        if(!wcsstr(GetCommandLineW(),L"--self-test"))MessageBoxW(nullptr,Wide(error.what()).c_str(),L"WPE C++ 启动失败",MB_OK|MB_ICONERROR);
    }
    CoUninitialize();return result;
}
