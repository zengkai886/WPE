#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <windowsx.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <dwmapi.h>
#include <wrl.h>
#include <WebView2.h>
#include "web_bridge.h"
#include "data_worker.h"
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>

using Microsoft::WRL::Callback;
using Microsoft::WRL::ComPtr;
using wpe::shell::Json;
using wpe::shell::WebBridge;
namespace fs=std::filesystem;
namespace {
constexpr UINT app_ready=WM_APP+1, app_drag=WM_APP+2, app_test=WM_APP+3, app_failure=WM_APP+4;
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
        data_.reset();
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
        if(data_&&bridge_&&!closing_)data_->Drain([this](std::string name,Json value){bridge_->PushEvent(std::move(name),std::move(value));});
        if(options_.test && std::chrono::steady_clock::now()-started_>std::chrono::seconds(30))Fail("WebView2 self-test timed out");
        if(!options_.test && !revealed_ && std::chrono::steady_clock::now()-started_>std::chrono::seconds(4)){revealed_=true;ShowWindow(window_,SW_SHOW);}
        if(!options_.test && !ready_ && std::chrono::steady_clock::now()-started_>std::chrono::seconds(30))Fail("原 Vue 页面未在 30 秒内完成初始化，请检查 WebView2 Runtime 和 wwwroot 资源。");
        return 0;
    case app_ready:
        if(!ready_){ready_=true;if(!options_.test){revealed_=true;ShowWindow(window_,SW_SHOW);}else BeginTest();}
        return 0;
    case app_drag:ReleaseCapture();SendMessageW(window_,WM_NCLBUTTONDOWN,HTCAPTION,0);return 0;
    case app_test:CaptureAndFinish();return 0;
    case app_failure:
        // Posted from WebView2 callbacks: no nested modal pump in those callbacks.
        if(!options_.test)MessageBoxW(window_,Wide(report_.value("error",std::string("Native host failed"))).c_str(),L"WPE C++ 宿主错误",MB_OK|MB_ICONERROR);
        Finish(false);return 0;
    case WM_CLOSE:
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
        return Guard([&]{CoString uri;Check(args->get_Uri(&uri.value),"Navigation URI");if(!WebBridge::IsAllowedSource(Utf8(uri.value)))Check(args->put_Cancel(TRUE),"Block navigation");else bridge_->FailAllPending();});
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
            auto submit=[this,method,args,done]{data_->Submit(method,args,done);};
            if(wpe::shell::DataService::NeedsConfirmation(method,args)){
                bridge_->Ask("confirm",{{"title","确认操作"},{"content","确定删除选中的数据吗？此操作不可撤销。"},{"icon",2}},
                    [submit=std::move(submit),done](Json answer){if(answer==true)submit();else done({{"ok",true},{"delta",0}},{});});
            }else submit();
        });
    }
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
        return Json{{"topMost",(GetWindowLongPtrW(window_,GWL_EXSTYLE)&WS_EX_TOPMOST)!=0}};});
    bridge_->Register("startDragWindow",[this](const Json&){PostMessageW(window_,app_drag,0,0);return Json{{"ok",true}};});
    if(options_.test){
        bridge_->Register("__testConfirm",[this](const Json&){
            bridge_->Ask("confirm",{{"title","C++ ↔ 原 Vue 双向桥测试"},{"content","此对话框由原 Vue 渲染，自动测试将点击确定。"},{"icon",2}},[this](Json answer){report_["originalVueConfirmed"]=answer;bridge_->PushEvent("toast",{{"level",1},{"text","NATIVE_BRIDGE_EVENT_OK"}});});return Json{{"ok",true}};});
        bridge_->Register("__testDone",[this](const Json& args){report_["frontend"]=args;PostMessageW(window_,app_test,0,0);return Json{{"ok",true}};});
    }
}
void Host::Script(const std::wstring& script){
    Check(view_->ExecuteScript(script.c_str(),Callback<ICoreWebView2ExecuteScriptCompletedHandler>([this,alive=std::weak_ptr(lifetime_)](HRESULT hr,LPCWSTR)->HRESULT{
        if(alive.expired()||closing_)return S_OK;
        if(FAILED(hr))Fail("ExecuteScript failed");return S_OK;
    }).Get()),"Execute test script");
}
void Host::BeginTest(){
    Script(LR"JS((()=>{
      const w=chrome.webview; let seq=0; const pending=new Map();
      w.addEventListener('message',e=>{const m=e.data;if(m.type==='result'&&pending.has(m.id)){const p=pending.get(m.id);pending.delete(m.id);m.ok?p.resolve(m.result):p.reject(new Error(m.error));}});
      const call=(method,args={})=>new Promise((resolve,reject)=>{const id='selftest-'+(++seq);pending.set(id,{resolve,reject});w.postMessage({type:'call',id,method,args});});
      const wait=async(f)=>{for(let i=0;i<150;i++){if(f())return;await new Promise(r=>setTimeout(r,40));}throw Error('DOM condition timed out');};
      (async()=>{
        const info=await call('getSystemCheck');if(info.version!=='C++ DATA-dev')throw Error('wrong native host');
        await wait(()=>document.querySelector('.win .titlebar')&&document.querySelectorAll('.rack .cd').length>=2);
        const top=await call('setTopMost',{on:true});if(!top.topMost)throw Error('topmost failed');
        const normal=await call('setTopMost',{on:false});if(normal.topMost)throw Error('topmost reset failed');
        let unsupported=false;try{await call('__unimplemented_capture');}catch(e){unsupported=String(e).includes('尚未实现');}
        if(!unsupported)throw Error('unsupported method falsely succeeded');
        await call('__testConfirm');
        await wait(()=>document.querySelector('[role=alertdialog] .btn.primary'));
        document.querySelector('[role=alertdialog] .btn.primary').click();
        await wait(()=>document.body.textContent.includes('NATIVE_BRIDGE_EVENT_OK'));
        const modeCards=document.querySelectorAll('.rack .cd').length;
        const feeds=new Map();w.addEventListener('message',e=>{const m=e.data;if(m.type==='event'&&m.name==='feed:replace')feeds.set(m.data.list,m.data.rows);});
        const prefs=await call('getPrefs');if(!prefs.isDark||prefs.language!=='zh-CN')throw Error('unexpected fresh DB prefs');
        await call('setLanguage',{language:'ja-JP'});if((await call('getPrefs')).language!=='ja-JP')throw Error('language not saved');
        await call('setLanguage',{language:'zh-CN'});
        document.querySelector('.rack .cd.cy').click();
        await wait(()=>document.querySelector('.side .sb-item')&&feeds.has(8));
        const filterNav=[...document.querySelectorAll('.side .sb-item')].find(e=>e.querySelector('.t')?.textContent.trim()==='滤镜列表');
        if(!filterNav)throw Error('original filter navigation missing');filterNav.click();
        await wait(()=>document.querySelector('.list-page .bar .btn.primary'));
        if(feeds.get(8).length){
          const old=feeds.get(8);if(old.length!==1||old[0].Name!=='C++ 数据闭环测试'||!old[0].IsEnable)throw Error('restart list persistence failed');
          const restored=(await call('getFilterEdit',{id:old[0].Id})).row;
          if(restored.Modify[0].Index!==-1||!restored.Modify[0].Progression)throw Error('restart editor persistence failed');
          await wait(()=>document.querySelector('.list-page .row .name')?.textContent==='C++ 数据闭环测试');
          await call('__testDone',{ok:true,restartPersistence:true,originalListDom:true,persistentFilterId:old[0].Id,dbFull:info.dbFull});return;
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
        await call('__testDone',{ok:true,titlebar:!!document.querySelector('.titlebar'),modeCards,unsupportedRejected:unsupported,windowRoundTrip:true,originalListDom:true,originalAddAndEnableButtons:true,negativeOffsetRoundTrip:true,cancelledDeletionKeptData:true,persistentFilterId:id,dbFull:info.dbFull,url:location.href});
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
    report_["scope"]="Original Vue buttons -> async native RPC -> SQLite commit -> feed -> original list DOM; cancelled delete; no capture/proxy/injection";
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
