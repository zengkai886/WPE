#include "shell/clipboard.h"
#include "shell/clipboard_worker.h"
#include <future>
#include <iostream>
#include <stdexcept>
#include <thread>
using namespace wpe::shell;
namespace {
void Check(bool b,const char* message){if(!b)throw std::runtime_error(message);}
class IsolatedClipboard {
    HWINSTA original_=GetProcessWindowStation(),station_{};
    HDESK originalDesktop_=GetThreadDesktop(GetCurrentThreadId()),desktop_{};
public:
    HWND owner{};
    IsolatedClipboard(){try{
        const auto name=L"WpeClipboardTest-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64());
        station_=CreateWindowStationW(name.c_str(),0,WINSTA_ALL_ACCESS,nullptr);
        if(!station_){SetLastError(ERROR_SUCCESS);station_=CreateWindowStationW(nullptr,0,WINSTA_ALL_ACCESS,nullptr);if(station_&&GetLastError()==ERROR_ALREADY_EXISTS){CloseWindowStation(station_);station_=nullptr;}}
        Check(station_!=nullptr,"Cannot create isolated window station; interactive clipboard was NOT touched");
        Check(SetProcessWindowStation(station_)!=FALSE,"Cannot select isolated window station");
        desktop_=CreateDesktopW(L"ClipboardTest",nullptr,nullptr,0,GENERIC_ALL,nullptr);Check(desktop_!=nullptr,"Cannot create isolated desktop");
        Check(SetThreadDesktop(desktop_)!=FALSE,"Cannot select isolated desktop");
        owner=CreateWindowExW(0,L"STATIC",L"ClipboardTest",0,0,0,0,0,HWND_MESSAGE,nullptr,nullptr,nullptr);Check(owner!=nullptr,"Cannot create clipboard owner");
    }catch(...){Cleanup();throw;}}
    ~IsolatedClipboard(){Cleanup();}
private:
    void Cleanup(){if(owner)DestroyWindow(owner);SetThreadDesktop(originalDesktop_);if(desktop_)CloseDesktop(desktop_);SetProcessWindowStation(original_);if(station_)CloseWindowStation(station_);}
};
class DelayedRenderer {
    HWND window_{};std::thread thread_;
    static LRESULT CALLBACK Proc(HWND window,UINT msg,WPARAM w,LPARAM l){
        if(msg==WM_RENDERFORMAT){std::this_thread::sleep_for(std::chrono::milliseconds(1300));auto h=GlobalAlloc(GMEM_MOVEABLE,6);if(h){auto p=static_cast<wchar_t*>(GlobalLock(h));if(p){p[0]=L'O';p[1]=L'K';p[2]=0;GlobalUnlock(h);if(!SetClipboardData(CF_UNICODETEXT,h))GlobalFree(h);}else GlobalFree(h);}return 0;}
        if(msg==WM_CLOSE){DestroyWindow(window);return 0;}if(msg==WM_DESTROY){PostQuitMessage(0);return 0;}return DefWindowProcW(window,msg,w,l);
    }
public:
    DelayedRenderer(){std::promise<HWND> ready;auto result=ready.get_future();const auto desktop=GetThreadDesktop(GetCurrentThreadId());
        thread_=std::thread([&ready,desktop]{SetThreadDesktop(desktop);WNDCLASSW c{};c.lpfnWndProc=Proc;c.lpszClassName=L"WpeDelayedClipboardTest";c.hInstance=GetModuleHandleW(nullptr);RegisterClassW(&c);
            const auto window=CreateWindowExW(0,c.lpszClassName,L"isolated",0,0,0,0,0,HWND_MESSAGE,nullptr,c.hInstance,nullptr);
            if(!window||!OpenClipboard(window)){if(window)DestroyWindow(window);ready.set_value(nullptr);return;}
            EmptyClipboard();SetClipboardData(CF_UNICODETEXT,nullptr);CloseClipboard();ready.set_value(window);MSG msg{};while(GetMessageW(&msg,nullptr,0,0)>0)DispatchMessageW(&msg);
        });window_=result.get();if(!window_){thread_.join();throw std::runtime_error("Cannot create delayed-render test owner");}
    }
    ~DelayedRenderer(){PostMessageW(window_,WM_CLOSE,0,0);thread_.join();}
};
}
int main(){try{
    // Private station owns a DIFFERENT Windows clipboard. Never backs up, logs,
    // changes or restores the user's interactive desktop clipboard.
    IsolatedClipboard isolated;const auto window=isolated.owner;std::wstring out;
    Check(WriteClipboardText(window,L"")==ClipboardStatus::ok,"clear failed");Check(ReadClipboardText(window,out)==ClipboardStatus::ok&&out.empty(),"empty read");
    for(const auto& value:{std::wstring(L"AA FF 80\r\n01 02"),std::wstring(L"中文\t\U0001F600 <&>"),std::wstring(65536,L'X')}){
        Check(WriteClipboardText(window,value)==ClipboardStatus::ok,"write failed");Check(ReadClipboardText(window,out)==ClipboardStatus::ok&&out==value,"Unicode roundtrip failed");
    }
    Check(WriteClipboardText(window,std::wstring(L"A\0B",3))==ClipboardStatus::ok,"embedded NUL write");Check(ReadClipboardText(window,out)==ClipboardStatus::ok&&out==L"A","NUL termination differs");
    std::promise<bool> ready;auto opened=ready.get_future();std::promise<void> release;auto released=release.get_future();
    std::thread holder([&]{const bool ok=OpenClipboard(nullptr)!=FALSE;ready.set_value(ok);released.wait();if(ok)CloseClipboard();});
    const bool locked=opened.get();const auto read=ReadClipboardText(window,out),write=WriteClipboardText(window,L"must not replace");release.set_value();holder.join();
    Check(locked&&read==ClipboardStatus::busy&&write==ClipboardStatus::busy,"contention must report busy");
    Check(ReadClipboardText(window,out)==ClipboardStatus::ok&&out==L"A","busy write changed data");
    Check(WriteClipboardText(window,L"")==ClipboardStatus::ok,"final clear failed");
    {
        DelayedRenderer renderer;ClipboardWorker worker;bool done=false,ok=false;std::wstring value;
        const auto start=std::chrono::steady_clock::now();worker.Submit(false,{},[&](bool success,std::wstring text){done=true;ok=success;value=std::move(text);});
        Check(std::chrono::steady_clock::now()-start<std::chrono::milliseconds(100),"Clipboard submission blocked UI");
        int heartbeat=0;while(!done&&std::chrono::steady_clock::now()-start<std::chrono::seconds(5)){worker.Drain();++heartbeat;std::this_thread::sleep_for(std::chrono::milliseconds(5));}
        Check(done&&ok&&value==L"OK"&&heartbeat>=30,"Delayed rendering blocked drain loop or lost result");
        bool wrote=false;worker.Submit(true,L"worker-roundtrip",[&](bool success,std::wstring){wrote=success;});
        const auto until=std::chrono::steady_clock::now()+std::chrono::seconds(3);while(!wrote&&std::chrono::steady_clock::now()<until){worker.Drain();std::this_thread::sleep_for(std::chrono::milliseconds(5));}
        Check(wrote&&ReadClipboardText(window,out)==ClipboardStatus::ok&&out==L"worker-roundtrip","Worker write did not reach real clipboard");
        const auto replaced=std::chrono::steady_clock::now();Check(WriteClipboardText(window,L"replacement")==ClipboardStatus::ok,"Other owner cannot replace clipboard");
        Check(std::chrono::steady_clock::now()-replaced<std::chrono::milliseconds(500),"Worker did not pump ownership messages");
    }
    Check(WriteClipboardText(window,L"")==ClipboardStatus::ok,"worker final clear failed");
    std::cout<<"PASS: real Win32 clipboard Unicode/empty/NUL/64K UTF-16 units/lock ownership; delayed-render worker kept UI responsive; private window station; user's clipboard untouched\n";return 0;
}catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<"; Win32="<<GetLastError()<<'\n';return 1;}}
