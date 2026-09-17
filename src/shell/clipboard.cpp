#include "clipboard.h"
#include <algorithm>
#include <cstring>
#include <limits>
namespace wpe::shell {
namespace {
struct Close {~Close(){CloseClipboard();}};
struct Memory {HGLOBAL handle{};~Memory(){if(handle)GlobalFree(handle);}};
struct Unlock {HGLOBAL handle{};~Unlock(){GlobalUnlock(handle);}};
}
ClipboardStatus ReadClipboardText(HWND owner,std::wstring& text) noexcept{
    text.clear();if(!OpenClipboard(owner))return ClipboardStatus::busy;Close close;
    if(!IsClipboardFormatAvailable(CF_UNICODETEXT))return ClipboardStatus::ok;
    const auto handle=GetClipboardData(CF_UNICODETEXT);if(!handle)return ClipboardStatus::error;
    const auto count=GlobalSize(handle)/sizeof(wchar_t);const auto ptr=static_cast<const wchar_t*>(GlobalLock(handle));if(!ptr)return ClipboardStatus::error;Unlock unlock{handle};
    try{const auto end=std::find(ptr,ptr+count,L'\0');if(end==ptr+count)return ClipboardStatus::error;text.assign(ptr,end);return ClipboardStatus::ok;}
    catch(...){return ClipboardStatus::error;}
}
ClipboardStatus WriteClipboardText(HWND owner,const std::wstring& text) noexcept{
    Memory memory;
    if(!text.empty()){
        if(text.size()>std::numeric_limits<SIZE_T>::max()/sizeof(wchar_t)-1)return ClipboardStatus::error;
        const auto bytes=(text.size()+1)*sizeof(wchar_t);memory.handle=GlobalAlloc(GMEM_MOVEABLE,bytes);if(!memory.handle)return ClipboardStatus::error;
        auto ptr=GlobalLock(memory.handle);if(!ptr)return ClipboardStatus::error;
        std::memcpy(ptr,text.c_str(),bytes);GlobalUnlock(memory.handle);
    }
    if(!OpenClipboard(owner))return ClipboardStatus::busy;Close close;
    if(!EmptyClipboard())return ClipboardStatus::error;
    if(memory.handle){if(!SetClipboardData(CF_UNICODETEXT,memory.handle))return ClipboardStatus::error;memory.handle=nullptr;} // ownership transferred to Windows
    return ClipboardStatus::ok;
}
}
