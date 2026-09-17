#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
namespace wpe::shell {
enum class ClipboardStatus { ok,busy,error };
// One OS attempt. GetClipboardData may block on another app's delayed renderer;
// production calls run on ClipboardWorker, never on the WebView UI thread.
ClipboardStatus ReadClipboardText(HWND owner,std::wstring& text) noexcept;
ClipboardStatus WriteClipboardText(HWND owner,const std::wstring& text) noexcept;
}
