#include <windows.h>
#include <shellapi.h>
#include <WebView2.h>

#include <filesystem>
#include <string>

namespace fs = std::filesystem;

namespace {
std::wstring ModuleFolder() {
    std::wstring path(32768, L'\0');
    const auto count = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (count == 0 || count == path.size()) return {};
    path.resize(count);
    return fs::path(path).parent_path().wstring();
}

bool HasWebView2() {
    LPWSTR version = nullptr;
    const HRESULT hr = GetAvailableCoreWebView2BrowserVersionString(nullptr, &version);
    const bool ok = SUCCEEDED(hr) && version && *version;
    if (version) CoTaskMemFree(version);
    return ok;
}

bool InstallWebView2(const fs::path& installer) {
    SHELLEXECUTEINFOW exec{sizeof(exec)};
    exec.fMask = SEE_MASK_NOCLOSEPROCESS;
    exec.lpVerb = L"runas";
    exec.lpFile = installer.c_str();
    exec.lpParameters = L"/install";
    exec.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&exec)) return false;
    if (exec.hProcess) {
        WaitForSingleObject(exec.hProcess, INFINITE);
        CloseHandle(exec.hProcess);
    }
    return HasWebView2();
}

int Fail(const wchar_t* text) {
    MessageBoxW(nullptr, text, L"WPE-陈北玄 启动失败", MB_OK | MB_ICONERROR);
    return 1;
}
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    const fs::path folder = ModuleFolder();
    if (folder.empty()) return Fail(L"无法确定程序目录。");

    if (!HasWebView2()) {
        const auto installer = folder / L"MicrosoftEdgeWebView2Setup.exe";
        if (!fs::is_regular_file(installer)) {
            return Fail(L"未检测到 WebView2 Runtime，且内置安装器缺失。\n\n请重新解压完整发布包后再启动。");
        }
        if (!InstallWebView2(installer)) {
            return Fail(L"WebView2 Runtime 尚未安装完成。\n\n请在安装提示中允许安装，然后重新打开 WPE。");
        }
    }

    const auto app = folder / L"wpe64-app.exe";
    if (!fs::is_regular_file(app)) return Fail(L"内置 WPE 主程序缺失：wpe64-app.exe。");

    std::wstring localAppData(32768, L'\0');
    const auto dataLength = GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData.data(),
                                                     static_cast<DWORD>(localAppData.size()));
    if (dataLength == 0 || dataLength >= localAppData.size())
        return Fail(L"无法确定当前用户的数据目录。");
    localAppData.resize(dataLength);
    const auto data = fs::path(localAppData) / L"WPE64" / L"2.3.0";
    std::error_code error;
    fs::create_directories(data, error);
    if (error) return Fail(L"当前用户数据目录不可写，无法启动 WPE。");

    std::wstring command = L"\"" + app.wstring() + L"\" --data-dir \"" + data.wstring() + L"\"";
    STARTUPINFOW startup{sizeof(startup)};
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, 0, nullptr,
                        folder.c_str(), &startup, &process)) {
        return Fail(L"无法启动 WPE 主程序。");
    }
    CloseHandle(process.hThread);

    // When launched from the one-file SFX package, the SFX host removes its
    // temporary extraction directory as soon as this process exits. Keep the
    // bootstrapper alive until the UI process exits so wwwroot, hook DLLs and
    // the other extracted files remain available for the whole session.
    const DWORD waitResult = WaitForSingleObject(process.hProcess, INFINITE);
    DWORD exitCode = 1;
    if (waitResult == WAIT_OBJECT_0) {
        GetExitCodeProcess(process.hProcess, &exitCode);
    }
    CloseHandle(process.hProcess);
    return static_cast<int>(exitCode);
}
