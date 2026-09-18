#include <Windows.h>
#include <string>

int wmain(int argc, wchar_t** argv) {
    if (argc != 2) return 3;
    const std::wstring module = argv[1];
    for (int i = 0; i < 1000; ++i) {
        if (GetModuleHandleW(module.c_str())) return 0;
        Sleep(5);
    }
    return 4;
}
