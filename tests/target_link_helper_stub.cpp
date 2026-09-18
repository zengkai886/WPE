#include <Windows.h>

// Deliberately never signals the ready event.  TargetLink's bounded wait and
// cleanup path use this executable to exercise helper-timeout handling without
// requiring a real cross-architecture target for the negative case.
int wmain(int, wchar_t**) {
    Sleep(60000);
    return 0;
}
