# Engineering rules

- Follow the active rewrite spec in `contracts/active-spec.json` (`docs/用户提供-重写工程文档-更新版.md`); record conflicts in `docs/实施校核.md` instead of silently changing requirements. Retain all original Vue; native WebView2 is the primary host, not Qt.
- Production code is C++20. C# exists only as the original test oracle; no Java runtime or original C# business process is required by the C++ library.
- Test the public seams explicitly specified by sections 3 and 4: primitive codec, stream framing, packet frames, bounded queue. Golden wire bytes come from the unchanged original C# source, never from the C++ implementation under test.
- Use explicit-width integers, checked lengths, RAII and owned immutable data where lifetime crosses threads. No undefined signed shifts or dangling spans.
- Preserve null versus empty and original .NET Framework UTF-8/GUID semantics. Do not silently revise protocol v4.
- No file I/O, network I/O, UI or formatting in a future Winsock detour. Do not claim mutexes are lock-free or offer guaranteed nanosecond latency.
- Compiler warnings are errors. Both Win32 and x64 must build and pass the same tests for completed common code.
- Each test run uses a fresh build directory and records hashes, tool versions and scope. No false product-completion or GUI claims.
- User source ZIP and uploaded document are read-only inputs. Build outputs stay outside the source tree.
