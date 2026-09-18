#include "shell/process_injector.h"
#include "shell/data_worker.h"
#include "common/ipc_codec.h"
#include "common/ipc_session.h"
#include "common/packet_frame.h"
#include <Windows.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <string_view>
#include <vector>

using namespace std::chrono_literals;

namespace {
std::size_t checks{};
void Check(bool value, const char* message) {
    ++checks;
    if (!value) throw std::runtime_error(message);
}
template<class F> void Throws(F&& action, const char* message) {
    bool threw = false;
    try { action(); } catch (const wpe::ProtocolError&) { threw = true; }
    Check(threw, message);
}

std::string SessionId() {
    std::ostringstream out;
    out << std::hex << std::setfill('0')
        << std::setw(8) << GetCurrentProcessId()
        << std::setw(8) << GetTickCount()
        << std::setw(8) << GetCurrentThreadId()
        << std::setw(8) << (GetTickCount() ^ 0x5a17c3e9U);
    return out.str();
}

struct ProcessCleanup final {
    HANDLE handle{};
    ~ProcessCleanup() {
        if (!handle) return;
        (void)TerminateProcess(handle, ERROR_CANCELLED);
        (void)WaitForSingleObject(handle, 3000);
    }
};

struct HandleCleanup final {
    HANDLE value{};
    ~HandleCleanup() { if (value) CloseHandle(value); }
};

struct DirectoryCleanup final {
    std::filesystem::path path;
    ~DirectoryCleanup() {
        std::error_code error;
        std::filesystem::remove_all(path, error);
    }
};

bool ContainsHookState(const std::vector<wpe::ByteBuffer>& events, bool wanted) {
    for (const auto& bytes : events) {
        try {
            wpe::IpcReader event(bytes);
            if (event.U8() == static_cast<std::uint8_t>(wpe::IpcEvent::HookState) &&
                event.Bool() == wanted) return true;
        } catch (...) {}
    }
    return false;
}

bool ContainsStoreAdded(const std::vector<wpe::ByteBuffer>& events,
                        const wpe::Guid& wanted, std::string_view expected) {
    for (const auto& frame : events) {
        try {
            wpe::IpcReader reader(frame);
            if (reader.U8() != static_cast<std::uint8_t>(wpe::IpcEvent::StoreAdded) ||
                reader.Guid_() != wanted)
                continue;
            const auto bytes = reader.Bytes();
            if (!bytes || bytes->size() != expected.size() || reader.Remaining() != 0)
                continue;
            if (std::equal(bytes->begin(), bytes->end(), expected.begin())) return true;
        } catch (...) {}
    }
    return false;
}

bool ContainsPacket(const std::vector<wpe::ByteBuffer>& frames, std::uint8_t type,
                    std::string_view expected) {
    for (const auto& frame : frames) {
        try {
            const auto packet = wpe::PacketFrame::Decode(frame);
            if (packet.packet_type != type || !packet.raw || packet.raw->size() != expected.size())
                continue;
            if (std::equal(packet.raw->begin(), packet.raw->end(), expected.begin()) &&
                packet.modified == packet.raw && packet.from && packet.to &&
                !packet.from->empty() && !packet.to->empty()) return true;
        } catch (...) {}
    }
    return false;
}

bool ContainsFilteredPacket(const std::vector<wpe::ByteBuffer>& frames, std::uint8_t type,
                            std::string_view raw, std::string_view modified) {
    for (const auto& frame : frames) {
        try {
            const auto packet = wpe::PacketFrame::Decode(frame);
            if (packet.packet_type == type && packet.filter_action == 0 && packet.raw &&
                packet.modified && packet.raw->size() == raw.size() &&
                packet.modified->size() == modified.size() &&
                std::equal(packet.raw->begin(), packet.raw->end(), raw.begin()) &&
                std::equal(packet.modified->begin(), packet.modified->end(), modified.begin()))
                return true;
        } catch (...) {}
    }
    return false;
}

bool ContainsSendSuccess(const std::vector<wpe::ByteBuffer>& events, const wpe::Guid& wanted) {
    for (const auto& frame : events) {
        try {
            wpe::IpcReader reader(frame);
            if (reader.U8() != static_cast<std::uint8_t>(wpe::IpcEvent::Stats)) continue;
            (void)reader.Bool(); (void)reader.Bool();
            const auto filter_count = reader.I32();
            if (filter_count < 0 || filter_count > 1000) continue;
            for (std::int32_t i = 0; i < filter_count; ++i) {
                (void)reader.Guid_(); (void)reader.I64();
            }
            const auto send_count = reader.I32();
            if (send_count < 0 || send_count > 1000) continue;
            for (std::int32_t i = 0; i < send_count; ++i) {
                const auto id = reader.Guid_();
                (void)reader.I64();
                const auto success = reader.I64();
                (void)reader.I64();
                if (id == wanted && success > 0) return true;
            }
        } catch (...) {}
    }
    return false;
}

bool ContainsFilterExecution(const std::vector<wpe::ByteBuffer>& events) {
    for (const auto& frame : events) {
        try {
            wpe::IpcReader reader(frame);
            if (reader.U8() != static_cast<std::uint8_t>(wpe::IpcEvent::Stats)) continue;
            (void)reader.Bool(); (void)reader.Bool();
            const auto filter_count = reader.I32();
            if (filter_count < 0 || filter_count > 1000) continue;
            for (std::int32_t i = 0; i < filter_count; ++i) {
                (void)reader.Guid_(); (void)reader.I64();
            }
            const auto send_count = reader.I32();
            if (send_count < 0 || send_count > 1000) continue;
            for (std::int32_t i = 0; i < send_count; ++i) {
                (void)reader.Guid_(); (void)reader.I64(); (void)reader.I64(); (void)reader.I64();
            }
            return reader.I64() > 0;
        } catch (...) {}
    }
    return false;
}

wpe::Text Text(std::string_view value) {
    std::u16string result;
    for (const unsigned char character : value) result.push_back(static_cast<char16_t>(character));
    return result;
}

template<class F>
void PumpData(wpe::shell::DataWorker& worker, F&& predicate,
              const wpe::shell::DataService::Emit& emit = [](std::string, wpe::shell::Json) {}) {
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (!predicate() && std::chrono::steady_clock::now() < deadline) {
        worker.Drain(emit);
        std::this_thread::sleep_for(2ms);
    }
    worker.Drain(emit);
    Check(predicate(), "data worker deadline exceeded");
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc != 4) throw std::runtime_error("target, production hook and probe DLL paths required");
        const std::filesystem::path target = argv[1];
        const std::filesystem::path hook = argv[2];
        const std::filesystem::path probe = argv[3];
        const auto session_id = SessionId();

        // Keep the production target event path and the shell-side warehouse
        // commit in one regression test.  The directory is unique per run so
        // a failed test cannot reuse a stale warehouse row or filter snapshot.
        const auto warehouse_root = std::filesystem::temp_directory_path() /
                                    "wpe64-warehouse-pipeline" / session_id;
        DirectoryCleanup warehouse_cleanup{warehouse_root};
        std::filesystem::create_directories(warehouse_root);
        auto data_worker = std::make_unique<wpe::shell::DataWorker>(warehouse_root / "data.db");
        std::string warehouse_id;
        bool warehouse_ready = false;
        std::string warehouse_setup_error;
        data_worker->Submit("addWareHouse", {}, [&](wpe::shell::Json value, std::string error) {
            warehouse_setup_error = std::move(error);
            if (warehouse_setup_error.empty() && value.contains("id")) {
                warehouse_id = value.at("id").get<std::string>();
                warehouse_ready = true;
            }
        });
        PumpData(*data_worker, [&] { return warehouse_ready || !warehouse_setup_error.empty(); });
        Check(warehouse_setup_error.empty() && !warehouse_id.empty(),
              "warehouse setup before injected session");

        const std::wstring event_suffix = std::to_wstring(GetCurrentProcessId()) + L"-" +
                                          std::to_wstring(GetTickCount64());
        const std::wstring start_name = L"Local\\WPE64-NetworkStart-" + event_suffix;
        const std::wstring ready_name = L"Local\\WPE64-NetworkReady-" + event_suffix;
        const std::wstring replay_name = L"Local\\WPE64-NetworkReplay-" + event_suffix;
        const std::wstring replay_done_name = L"Local\\WPE64-NetworkReplayDone-" + event_suffix;
        const std::wstring send_list_name = L"Local\\WPE64-NetworkSendList-" + event_suffix;
        const std::wstring done_name = L"Local\\WPE64-NetworkDone-" + event_suffix;
        HandleCleanup start_event{CreateEventW(nullptr, TRUE, FALSE, start_name.c_str())};
        HandleCleanup ready_event{CreateEventW(nullptr, TRUE, FALSE, ready_name.c_str())};
        HandleCleanup replay_event{CreateEventW(nullptr, TRUE, FALSE, replay_name.c_str())};
        HandleCleanup replay_done_event{CreateEventW(nullptr, TRUE, FALSE, replay_done_name.c_str())};
        HandleCleanup send_list_event{CreateEventW(nullptr, TRUE, FALSE, send_list_name.c_str())};
        HandleCleanup done_event{CreateEventW(nullptr, TRUE, FALSE, done_name.c_str())};
        if (!start_event.value || !ready_event.value || !replay_event.value ||
            !replay_done_event.value || !send_list_event.value || !done_event.value)
            throw std::runtime_error("network test events could not be created");

        std::mutex event_mutex;
        std::condition_variable event_ready;
        std::vector<wpe::ByteBuffer> events;
        std::mutex packet_mutex;
        std::condition_variable packet_ready;
        std::vector<wpe::ByteBuffer> packets;
        std::atomic_bool store_event_seen{false};
        std::atomic_bool store_commit_done{false};
        std::mutex store_commit_mutex;
        wpe::shell::Json store_commit_value;
        std::string store_commit_error;
        wpe::ShellIpcSession shell(session_id, [&](wpe::ByteBuffer packet) {
            {
                std::lock_guard lock(packet_mutex);
                packets.push_back(std::move(packet));
            }
            packet_ready.notify_all();
        }, [&](wpe::ByteBuffer event) {
            bool is_store_event = false;
            try {
                wpe::IpcReader reader(event);
                is_store_event = reader.U8() == static_cast<std::uint8_t>(wpe::IpcEvent::StoreAdded);
            } catch (...) {}
            if (is_store_event) {
                store_event_seen.store(true);
                // SubmitStoreEvent is intentionally thread-safe: target event
                // delivery occurs on ShellIpcSession's event thread while the
                // completion is drained on the host/UI thread below.
                data_worker->SubmitStoreEvent(event, [&](wpe::shell::Json value, std::string error) {
                    std::lock_guard lock(store_commit_mutex);
                    store_commit_value = std::move(value);
                    store_commit_error = std::move(error);
                    store_commit_done.store(true);
                });
            }
            {
                std::lock_guard lock(event_mutex);
                events.push_back(std::move(event));
            }
            event_ready.notify_all();
        }, {}, wpe::ShellSessionOptions{50ms});

        const std::wstring target_arguments = L"\"" + start_name + L"\" \"" + ready_name +
            L"\" \"" + replay_name + L"\" \"" + replay_done_name + L"\" \"" +
            send_list_name + L"\" \"" + done_name + L"\"";
        auto child = wpe::shell::ProcessInjector::LaunchSuspended(target, target_arguments);
        ProcessCleanup cleanup{child.ProcessHandle()};
        child.Resume();
        Check(WaitForSingleObject(child.ProcessHandle(), 0) == WAIT_TIMEOUT,
              "session target is running");

        wpe::shell::InjectionOptions options{session_id, 5000, false};
        auto missing_shell = options;
        missing_shell.session = "11111111222222223333333344444444";
        missing_shell.connect_timeout_ms = 100;
        wpe::shell::ProcessInjector::InjectAndStart(child.Pid(), hook, missing_shell, 2s);
        ++checks;
        Sleep(300); // the target worker must self-shutdown when no shell owns those pipes
        Throws([&] {
            auto invalid = options;
            invalid.session = "not-a-guid";
            wpe::shell::ProcessInjector::InjectAndStart(child.Pid(), hook, invalid, 2s);
        }, "invalid session rejected before bootstrap");
        Throws([&] {
            wpe::shell::ProcessInjector::InjectAndStart(child.Pid(), probe, options, 2s);
        }, "DLL without WpeStart export rejected");

        wpe::shell::ProcessInjector::InjectAndStart(child.Pid(), hook, options, 5s);
        shell.Accept(5000);
        shell.Start();
        Check(shell.State() == wpe::IpcLinkState::Attached, "injected target session attached");
        Check(shell.TargetPid() == static_cast<std::int32_t>(child.Pid()),
              "Hello reports injected target PID");
        Check(shell.TargetIs64() == (sizeof(void*) == 8), "Hello reports target architecture");

        {
            std::unique_lock lock(event_mutex);
            Check(event_ready.wait_for(lock, 2s, [&] { return !events.empty(); }),
                  "injected target emitted initial HookState");
            wpe::IpcReader event(events.front());
            Check(event.U8() == static_cast<std::uint8_t>(wpe::IpcEvent::HookState),
                  "initial injected event type");
            Check(!event.Bool(), "hook state is off before StartHook");
            (void)event.Bool(); (void)event.Bool(); (void)event.Bool();
            Check(event.Remaining() == 0, "initial HookState has exact v4 fields");
        }

        wpe::IpcWriter flags;
        for (int i = 0; i < 12; ++i) flags.Bool((i % 2) == 0);
        wpe::IpcWriter set_config;
        set_config.U8(static_cast<std::uint8_t>(wpe::IpcCommand::SetConfig));
        set_config.U8(static_cast<std::uint8_t>(wpe::ConfigKind::HookFlags));
        set_config.Bytes(flags.ToArray());
        shell.CallVoid(set_config.ToArray());
        ++checks;

        wpe::IpcWriter filter_payload;
        filter_payload.I32(1);
        filter_payload.Bool(true);
        filter_payload.Guid_(wpe::Guid::Parse("00112233-4455-6677-8899-aabbccddeeff"));
        filter_payload.Str(Text("cross-process-filter"));
        filter_payload.Bool(false); filter_payload.Str(Text(""));
        filter_payload.Bool(false); filter_payload.Str(Text(""));
        filter_payload.Bool(false); filter_payload.Str(Text(""));
        filter_payload.Bool(false); filter_payload.Str(Text(""));
        filter_payload.I32(0); filter_payload.I32(0);
        // A matching filter both replaces the packet and executes a
        // WareHouse trigger.  This is the real target -> IPC StoreAdded path
        // exercised by the P4-1 regression below.
        filter_payload.Bool(true); filter_payload.I32(4);
        filter_payload.Guid_(wpe::Guid::Parse(warehouse_id));
        for (int i = 0; i < 12; ++i) filter_payload.Bool(i == 0);
        filter_payload.I32(0); filter_payload.Bool(false); filter_payload.Bool(false);
        filter_payload.I32(1); filter_payload.Bool(false); filter_payload.I32(1);
        filter_payload.Str(Text("")); filter_payload.I32(0);
        filter_payload.Str(Text("")); filter_payload.Str(Text(""));
        filter_payload.Str(Text("0|63")); filter_payload.Str(Text("0|43"));
        wpe::IpcWriter set_filters;
        set_filters.U8(static_cast<std::uint8_t>(wpe::IpcCommand::SetConfig));
        set_filters.U8(static_cast<std::uint8_t>(wpe::ConfigKind::Filters));
        set_filters.Bytes(filter_payload.ToArray());
        shell.CallVoid(set_filters.ToArray());
        ++checks;

        wpe::IpcWriter start_hook;
        start_hook.U8(static_cast<std::uint8_t>(wpe::IpcCommand::StartHook));
        shell.CallVoid(start_hook.ToArray());
        ++checks;
        {
            std::unique_lock lock(event_mutex);
            Check(event_ready.wait_for(lock, 2s, [&] { return ContainsHookState(events, true); }),
                  "production target emitted HookState(true)");
        }
        Check(SetEvent(start_event.value) != FALSE, "target network scenario released");
        Check(WaitForSingleObject(ready_event.value, 3000) == WAIT_OBJECT_0,
              "target completed initial real network round trip");
        {
            std::unique_lock lock(packet_mutex);
            Check(packet_ready.wait_for(lock, 3s, [&] {
                return ContainsFilteredPacket(packets, 1, "cross-process", "Cross-process") &&
                       ContainsPacket(packets, 5, "Cross-process");
            }), "injected DLL applied filter and returned raw/modified frames through pkt pipe");
        }
        {
            const auto wanted = wpe::Guid::Parse(warehouse_id);
            std::unique_lock lock(event_mutex);
            Check(event_ready.wait_for(lock, 3s, [&] {
                return ContainsStoreAdded(events, wanted, "Cross-process");
            }), "production target emitted StoreAdded for the matching warehouse filter");
        }
        Check(store_event_seen.load(), "shell event handler observed StoreAdded");
        std::vector<wpe::shell::Json> warehouse_feeds;
        PumpData(*data_worker, [&] { return store_commit_done.load(); },
                 [&](std::string name, wpe::shell::Json value) {
                     if (name == "feed:replace" && value.value("list", -1) == 11)
                         warehouse_feeds.push_back(std::move(value));
                 });
        {
            std::lock_guard lock(store_commit_mutex);
            Check(store_commit_error.empty() && store_commit_value.value("ok", false) &&
                  store_commit_value.value("stored", false),
                  "StoreAdded event committed by the shell data worker");
        }
        Check(!warehouse_feeds.empty() && warehouse_feeds.back().at("rows").size() == 1 &&
              warehouse_feeds.back().at("rows").front().at("DataCount") == 1,
              "warehouse feed refreshed after target event commit");
        bool rows_ready = false;
        wpe::shell::Json warehouse_rows;
        std::string rows_error;
        data_worker->Submit("getStoreRows", {{"wid", warehouse_id}},
                             [&](wpe::shell::Json value, std::string error) {
                                 warehouse_rows = std::move(value);
                                 rows_error = std::move(error);
                                 rows_ready = true;
                             });
        PumpData(*data_worker, [&] { return rows_ready; });
        Check(rows_error.empty() && warehouse_rows.at("rows").size() == 1 &&
              warehouse_rows.at("rows").front().at("Len") == 13,
              "warehouse row contains the post-filter packet bytes");
        {
            std::unique_lock lock(event_mutex);
            Check(event_ready.wait_for(lock, 3s, [&] {
                return ContainsFilterExecution(events);
            }), "filter execution count returned through Stats");
        }

        wpe::Packet captured;
        {
            std::lock_guard lock(packet_mutex);
            bool found = false;
            for (const auto& frame : packets) {
                const auto candidate = wpe::PacketFrame::Decode(frame);
                if (candidate.packet_type == 1 && candidate.raw &&
                    candidate.raw->size() == std::string_view("cross-process").size() &&
                    std::equal(candidate.raw->begin(), candidate.raw->end(),
                               std::string_view("cross-process").begin())) {
                    captured = candidate;
                    found = true;
                    break;
                }
            }
            Check(found, "captured target socket selected for IPC replay");
        }
        Check(captured.socket > 0 && captured.socket <= (std::numeric_limits<std::int32_t>::max)(),
              "captured socket fits the v4 i32 handle field");

        wpe::IpcWriter socket_info_request;
        socket_info_request.U8(static_cast<std::uint8_t>(wpe::IpcCommand::GetSocketInfo));
        socket_info_request.I32(static_cast<std::int32_t>(captured.socket));
        const auto socket_info_bytes = shell.Call(socket_info_request.ToArray());
        wpe::IpcReader socket_info_response(socket_info_bytes);
        Check(socket_info_response.U8() == static_cast<std::uint8_t>(wpe::IpcStatus::Ok),
              "cross-process GetSocketInfo status");
        const auto live_from = socket_info_response.Str();
        const auto live_to = socket_info_response.Str();
        Check(live_from && live_to && !live_from->empty() && !live_to->empty() &&
              socket_info_response.Remaining() == 0,
              "cross-process GetSocketInfo returns exact live endpoints");

        wpe::IpcWriter replay_request;
        replay_request.U8(static_cast<std::uint8_t>(wpe::IpcCommand::SendPacket));
        replay_request.I32(static_cast<std::int32_t>(captured.socket));
        replay_request.I32(1);
        replay_request.Str(live_from);
        replay_request.Str(live_to);
        replay_request.Bytes(wpe::ByteBuffer{'i', 'p', 'c', '-', 'r', 'e', 'p', 'l', 'a', 'y'});
        const auto replay_bytes = shell.Call(replay_request.ToArray());
        wpe::IpcReader replay_response(replay_bytes);
        Check(replay_response.U8() == static_cast<std::uint8_t>(wpe::IpcStatus::Ok) &&
              replay_response.Bool() && replay_response.Remaining() == 0,
              "cross-process SendPacket returns exact Ok + true response");
        Check(SetEvent(replay_event.value) != FALSE, "target replay verification released");
        Check(WaitForSingleObject(replay_done_event.value, 3000) == WAIT_OBJECT_0,
              "target completed the direct replay before list execution");

        // Exercise the complete configured-send path through the real target:
        // shell config -> target snapshot -> send worker -> production DLL
        // replay -> target socket.  This is deliberately separate from the
        // direct SendPacket command above.
        const auto list_send_id = wpe::Guid::Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        wpe::IpcWriter list_sends;
        list_sends.I32(1); list_sends.Bool(true); list_sends.Guid_(list_send_id);
        list_sends.Str(Text("cross-process-send"));
        list_sends.Bool(false); list_sends.I32(1); list_sends.I32(0); list_sends.Str(Text(""));
        list_sends.I32(1); list_sends.I32(static_cast<std::int32_t>(captured.socket)); list_sends.I32(1);
        list_sends.Str(live_from); list_sends.Str(live_to);
        list_sends.Bytes(wpe::ByteBuffer{'l', 'i', 's', 't', '-', 'r', 'e', 'p', 'l', 'a', 'y'});
        wpe::IpcWriter set_sends;
        set_sends.U8(static_cast<std::uint8_t>(wpe::IpcCommand::SetConfig));
        set_sends.U8(static_cast<std::uint8_t>(wpe::ConfigKind::Sends));
        set_sends.Bytes(list_sends.ToArray());
        shell.CallVoid(set_sends.ToArray());
        ++checks;
        wpe::IpcWriter start_list;
        start_list.U8(static_cast<std::uint8_t>(wpe::IpcCommand::StartSendList));
        shell.CallVoid(start_list.ToArray());
        ++checks;
        Check(SetEvent(send_list_event.value) != FALSE, "target send-list verification released");
        Check(WaitForSingleObject(done_event.value, 3000) == WAIT_OBJECT_0,
              "target received configured send-list bytes through its process-local socket");
        {
            std::unique_lock lock(event_mutex);
            Check(event_ready.wait_for(lock, 3s, [&] {
                return ContainsSendSuccess(events, list_send_id);
            }), "send-list completion and counters returned through Stats");
        }
        Check(WaitForSingleObject(child.ProcessHandle(), 0) == WAIT_TIMEOUT,
              "target confirms replay before entering success hold");
        Throws([&] {
            wpe::shell::ProcessInjector::InjectAndStart(child.Pid(), hook, options, 2s);
        }, "second target worker rejected while the first session is active");

        shell.Detach();
        Check(shell.State() == wpe::IpcLinkState::Disconnected,
              "injected target detached cleanly");
        Check(WaitForSingleObject(child.ProcessHandle(), 0) == WAIT_TIMEOUT,
              "detaching DLL session does not terminate host process");

        // Close the worker after the target is detached, reopen the same
        // SQLite file, and verify that the automatically-ingested row survives
        // a full worker restart rather than only existing in the in-memory
        // feed mirror.
        data_worker.reset();
        auto reopened_worker = std::make_unique<wpe::shell::DataWorker>(warehouse_root / "data.db");
        bool reopened_ready = false;
        wpe::shell::Json reopened_rows;
        std::string reopened_error;
        reopened_worker->Submit("getStoreRows", {{"wid", warehouse_id}},
                                [&](wpe::shell::Json value, std::string error) {
                                    reopened_rows = std::move(value);
                                    reopened_error = std::move(error);
                                    reopened_ready = true;
                                });
        PumpData(*reopened_worker, [&] { return reopened_ready; });
        Check(reopened_error.empty() && reopened_rows.at("rows").size() == 1 &&
              reopened_rows.at("rows").front().at("Len") == 13,
              "automatically-ingested warehouse row persisted across worker restart");

        std::cout << "PASS: " << checks
                  << " injected-session checks; production DLL, StoreAdded auto-ingestion, "
                     "real capture, target socket info/replay and detach\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
