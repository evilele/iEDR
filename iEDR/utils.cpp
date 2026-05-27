#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winevt.h>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <tlhelp32.h>
#include <iostream>
#include <thread>
#include <vector>

#include "utils.h"

#pragma comment(lib, "wevtapi.lib")

/* checks if the path after C:\ D:\ \\Device\HarddiskVolumeX is the same, not including the drive and trailing \ */
bool filepath_match(std::wstring path1, std::wstring path2) {
    auto normalize = [](const std::wstring& path) -> std::wstring {
        std::wstring p = path;

        const std::wstring device_prefix = L"\\Device\\HarddiskVolume";
        if (_wcsnicmp(p.c_str(), device_prefix.c_str(), device_prefix.size()) == 0) {
            size_t pos = p.find(L'\\', device_prefix.size());
            if (pos != std::wstring::npos) {
                p = p.substr(pos);
            }
            else {
                p.clear();
            }
        }
        else if (p.size() >= 3 && ::iswalpha(p[0]) && p[1] == ':' && p[2] == '\\') {
            p = p.substr(2);
        }

        std::transform(p.begin(), p.end(), p.begin(), [](wchar_t c) {
            return static_cast<wchar_t>(::towlower(c));
            });

        if (p.size() > 1 && p.back() == L'\\') { // \test\ and \test should match
            p.pop_back();
        }

        return p;
        };

    return normalize(path1) == normalize(path2);
}

// all stolen from https://github.com/dobin/RedEdr
/* wchar to string */
std::string wchar_to_string(const wchar_t* wideString) {
    if (!wideString) {
        return "";
    }
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wideString, -1, nullptr, 0, nullptr, nullptr);
    if (sizeNeeded <= 0) {
        return "";
    }
    std::string ret(sizeNeeded - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wideString, -1, &ret[0], sizeNeeded, nullptr, nullptr);
    return ret;
}

/* string to wstring */
std::wstring string_to_wstring(const std::string& str) {
    return std::wstring(str.begin(), str.end());
}

/* wstring to string */
std::string wstring_to_string(std::wstring& wide_string) {
    if (wide_string.empty()) {
        return "";
    }

    // Determine the size needed for the UTF-8 buffer
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wide_string.c_str(), -1, nullptr, 0, nullptr, nullptr);

    // Allocate the buffer and perform the conversion
    std::string utf8_string(size_needed - 1, '\0'); // Exclude the null terminator
    WideCharToMultiByte(CP_UTF8, 0, wide_string.c_str(), -1, &utf8_string[0], size_needed, nullptr, nullptr);

    return utf8_string;
}

/* ETW timestamp to wstr */
std::wstring timestamp_to_wstring(LARGE_INTEGER timestamp) {
	// keep precision of 100ns, but convert to human readable format

    FILETIME ft;
    ft.dwLowDateTime = timestamp.LowPart;
    ft.dwHighDateTime = timestamp.HighPart;
    SYSTEMTIME st; 
    if (!FileTimeToSystemTime(&ft, &st)) {
        return L"0000-00-00 00:00:00.0000000";
    }

    // calculate the remaining fractions of the 100ns intervals, 1 millisecond = 10,000 intervals of 100ns
    uint64_t total_100ns = (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    uint32_t fractions_100ns = static_cast<uint32_t>(total_100ns % 10000);

    std::wstringstream wss;
    wss << std::setfill(L'0')
        << std::setw(2) << st.wHour << L":"
        << std::setw(2) << st.wMinute << L":"
        << std::setw(2) << st.wSecond << L"."
        << std::setw(3) << st.wMilliseconds
        << std::setw(4) << fractions_100ns;
	return wss.str();
}

/* get process id by proc name */
int get_process_id_by_name(const std::wstring& proc) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    int pid = 0;

    if (Process32First(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, proc.c_str()) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
}

/* ticks to iso timestamp YYYY-MM-DDTHH:MM:SS.MMMZ */
std::wstring system_time_to_iso(const SYSTEMTIME& st) {
    std::wstringstream wss;
    wss << std::setfill(L'0')
        << std::setw(4) << st.wYear << L"-"
        << std::setw(2) << st.wMonth << L"-"
        << std::setw(2) << st.wDay << L"T"
        << std::setw(2) << st.wHour << L":"
        << std::setw(2) << st.wMinute << L":"
        << std::setw(2) << st.wSecond << L"Z";
    return wss.str();
}

/* parse defender event type */
std::wstring get_defender_events(int event_id, std::vector<std::wstring> to_extract, std::wstring event_type_desc) {
	std::wstring id = std::to_wstring(event_id);
    std::wstring after_time = system_time_to_iso(g_last_attack_start);

    // filter ID 1116 and System Time > g_last_attack_start
    std::wstring query = L"*[System[(EventID = " + id + L") and TimeCreated[@SystemTime >= '" + after_time + L"']]]";
    EVT_HANDLE hResults = EvtQuery(NULL, MDE_log.c_str(), query.c_str(), EvtQueryChannelPath | EvtQueryReverseDirection);
    if (!hResults) {
        if (g_dev_debug) {
            std::wcerr << L"[!] Failed to query events for " << id << L" in " << MDE_log << L": " << GetLastError() << L"\n";
		}
    }

    std::wstring log = L"";
    EVT_HANDLE hEvents[10];
    DWORD returned = 0;

    while (EvtNext(hResults, 10, hEvents, 1000, 0, &returned)) {
        for (DWORD i = 0; i < returned; EvtClose(hEvents[i++])) {
            DWORD used = 0, count = 0;
            EvtRender(NULL, hEvents[i], EvtRenderEventXml, 0, NULL, &used, &count);
            std::vector<wchar_t> buf(used / sizeof(wchar_t));
            if (!EvtRender(NULL, hEvents[i], EvtRenderEventXml, used, &buf[0], &used, &count)) {
                if (g_dev_debug) {
                    std::wcerr << L"[!] Failed to render event XML for " << id << ": " << GetLastError() << L"\n";
                }
            }

			std::wstring xml(&buf[0]);

            // extract <TimeCreated SystemTime='2026-05-26T19:11:41.2621732Z'/>
			std::wstring timestamp = L"0000-00-00T00:00:00.000Z";

			size_t time_pos = xml.find(L"<TimeCreated SystemTime='");
            if (time_pos != std::wstring::npos) {
                time_pos += 25; // length of <TimeCreated SystemTime='
                size_t end_time_pos = xml.find(L"'/>", time_pos);
                if (end_time_pos != std::wstring::npos) {
                    timestamp = xml.substr(time_pos, end_time_pos - time_pos);
                }
			} else {
                if (g_dev_debug) {
                    std::wcerr << L"[!] Failed to find TimeCreated in event XML for " << id << L"\n";
                }
			}

			// extract relevant fields
			std::wstring message = L"";

            for (const auto& name : to_extract) {
                size_t pos = xml.find(L"<Data Name='" + name + L"'>");
                if (pos != std::wstring::npos) {
                    pos += 14 + name.size(); // length of <Data Name=''>
                    size_t end_pos = xml.find(L"</Data>", pos);
                    if (end_pos != std::wstring::npos) {
                        if (!message.empty()) {
                            message += L", ";
						}
                        message += name + L": " + xml.substr(pos, end_pos - pos);
                    }
                }
                else {
                    if (g_dev_debug) {
                        std::wcerr << L"[!] Failed to find " << name << L" in event XML for " << id << L"\n";
					}
                }
            }

			log += timestamp + L" - " + id + L" - " + event_type_desc + L" : " + message + L"\n";
        }
    }

    EvtClose(hResults);

    if (log.empty()) {
        log = L"[-] No relevant events found in " + MDE_log + L" (" + id + L") " + event_type_desc + L"\n";
	}
    return log;
}

/* get relevant events from MDE log after last attack start */
std::wstring get_mde_eventlog() {
	std::wstring detections = L"[+] Events from " + MDE_log + L":\n";

    // https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus#event-id-1116
	detections += get_defender_events(1116, { L"Source Name", L"Threat Name", L"Severity Name", L"Path" }, L"MALWAREPROTECTION_STATE_MALWARE_DETECTED");

    // https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus#event-id-1117
    detections += get_defender_events(1117, { L"Source Name", L"Threat Name", L"Severity Name", L"Action Name", L"Path" }, L"MALWAREPROTECTION_STATE_MALWARE_ACTION_TAKEN");

	return detections;
}

/* reset attack tracking variables (with a delay) */
void reset_attack_tracking_and_print_evtl_threaded() {
    // private helper function to be threaded
    auto reset = []() {
        std::this_thread::sleep_for(std::chrono::seconds(tracking_shutdown_delay));
        g_attack_pid = 0;
        g_attack_main_tid = 0;
        if (g_debug) {
            std::wcout << L"[+] Reset attack tracking variables after attack termination\n";
        }
        // wait again for mde event log
        std::this_thread::sleep_for(std::chrono::seconds(tracking_shutdown_delay));
        std::wcout << get_mde_eventlog();
        };
    std::thread(reset).detach();
}