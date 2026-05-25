#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <tlhelp32.h>
#include <iostream>
#include <thread>

#include "utils.h"

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

/* reset attack tracking variables (with a delay) */
void reset_attack_tracking_threaded() {
    // private helper function to be threaded
    auto reset = []() {
        std::this_thread::sleep_for(std::chrono::seconds(tracking_shutdown_delay));
        g_attack_pid = 0;
        g_attack_main_tid = 0;
        if (g_debug) {
            std::wcout << L"[+] Reset attack tracking variables after attack termination\n";
        }
	};
	std::thread(reset).detach();
}

/* TODO get relevant events from defender event log */
std::wstring get_mde_eventlog() {
    // return lines as eventid:message:description
	std::wstring log = MDE_log + L" events:\n";
    bool found_events = false;
	// std::vector<std::wstring> events = get_mde_events_after(g_last_attack_start);
	// for (const auto& e : events) {
    // if (e.id >= 1000 && e.id < 2000) {
	// log += std::to_wstring(e.id) + L":" + e.message + L":" + e.description + L"\n";
    // found_events = true;
    // }
    if (!found_events && g_debug) {
        log = L"[-] No relevant events found in " + MDE_log;
    }
    return log;
}