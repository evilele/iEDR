#pragma once

#include <string>

const std::wstring MDE_log = L"Microsoft-Windows-Windows Defender/Operational";
const std::wstring MsMpEng = L"MsMpEng.exe";
const int tracking_shutdown_delay = 3; // seconds to keep tracking after attack end to catch any remaining events

enum verbosity_level {
    MINIMAL = 0,
    DEFAULT = 1,
    VERBOSE = 2
};

extern bool g_debug;
extern bool g_dev_debug;
extern verbosity_level g_level;

extern std::wstring g_attack_path;
extern int g_attack_pid;
extern int g_edr_pid;
extern int g_attack_main_tid;
extern SYSTEMTIME g_last_attack_start;

bool filepath_match(std::wstring, std::wstring);
std::string wchar_to_string(const wchar_t*);
std::wstring string_to_wstring(const std::string&);
std::string wstring_to_string(const std::wstring&);
std::wstring timestamp_to_wstring(LARGE_INTEGER);
int get_process_id_by_name(const std::wstring&);
void reset_attack_tracking_and_print_evtl_threaded();