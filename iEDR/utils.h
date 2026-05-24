#pragma once

#include <string>

enum verbosity_level {
    MINIMAL = 0,
    DEFAULT = 1,
    VERBOSE = 2
};

extern bool g_debug;
extern bool g_dev_debug;
extern verbosity_level g_level;

extern std::wstring g_attack_path;
extern bool g_autodetect_attack_path;
extern int g_attack_pid;
extern int g_edr_pid;
extern std::wstring g_attack_pid_str;
extern int g_attack_main_tid;

bool filepath_match(std::wstring, std::wstring);
std::string wchar_to_string(const wchar_t*);
std::wstring string_to_wstring(const std::string&);
std::string wstring_to_string(const std::wstring&);
std::wstring timestamp_to_wstring(LARGE_INTEGER);