#pragma once

#include <string>

enum verbosity_level {
    MINIMAL = 0,
    DEFAULT = 1,
    VERBOSE = 2
};

extern bool g_debug;
extern verbosity_level g_level;
extern std::string g_attack_path;
extern int g_attack_pid;

std::string wchar_to_string(const wchar_t* wstr);
std::wstring string_to_wstring(const std::string& str);
std::string wstring_to_string(const std::wstring& wstr);