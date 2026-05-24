#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <algorithm>
#include <sstream>
#include <iomanip>

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