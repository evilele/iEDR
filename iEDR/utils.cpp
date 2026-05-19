#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include "utils.h"
#include <algorithm>

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