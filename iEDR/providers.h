#pragma once

#include <map>
#include <string>
#include <vector>

#include "utils.h"


const std::wstring kernel_process_provider_name = L"Microsoft-Windows-Kernel-Process";
const std::wstring kernel_file_provider_name = L"Microsoft-Windows-Kernel-File";
const std::wstring kernel_network_provider_name = L"Microsoft-Windows-Kernel-Network";
const std::wstring kernel_api_audit_provider_name = L"Microsoft-Windows-Kernel-Audit-API-Calls";
const std::wstring antimalware_provider_name = L"Microsoft-Antimalware-Engine";

struct FilterValue {
    enum Type { INT_FILTER, INT_PTR_FILTER, WSTR_PTR_FILTER } type;

    union {
        int i_val;
        const int* i_ptr;
        const std::wstring* s_ptr;
    };

    // Constructors for automatic type detection
    FilterValue(int v) : type(INT_FILTER), i_val(v) {}
    FilterValue(const int* v) : type(INT_PTR_FILTER), i_ptr(v) {}
    FilterValue(const std::wstring* v) : type(WSTR_PTR_FILTER), s_ptr(v) {}

    int get_int() const {
        return (type == INT_PTR_FILTER) ? *i_ptr : i_val;
    }

    std::wstring get_str() const {
        return (type == WSTR_PTR_FILTER && s_ptr) ? *s_ptr : L"";
    }
};

struct operation {
    enum class Type { EQUALS, PATH_EQUALS, CONTAINS_STR, CONTAINS_FLAG };
    const Type type;
};


struct filter {
    const std::wstring field_name;
    const uint16_t tdh_field_type;
    const operation op;
    const FilterValue expected;
};

struct event {
    const int id;
    const std::vector<filter> filters;
    const std::wstring output;
};

struct events {
    const std::vector<event> minimal_ids;
    const std::vector<event> relevant_ids;
    const std::vector<event> all_ids;

    const std::vector<event>& get(verbosity_level lvl) const {
        switch (lvl) {
        case MINIMAL: return minimal_ids;
        case VERBOSE: return all_ids;
        case DEFAULT:
        default:      return relevant_ids;
        }
    }
};

struct provider {
    const std::wstring provider_name;
    const events events_to_track;
};

extern std::map<std::wstring, provider> providers_to_track;

extern std::map<std::wstring, std::vector<int>> providers_event_ids_no_debug_output; // to verbose