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

// Microsoft-Windows-Kernel-Process
// {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
static const GUID KERNEL_PROCESS_PROVIDER =
{
    0x22fb2cd6, 0x0e7b, 0x422b,
    {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}
};

// Microsoft-Windows-Kernel-File
// {EDD08927-9CC4-4E65-B970-C2560FB5C289}
static const GUID KERNEL_FILE_PROVIDER =
{
    0xedd08927, 0x9cc4, 0x4e65,
    {0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x89}
};

// Microsoft-Windows-Kernel-Network
// {7DD42A49-5329-4832-8DFD-43D979153A88}
static const GUID KERNEL_NETWORK_PROVIDER =
{
    0x7dd42a49, 0x5329, 0x4832,
    {0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88}
};

// Microsoft-Windows-Kernel-Audit-API-Calls
// {E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23}
static const GUID KERNEL_AUDIT_API_PROVIDER =
{
    0xe02a841c, 0x75a3, 0x4fa7,
    {0xaf, 0xc8, 0xae, 0x09, 0xcf, 0x9b, 0x7f, 0x23}
};

// Microsoft-Antimalware-Engine
// {0A002690-3839-4E3A-B3B6-96D8DF868D99}
static const GUID ANTIMALWARE_ENGINE_PROVIDER =
{
    0x0a002690, 0x3839, 0x4e3a,
    {0xb3, 0xb6, 0x96, 0xd8, 0xdf, 0x86, 0x8d, 0x99}
};


struct operation {
    enum class Type { EQUALS, PATH_EQUALS, PID_STR_EQUALS, CONTAINS_STR, CONTAINS_FLAG, IN_LIST, FIRST_IN_LIST, NFIRST_IN_LIST, ANY };
    const Type type;
};

struct FilterValue {
    enum FilterType { CONST_FILTER, INT_VECTOR_FILTER, WSTR_FILTER } filter_type;

    union {
        int i_val;
        const std::vector<int>* v_ptr;
        const std::wstring* s_ptr;
    };

    FilterValue(int v) : filter_type(CONST_FILTER), i_val(v) {}
    FilterValue(const std::vector<int>* v) : filter_type(INT_VECTOR_FILTER), v_ptr(v) {}
    FilterValue(const std::wstring* v) : filter_type(WSTR_FILTER), s_ptr(v) {}

    // Checks if an integer matches based on a specific operation type
    bool match_int(int actual_int, operation::Type op_type) const {
        if (filter_type == CONST_FILTER) {
            if (i_val == 0) return true; // Bypass

            switch (op_type) {
            case operation::Type::EQUALS:
                return actual_int == i_val;
            case operation::Type::CONTAINS_FLAG:
                return (actual_int & i_val) != 0;
            case operation::Type::PID_STR_EQUALS: {
                std::wstring expected_str = L"pid:" + std::to_wstring(i_val);
                return std::to_wstring(actual_int) == expected_str;
            }
            case operation::Type::ANY:
                return true;
            default:
                return false;
            }
        }

        if (filter_type == INT_VECTOR_FILTER && v_ptr) {
            switch (op_type) {
                case operation::Type::ANY:
                    return true;
                case operation::Type::IN_LIST: 
                {
                    if (v_ptr->empty()) return false; // operation defined but no list to compare against -> always false
                    return std::find(v_ptr->begin(), v_ptr->end(), actual_int) != v_ptr->end();
                }
                case operation::Type::FIRST_IN_LIST: 
                {
                    if (v_ptr->empty()) return false;
                    return actual_int == v_ptr->at(0);
                }
                case operation::Type::NFIRST_IN_LIST:
                {
                    if (v_ptr->empty()) return false;
                    return std::find(v_ptr->begin() + 1, v_ptr->end(), actual_int) != v_ptr->end();
                }
                                                   
            }
        }

        return false;
    }

    // Checks if a string matches based on a specific operation type
    bool match_str(const std::wstring& actual_str, operation::Type op_type) const {
        if (filter_type == WSTR_FILTER && s_ptr) {
            switch (op_type) {
            case operation::Type::EQUALS:
                return actual_str == *s_ptr;
            case operation::Type::PATH_EQUALS:
                return filepath_match(actual_str, *s_ptr);
            case operation::Type::CONTAINS_STR:
                return actual_str.find(*s_ptr) != std::wstring::npos;
            case operation::Type::ANY:
                return true;
            default:
                return false;
            }
        }
        return false;
    }
};

struct filter {
    const std::wstring field_name;
    const operation op;
    const FilterValue expected;

    bool matches(int actual_int) const {
        return expected.match_int(actual_int, op.type);
    }

    bool matches(const std::wstring& actual_str) const {
        return expected.match_str(actual_str, op.type);
    }
};

enum AddOutputFormat {
    DEC,
    HEX,
    STR
};

// refactor (problem): 1 output maps to n filters, 1..n filters may contain interesting information to print (add_output)
// --> add_output should be a list containing {field, format, add_text} and output += add_output_1, ..., add_output_n
// also maybe translate pid in output to exe_name?
struct event {
    const int id;
    const int* originating_pid; // optional originating PID filter // TODO this is only used for ka5, relevant? refactor?
    const std::vector<filter> filters; // field filters// TODO refactor so that fields must not be in <>filters?
    const std::wstring output;
	const std::wstring add_output_field; // optional output from field value, field must also be in filters but can also be ANY (not filtered) // TODO above
    const AddOutputFormat add_output_format;
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
	const GUID guid;
	const std::wstring provider_name;
    const events events_to_track;
};

extern std::vector<provider> providers_to_track;