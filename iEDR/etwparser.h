#pragma once

#include <krabs.hpp>

#include "utils.h"

extern bool g_trace_started;

// properties from the actual events --> values cannot be changed!
static const std::string PPID = "ppid";
static const std::string TARGET_PID = "targetpid";
static const std::string TARGET_TID = "targettid";
static const std::string ORIGINATING_PID = "pid"; // antimalware-traces + kernel-network-traces
static const std::string FILEPATH = "filepath";
static const std::string MESSAGE = "message";
static const std::string SIGSEQ = "sigseq";
static const std::string SIGSHA = "sigsha";
static const std::string NAME = "name";
static const std::string FIRST_PARAM = "firstparam";
static const std::string SECOND_PARAM = "secondparam";
static const std::string CLASSIFICATION = "classification";
static const std::string DETERMINATION = "determination";
static const std::string RESOURCESCHEMA = "resourceschema";
static const std::string REALPATH = "realpath";
static const std::string THREATNAME = "threatname";
static const std::string DATA = "data";
static const std::string SOURCE = "source";

enum class ValueType { INT_LITERAL, STR_LITERAL, INT_PTR, STR_PTR };
struct FilterValue {
    ValueType type;
    int int_val;
    std::string str_val;
    const int* int_ptr;
    const std::string* str_ptr;

    FilterValue(int v) : type(ValueType::INT_LITERAL), int_val(v) {}
    FilterValue(const std::string& v) : type(ValueType::STR_LITERAL), str_val(v) {}
    FilterValue(const char* v) : type(ValueType::STR_LITERAL), str_val(v) {}
    FilterValue(const int* v) : type(ValueType::INT_PTR), int_ptr(v) {}
    FilterValue(const std::string* v) : type(ValueType::STR_PTR), str_ptr(v) {}
};

struct filter {
    std::string field_name;
    FilterValue expected;
};

struct event {
    unsigned short id;
    std::vector<filter> filters;
};

struct events {
    std::vector<event> minimal_ids;
    std::vector<event> default_ids;
    std::vector<event> verbose_ids;

    const std::vector<event>& get(verbosity_level lvl) const {
        switch (lvl) {
        case MINIMAL: return minimal_ids;
        case VERBOSE: return verbose_ids;
        case DEFAULT:
        default:      return default_ids;
        }
    }
};

struct provider {
    std::string provider_name;
    events events_to_track; 
};

struct merge_field {
    std::string field_name;
	std::vector<std::string> for_providers; // if empty, merge for all providers
};

struct merge_category {
    std::string final_name;
    std::vector<merge_field> fields_to_merge;
};
extern merge_category ppid_keys, tpid_keys, ttid_keys, filepath_keys;

void event_callback(const EVENT_RECORD&, const krabs::trace_context&);