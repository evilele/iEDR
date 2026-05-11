#include <iostream>

#include "etwparser.h"
#include "utils.h"

bool with_stack_trace = false;

// keys that get merged together 
// TODO check all merges
merge_category ppid_keys = {
    PPID,
    {
		{ "parentpid" }, { } // for all providers, this is the parent pid
    }
};
merge_category tpid_keys = { // all refer to yet another pid (event has an emitter (process_id), original proc (pid), and the target proc (tpid))
    TARGET_PID,
    {
        { "processid", { "Microsoft-Windows-Kernel-Process" } }, // in kernel traces, this is the target pid, in antimalware traces, this is the originating pid (but only event 95 has this)
        { "tpid", { "Microsoft-Windows-Kernel-Process" } }, // only in kernel traces, and also means target pid
        { "targetprocessid", { "Microsoft-Windows-Kernel-Process" } }, // only in kernel traces, and also means target pid
		{ "frozenprocessid", { "Microsoft-Windows-Kernel-Process" } } // only in kernel traces, and also means target pid}
    }
};
merge_category ttid_keys = { // both refer to yet another pid (event has an emitter (process_id), original proc (pid), and the target proc (tpid))
    TARGET_TID,
    { 
        { "targetthreadid", { "Microsoft-Windows-Kernel-Process" } }, // only in kernel traces, and also means target tid (also with a t, this is a typo)
		{ "ttid", { "Microsoft-Windows-Kernel-Process" d} }, // only in kernel traces, and also means target tid}
    }
};
merge_category filepath_keys = {
    "filepath",
    { 
        { "basepath", { "Microsoft-Windows-Kernel-File" } }, // in kernel traces, this is the filepath, in antimalware traces, this is the "first resource path"
        { "filename", { "Microsoft-Windows-Kernel-Process", "Microsoft-Windows-Kernel-File" } }, // in kernel-process traces, this is the image name, in kernel-file traces, this is the filepath
        { "imagename", { "Microsoft-Windows-Kernel-Process" } }, // in kernel traces, this is the image name, in antimalware traces, this is the "first resource path"
        { "path", { "Microsoft-Windows-Kernel-Process" } }, // in kernel traces, this is the image path, in antimalware traces, this is the "first resource path"
		{ "reasonimagepath", { "Microsoft-Windows-Kernel-Process" } } // only in kernel traces, and also means filepath
    }
};
std::vector<merge_category> key_categories_to_merge = { ppid_keys, tpid_keys, ttid_keys, filepath_keys };

// the providers to track
/*
    1 ProcessStart
    2 ProcessStop
    3 ThreadStart
    4 ThreadStop
    5 ImageLoad
    6 ImageUnload
    11 ProcessFreeze
*/
event kp1 = { 1,  { {"FileName", g_attack_path} } };
event kp2 = { 2,  { {"FileName", g_attack_path} } };
event kp3 = { 3,  { {"FileName", g_attack_path} } };
event kp4 = { 4,  { {"FileName", g_attack_path} } };
event kp5 = { 5,  { {"FileName", g_attack_path} } };
event kp6 = { 6,  { {"FileName", g_attack_path} } };
event kp11 = { 11, { {"ProcessID", &g_attack_pid} } };
provider kernel_process_provider = {
    "Microsoft-Windows-Kernel-Process",
    {
        { kp1 },
        { kp1, kp2, kp3, kp4, kp5, kp6, kp11 },
        { kp1, kp2, kp3, kp4, kp5, kp6, kp11 }
    }
};

/*
    10 NameCreate
    17 SetInformation
    19 Rename
    22 QueryInformation
    23 FSCTL
    25 DirNotify
    26 DeletePath
    27 RenamePath
    28 SetLinkPath
    29 Rename
    30 CreateNewFile
    31 SetSecurity
    32 QuerySecurity
    33 SetEA
    34 QueryEA
*/
event kf10 = { 10, { {"FileName", g_attack_path} } };
event kf30 = { 30, { {"FileName", g_attack_path} } };
provider kernel_file_provider = {
    "Microsoft-Windows-Kernel-File",
    {
        { kf30 },
        { kf10, kf30 },
        { kf10, kf30 }
    }
};

/*
    12 TCPIPConnectionattempted
    15 TCPIPConnectionaccepted
    28 TCPIPConnectionattempted
    31 TCPIPConnectionaccepted
    42 UDPIPDatasentoverUDPprotocol
    43 UDPIPDatareceivedoverUDPprotocol
    58 UDPIPDatasentoverUDPprotocol
    59 UDPIPDatareceivedoverUDPprotocol
*/
event kn12 = { 12, {  { } } };
event kn15 = { 15, {  { } } };
event kn28 = { 28, {  { } } };
event kn31 = { 31, {  { } } };
event kn42 = { 42, {  { } } };
event kn43 = { 43, {  { } } };
event kn58 = { 58, {  { } } };
event kn59 = { 59, {  { } } };
provider kernel_network_provider = {
    "Microsoft-Windows-Kernel-Network",
    {
        { },
        { },
        { kn12, kn15, kn28, kn31, kn42, kn43, kn58, kn59 }
    }
};

/*
    1: PspLogAuditSetLoadImageNotifyRoutineEvent(kernel)
    2: PspLogAuditTerminateRemoteProcessEvent
    3: NtCreateSymbolicLink
    4: PspSetContextThreadInternal
    5: PspLogAuditOpenProcessEvent
    6: PspLogAuditOpenThreadEvent
    7: IoRegisterLastChanceShutdownNotification(kernel)
    8: IoRegisterShutdownNotification(kernel)
*/
event ka3 = { 3, { {"SymbolicLinkName", g_attack_path} } };
event ka4 = { 4, { {"ThreadId", 0} } };
event ka5 = { 5, { {"ProcessID", &g_attack_pid} } };
event ka6 = { 6, { {"ThreadId", 0} } };
provider kernel_api_provider = {
    "Microsoft-Windows-Kernel-Audit-API-Calls",
    {
        { ka5 },
        { ka5 },
        { ka3, ka4, ka5, ka6 }
    }
};

/* ?? */
/*
// -------------------- FILTERING LISTS -------------------- //
// Antimalware Trace
static const std::vector<int> am_event_ids_to_remove = { };
// TODO filter event 1 on "first resource path" == C:\Users\Public\Downloads\attack.exe, and merge "first resource path" into filepath, when "first resource type" == "file"
// TODO event 1 can also be "first resource type" == "process", then merge into target_pid
static const std::vector<int> am_event_ids_with_opid = { 5, 6, 11, 15, 16, 26, 29, 104, 105, 109, 110, 111, 112, 60, 70, 71, 72, 73 };
// TODO filter 5,6 (stream scan request start, stop) based on filepath == C:\Users\Public\Downloads\attack.exe
static const std::vector<int> am_event_ids_with_pid_but_noisy = { 11, 111, 112 };
static const std::vector<int> am_event_ids_with_opid_and_tpid = { 53 };
static const std::vector<int> am_event_ids_with_pid_in_data = { 43, 67 }; // TODO name == C:\Users\Public\Downloads\attack.exe, also name merge into -> filepath
static const std::vector<int> am_event_ids_with_message = { 3 };
static const std::vector<int> am_event_ids_with_filepath = { 7, 30, 31, 35, 36, 37, 38 };
static const std::vector<int> am_event_ids_with_pipe = { 32, 33 };
static const std::vector<int> am_event_ids_relevant = { 44, 59 };
// event 44 is a MetaStoreTask MetaStoreAction but it has no reversible identifiers
// event 59 just logs all Behaviour tracking tasks, but has no identifier tied to actual files / events / procs, etc. -> sigseq and sigsha only identify the tracking task, NOT the file / event / proc
// am_events_ids_relevant are automatically classified as Relevant (until the default classification changes)
*/
// minimal
event am1 = { 1, { {"filepath", g_attack_path} } };
event am5 = { 5, { {"opid", &g_attack_pid} } };
event am30 = { 6, { {"filepath", g_attack_path} } };
event am32 = { 32, { {"filepath", g_attack_path} } };
event am43 = { 43, { {"filepath", g_attack_path}, { "data", &g_attack_pid } } };

// default
event am36 = { 36, { {"filepath", g_attack_path} } };
event am44 = { 44, {  } };
event am46 = { 46, {  } };

// all
event am2 = { 2, {  } };
event am3 = { 3, {  } };
event am4 = { 4, {  } };
event am6 = { 6, {  } };
event am7 = { 7, {  } };
event am11 = { 11, {  } };
event am15 = { 15, {  } };
event am16 = { 16, {  } };
event am26 = { 26, {  } };
event am31 = { 31, {  } };
event am33 = { 33, {  } };
event am38 = { 38, {  } };
event am53 = { 53, {  } };
event am59 = { 59, {  } };
event am60 = { 60, {  } };
event am62 = { 62, {  } };
event am67 = { 67, {  } };
event am70 = { 70, {  } };
event am71 = { 71, {  } };
event am72 = { 72, {  } };
event am73 = { 73, {  } };
event am74 = { 74, {  } };
event am95 = { 95, {  } };
event am103 = { 103, {  } };
event am104 = { 104, {  } };
event am105 = { 105, {  } };
event am109 = { 109, {  } };
event am110 = { 110, {  } };
event am111 = { 111, {  } };
event am112 = { 112, {  } };

provider antimalware_provider = {
    "Microsoft-Antimalware-Engine",
    {
        { am1, am5, am30, am32, am43 },
        { am1, am5, am30, am32, am36, am43, am44, am46 },
        { am1, am2, am3, am4, am5, am6, am7, am11, am15, am16, am26, am30, am31, am32, am33, am36, am38, am43, am44, am53, am59, am60, am62, am67, am70, am71, am72, am73, am74, am95, am103, am104, am105, am109, am110, am111, am112 }
    }
};

void parse_etw_event(const EVENT_RECORD& record, const krabs::schema& schema) {
    // TODO implement parsing of events based on the schema and the properties defined in the event structs
    // for example, if the event has a property "filepath", extract it and check if it matches g_attack_path, etc.
    // also implement merging of properties based on the key_categories_to_merge vector

    try {
        std::string provider_name = wchar_to_string(schema.provider_name());
		std::wstring task_name = schema.task_name();
		unsigned short event_id = schema.event_id();
        if (g_debug) {
            std::cout << "[+] ETW Event: " << provider_name << " - " << event_id << "\n";
        }
        krabs::parser parser(schema);
        // parse all properties defined in the schema
        for (const auto& property : parser.properties()) {
            std::string last_key;
            std::string original_key = "";
            int last_type;

            try {
                // get property name and type
                const std::wstring& property_name = property.name();
                const auto property_type = property.type();

                // create key and convert it to lowercase
                std::string key = wstring_to_string((std::wstring&)property_name);
                std::transform(key.begin(), key.end(), key.begin(),
                    [](unsigned char c) { return std::tolower(c); });

                // for tracking potential overwrites & error messages
                std::string overwritten_value = "";
                last_key = key;
                last_type = property_type;

                // check if it's a merged key --> write value to merged_key
                for (const auto& cat : key_categories_to_merge) {
                    for (const auto& field : cat.fields_to_merge) {
						// check if this field should be merged for this provider (if for_providers is empty, merge for all providers, otherwise only merge if provider_name is in the list)
                        if (!field.for_providers.empty() && std::find(field.for_providers.begin(), field.for_providers.end(), provider_name) == field.for_providers.end()) {
                            continue; // no providers or not matching providers -> skip this field for this provider
                        }
                        if (field.field_name == key) {
                            original_key = key;
                            key = cat.final_name;
                            break; // stop checking other fields in this category
                        }
					}
                }
                if (j.contains(key)) {
                    overwritten_value = get_val(j, key);
                }

                switch (property_type) {

                case TDH_INTYPE_UNICODESTRING:
                {
                    std::wstringstream wss;
                    wss << parser.parse<std::wstring>(property_name);
                    std::string s = wstring_to_string((std::wstring&)wss.str());
                    j[key] = s;
                    break;
                }

                case TDH_INTYPE_ANSISTRING:
                    j[key] = parser.parse<std::string>(property_name);
                    break;
                case TDH_INTYPE_INT8:
                    j[key] = (int32_t)parser.parse<CHAR>(property_name);
                    break;
                case TDH_INTYPE_UINT8:
                    j[key] = (uint32_t)parser.parse<UCHAR>(property_name);
                    break;
                case TDH_INTYPE_INT16:
                    j[key] = (int32_t)parser.parse<SHORT>(property_name);
                    break;
                case TDH_INTYPE_UINT16:
                    j[key] = (int32_t)parser.parse<USHORT>(property_name);
                    break;
                case TDH_INTYPE_INT32:
                    j[key] = (int32_t)parser.parse<int32_t>(property_name);
                    break;
                case TDH_INTYPE_UINT32:
                    j[key] = (uint32_t)parser.parse<uint32_t>(property_name);
                    break;
                case TDH_INTYPE_INT64:
                    j[key] = (int64_t)parser.parse<int64_t>(property_name);
                    break;
                case TDH_INTYPE_UINT64:
                    j[key] = (uint64_t)parser.parse<uint64_t>(property_name);
                    break;
                case TDH_INTYPE_BOOLEAN:
                {
                    try {
                        j[key] = (bool)parser.parse<bool>(property_name);
                    }
                    catch (...) {
                        // fallback: dump raw bytes
                        auto bin = parser.parse<krabs::binary>(property_name);
                        const auto& bytes = bin.bytes();
                        std::ostringstream oss;
                        oss << "0x" << std::hex << std::setfill('0');
                        for (auto b : bytes)
                            oss << std::setw(2) << static_cast<int>(b);
                        j[key] = oss.str();
                    }
                    break;
                }
                case TDH_INTYPE_POINTER:
                    j[key] = (uint64_t)parser.parse<PVOID>(property_name);
                    break;

                case TDH_INTYPE_BINARY:
                {
                    try {
                        auto bin = parser.parse<krabs::binary>(property_name);
                        const auto& bytes = bin.bytes();
                        const auto size = bytes.size();
                        const auto data = bytes.empty() ? nullptr : bytes.data();

                        if (size == 4 && data) {
                            char ipStr[INET_ADDRSTRLEN] = { 0 };
                            if (inet_ntop(AF_INET, data, ipStr, sizeof(ipStr)))
                                j[key] = std::string(ipStr);
                            else
                                j[key] = "<inet_ntop_AF_INET_failed>";
                        }
                        else if (size == 16 && data) {
                            // detect IPv4-mapped IPv6 ::ffff:a.b.c.d (first 10 bytes 0, then 0xff,0xff)
                            bool ipv4_mapped = (std::equal(bytes.begin(), bytes.begin() + 10, std::vector<BYTE>(10, 0).begin())
                                && bytes[10] == 0xff && bytes[11] == 0xff);
                            if (ipv4_mapped) {
                                // convert last 4 bytes as IPv4
                                char ipStr[INET_ADDRSTRLEN] = { 0 };
                                if (inet_ntop(AF_INET, data + 12, ipStr, sizeof(ipStr)))
                                    j[key] = std::string("::ffff:") + std::string(ipStr); // or ipStr alone if you prefer
                                else
                                    j[key] = "<inet_ntop_mapped_failed>";
                            }
                            else {
                                char ipStr[INET6_ADDRSTRLEN] = { 0 };
                                if (inet_ntop(AF_INET6, data, ipStr, sizeof(ipStr)))
                                    j[key] = std::string(ipStr);
                                else
                                    j[key] = "<inet_ntop_AF_INET6_failed>";
                            }
                        }
                        else {
                            // fallback: hex dump
                            std::ostringstream oss;
                            oss << "0x" << std::hex << std::setfill('0');
                            for (BYTE b : bytes) {
                                oss << std::setw(2) << static_cast<int>(b);
                            }
                            j[key] = oss.str();
                        }
                    }
                    catch (...) {
                        // ignore conversion errors
                        j[key] = "<parse error>";
                    }
                    break;
                }

                case TDH_INTYPE_GUID:
                {
                    GUID guid = parser.parse<GUID>(property_name);
                    std::ostringstream oss;
                    oss << std::hex << std::setfill('0')
                        << std::setw(8) << guid.Data1 << "-"
                        << std::setw(4) << guid.Data2 << "-"
                        << std::setw(4) << guid.Data3 << "-";

                    for (int i = 0; i < 2; i++)
                        oss << std::setw(2) << static_cast<int>(guid.Data4[i]);
                    oss << "-";
                    for (int i = 2; i < 8; i++)
                        oss << std::setw(2) << static_cast<int>(guid.Data4[i]);

                    j[key] = oss.str();
                    break;
                }

                case TDH_INTYPE_FILETIME:
                {
                    FILETIME fileTime = parser.parse<FILETIME>(property_name);
                    ULARGE_INTEGER uli;
                    uli.LowPart = fileTime.dwLowDateTime;
                    uli.HighPart = fileTime.dwHighDateTime;
                    j[key] = uli.QuadPart;
                    break;
                }

                case TDH_INTYPE_SID:
                {
                    std::vector<uint8_t> raw;
                    if (parser.try_parse(property_name, raw)) {
                        // try to convert raw bytes to a SID string
                        if (!raw.empty() && IsValidSid((PSID)raw.data())) {
                            LPWSTR sidString = nullptr;
                            if (ConvertSidToStringSidW((PSID)raw.data(), &sidString)) {
                                std::wstring ws(sidString);
                                j[key] = wstring_to_string(ws);
                                LocalFree(sidString);
                            }
                            else {
                                j[key] = "invalid_sid";
                            }
                        }
                        else {
                            // fallback: output raw data as hex
                            std::ostringstream oss;
                            oss << "0x";
                            for (auto b : raw) {
                                oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
                            }
                            j[key] = oss.str();
                        }
                    }
                    else {
                        // parsing failed, fallback: empty hex
                        j[key] = "0x";
                    }
                    break;
                }

                case TDH_INTYPE_HEXINT32:
                {
                    std::ostringstream oss;
                    oss << "0x" << std::hex << std::uppercase << parser.parse<uint32_t>(property_name);
                    j[key] = oss.str();
                    break;
                }

                case TDH_INTYPE_HEXINT64:
                {
                    std::ostringstream oss;
                    oss << "0x" << std::hex << std::uppercase << parser.parse<uint64_t>(property_name);
                    j[key] = oss.str();
                    break;
                }

                default:
                    std::cout << "[*] ETW: Warning: Unsupported property type " << property_type << " for " << j[TASK] << "'s " << key << "\n";
                    j[key] = "unsupported";
                    break;
                }

                if (overwritten_value != "") {
                    if (overwritten_value != j[key]) { // only warn if the values differ
                        std::cerr << "[!] ETW: Warning, " << j[PROVIDER_NAME] << ":" << j[EVENT_ID] <<
                            ", overwritten '" << key << ":" << overwritten_value <<
                            "' with '" << key << ":" << j[key] << "'";
                        if (original_key != "") { // include name of merged key (if overwrite was b.c. of a merge)
                            std::cerr << " because of merged key '" << original_key << "'";
                        }
                        std::cerr << "\n";
                    }
                }
            }
            catch (const std::exception& ex) {
                std::cerr <<
                    "[!] ETW: parse_etw_event failed to parse " << j[TASK] <<
                    ", key: " << last_key <<
                    ", type: " << last_type <<
                    ", error: " << ex.what() << "\n";
                j[last_key] = PARSE_ERROR; // write error and continue to next prop
            }
        }

        // callstack
        if (with_stack_trace) {
            try {
                j["stacktrace"] = json::array();
                int idx = 0;
                for (auto& return_address : schema.stack_trace()) {
                    // only add non-kernelspace addresses
                    if (return_address < 0xFFFF080000000000) {
                        j["stacktrace"].push_back(return_address);
                        idx++;
                    }
                }
            }
            catch (const std::exception& ex) {
                std::cerr << "[!] ETW: Failed to parse " << j[TASK] << "'s call stack: " << ex.what() << "\n";
            }
        }

        return j;
    }
    catch (const std::exception& ex) {
        std::cerr << "[!] ETW: parse_etw_event general exception: " << ex.what() << "\n";
        return json();
    }
}

// hand over schema for parsing
void event_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    g_trace_started = true;
    parse_etw_event(record, krabs::schema(record, trace_context.schema_locator));
}