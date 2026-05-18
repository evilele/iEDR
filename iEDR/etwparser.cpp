#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <iostream>

#include "etwparser.h"
#include "providers.h"
#include "utils.h"

// do int-based fields (like ProcessId or DesiredAccess) match?
bool matches(int actual, const filter& f) {
    int expected = f.expected.get_int();
    switch (f.op.type) {
    case operation::Type::EQUALS:
        return actual == expected;
    case operation::Type::CONTAINS_FLAG:
        return (actual & expected) != 0;
    default:
        return false;
    }
}

// do wstring-based fields (like FilePath) match?
bool matches(const std::wstring& actual, const filter& f) {
    std::wstring expected = f.expected.get_str();
    switch (f.op.type) {
    case operation::Type::EQUALS:
        return actual == expected;
    case operation::Type::CONTAINS_STR:
        return actual.find(expected) != std::wstring::npos;
    default:
        return false;
    }
}

void parse_etw_event(const EVENT_RECORD& record, const krabs::schema& schema) {

    try {
        std::wstring provider_name = schema.provider_name();
        unsigned short id = schema.event_id();
        if (g_debug) {
            std::wcout << L"[+] ETW Event: " << provider_name << L" -  EventID: " << schema.event_id() << L"\n";
        }

        // 1.check if this provider is interesting
        auto prov_it = providers_to_track.find(provider_name);
        if (prov_it == providers_to_track.end()) return;
		const provider& p = prov_it->second;

		// 2. check if this event ID is interesting, given the provider
        const auto& events = p.events_to_track.get(g_level);
        for (const auto& e : events) {
            if (e.id == id) {
                if (g_dev_debug) {
                    std::wcout << L"[+] Found matching event ID " << id << L" for provider " << provider_name << L"\n";
                }

                // 3. iterate through all filters defined for this specific event
                krabs::parser parser(schema);
                bool all_filters_passed = true;

                // 4. process filters for this specific event
                for (const auto& f : e.filters) {
                    bool current_match = false;
                    try {
                        switch (f.tdh_field_type) {
                        case TDH_INTYPE_UINT16: {
                            uint16_t val = parser.parse<uint16_t>(f.field_name);
                            current_match = matches((int)val, f);
                            break;
                        }
                        case TDH_INTYPE_UINT32:
                        case TDH_INTYPE_HEXINT32: {
                            uint32_t val = parser.parse<uint32_t>(f.field_name);
                            current_match = matches((int)val, f);
                            break;
                        }
                        case TDH_INTYPE_UNICODESTRING: {
                            std::wstring val = parser.parse<std::wstring>(f.field_name);
                            current_match = matches(val, f);
                            break;
                        }
                        case TDH_INTYPE_ANSISTRING: {
                            std::string val = parser.parse<std::string>(f.field_name);
                            current_match = matches(std::wstring(val.begin(), val.end()), f);
                            break;
                        }
                        case TDH_INTYPE_POINTER:
                        case TDH_INTYPE_SIZET: {
                            uint64_t val = parser.parse<uint64_t>(f.field_name);
                            current_match = matches((int)val, f);
                            break;
                        }
                        default:
                            current_match = false;
							std::wcout << L"[!] Unsupported TDH field type " << f.tdh_field_type << L" for field '" 
                                << f.field_name << L"' in EventID " << provider_name << L" - " << schema.event_id() << L"\n";
                            break;
                        }
                    }
                    catch (...) {
                        if (g_dev_debug) {
                            std::wcerr << L"[!] Error parsing field '" << f.field_name << L"' for event " << provider_name << L" - " << schema.event_id() << L"\n";
                        }
                        current_match = false;
                    }

                    if (!current_match) {
                        all_filters_passed = false;
                        if (g_dev_debug) {
                            std::wcout << L"[-] Filter failed: " << f.field_name << L" did not match expected value for event " << provider_name << L" - " << schema.event_id() << L"\n";
                        }
                        break;
                    }
                }
                // 5. If all filters passed, output the event
                if (all_filters_passed) {
                    if (g_dev_debug) {
                        std::wcout << L"[+] Matched Event: " << provider_name << L" - " << schema.event_id() << L" : " << string_to_wstring(e.output) << L"\n";
                    }
                    else {
                        std::cout << e.output << "\n";
                    }
                }
            }
		}
        // check if the event marks the start of the attack
        /*
        if (g_attack_pid == 0 && provider_name == kernel_process_provider_name && id == 1) { // ProcessStart event
            try {
                std::wstring image_name = parser.parse<std::wstring>(L"ImageName");
                if (image_name == g_attack_path) {
                    g_attack_started = true;
                    if (g_debug) {
                        std::wcout << L"[+] Attack started: ProcessStart event with ImageName " << image_name << L"\n";
                    }
                }
            }
            catch (...) {
                if (g_dev_debug) {
                    std::wcerr << L"[!] Error parsing ImageName for ProcessStart event\n";
                }
            }
		}
        */
    }
    catch (const std::exception& e) {
        if (g_dev_debug) {
			std::cerr << "[!] Error parsing event: " << e.what() << std::endl;
        }
        return;
    }
}

// hand over schema for parsing
void event_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    if (g_dev_debug) {
        std::cout << "----------------------- Parsing EventID: " << record.EventHeader.EventDescriptor.Id << " ---------\n";
    }
    g_trace_started = true;
    parse_etw_event(record, krabs::schema(record, trace_context.schema_locator));
    if (g_dev_debug) {
		std::cout << "----------------------- OK EventID: " << record.EventHeader.EventDescriptor.Id << " ---------\n";
    }
}