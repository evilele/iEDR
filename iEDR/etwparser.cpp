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

bool evaluate_filter(const filter& f, krabs::parser& parser) {
    try {

    }
    catch (...) {
        return false;
    }
}

void parse_etw_event(const EVENT_RECORD& record, const krabs::schema& schema) {

    try {
        std::wstring provider_name = schema.provider_name();
        unsigned short id = schema.event_id();
        if (g_debug) {
            std::wcout << L"[+] ETW Event: " << provider_name << L" - " << schema.event_id() << L"\n";
        }

        // 1. Quick Provider Lookup (if this provider is interesting)
        auto prov_it = providers_to_track.find(provider_name);
        if (prov_it == providers_to_track.end()) return;
		const provider& p = prov_it->second;

		// 2. Quick Event ID Lookup (if this event ID is interesting, given the provider)
        const auto& events = p.events_to_track.get(g_level);
        auto event_it = events.find(id);
        if (event_it == events.end()) return;
        const event& e = event_it->second;

		// 3. Iterate through all filters defined for this specific event
        krabs::parser parser(schema);
        bool all_filters_passed = true;

        // 4. Process filters for this specific event
        for (const auto& f : e.filters) {
            bool current_match = false;
            try {
                switch (f.tdh_field_type) {
                case TDH_INTYPE_UINT16: {
                    uint16_t val = parser.parse<uint16_t>(f.field_name);
                    current_match = matches((int)val, f);
                }
                case TDH_INTYPE_UINT32:
                case TDH_INTYPE_HEXINT32: {
                    uint32_t val = parser.parse<uint32_t>(f.field_name);
                    current_match = matches((int)val, f);
                }
                case TDH_INTYPE_UNICODESTRING: {
                    std::wstring val = parser.parse<std::wstring>(f.field_name);
                    current_match = matches(val, f);
                }
                case TDH_INTYPE_ANSISTRING: {
                    std::string val = parser.parse<std::string>(f.field_name);
                    current_match = matches(std::wstring(val.begin(), val.end()), f);
                }
                case TDH_INTYPE_POINTER:
                case TDH_INTYPE_SIZET: {
                    uint64_t val = parser.parse<uint64_t>(f.field_name);
                    current_match = matches((int)val, f);
                }
                default:
                    current_match = false;
                }
            }
            catch (...) {
                if (g_dev_debug) {
                    std::wcerr << L"[-] Error parsing field '" << f.field_name << L"' for event " << provider_name << L" - " << schema.event_id() << L"\n";
                }
                current_match = false;
            }

            if (!current_match) {
                all_filters_passed = false;
                if (g_dev_debug) {
                    std::wcout << L"[!] Filter failed: " << f.field_name << L" did not match expected value for event " << provider_name << L" - " << schema.event_id() << L"\n";
				}
                break;
            }
        }
        // 5. If all filters passed, output the event
        if (all_filters_passed) {
            if (g_dev_debug) {
                std::wcout << L"[!] Matched Event: " << provider_name << L" - " << schema.event_id() << L" : " << string_to_wstring(e.output) << L"\n";
            }
            else {
				std::cout << e.output << "\n";
            }
        }
    }
    catch (const std::exception& e) {
        if (g_dev_debug) {
			std::cerr << "[-] Error parsing event: " << e.what() << std::endl;
        }
        return;
    }
}

// hand over schema for parsing
void event_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    g_trace_started = true;
    parse_etw_event(record, krabs::schema(record, trace_context.schema_locator));
    if (g_dev_debug) {
		std::cout << "----------------------- Parsed event " << record.EventHeader.EventDescriptor.Id << " ---------\n";
    }
}