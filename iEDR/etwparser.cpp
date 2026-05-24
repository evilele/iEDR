#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <iostream>

#include "etwparser.h"
#include "providers.h"
#include "utils.h"

// do int-based fields (like ProcessId or DesiredAccess) match?
bool matches(long long actual, const filter& f) {
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
    case operation::Type::PATH_EQUALS: {
        if (g_autodetect_attack_path && g_attack_path.find_last_of(L'\\') == g_attack_path.length() - 1) { // in autodetect mode, no concrete path set yet
			std::wstring actual_folderpath = actual.substr(0, actual.find_last_of(L'\\'));
            return filepath_match(actual_folderpath, expected);
        }
		return filepath_match(actual, expected);
    }
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
            std::wcout << L"[+] ETW Event: " << provider_name << L" -  EventID: " << schema.event_id() << L" - Task: " << schema.task_name() << L"\n";
        }
		std::wstring task_name = schema.task_name();

        // 1.check if this provider is interesting
        auto prov_it = providers_to_track.find(provider_name);
        if (prov_it == providers_to_track.end()) return;
		const provider& p = prov_it->second;

        int last_int = -13371337;
		std::wstring last_wstr = L"dummypl4ceholder1234";

        // 2. parse fields
        krabs::parser parser(schema);

		// 3. check if this event ID is interesting, given the provider
        const auto& events = p.events_to_track.get(g_level);
        for (const auto& e : events) {
            if (e.id == id) {
                if (g_dev_debug) {
                    //std::wcout << L"[+] Found matching event ID " << id << L" for provider " << provider_name << L"\n";
                }


                // 4. iterate through all filters defined for this specific event & process filters for this specific event
                bool all_filters_passed = true;

                for (const auto& f : e.filters) {
                    bool current_match = false;
                    try {
                        switch (f.tdh_field_type) {
                        case TDH_INTYPE_UINT16: {
                            uint16_t val = parser.parse<uint16_t>(f.field_name);
                            current_match = matches((int)val, f);
							last_int = (int)val;
                            break;
                        }
                        case TDH_INTYPE_UINT32:
                        case TDH_INTYPE_HEXINT32: {
                            uint32_t val = parser.parse<uint32_t>(f.field_name);
                            current_match = matches((int)val, f);
                            last_int = (int)val;
                            break;
                        }
                        case TDH_INTYPE_UNICODESTRING: {
                            std::wstring val = parser.parse<std::wstring>(f.field_name);
                            current_match = matches(val, f);
							last_wstr = val;
                            break;
                        }
                        case TDH_INTYPE_ANSISTRING: {
                            std::string val = parser.parse<std::string>(f.field_name);
                            current_match = matches(std::wstring(val.begin(), val.end()), f);
							last_wstr = std::wstring(val.begin(), val.end());
                            break;
                        }
                        case TDH_INTYPE_POINTER:
                        case TDH_INTYPE_SIZET: {
                            uint64_t val = parser.parse<uint64_t>(f.field_name);
                            current_match = matches((long long)val, f);
							last_int = (int)val;
                            break;
                        }
                        default:
                            current_match = false;
							std::wcout << L"[!] Unsupported TDH field type " << f.tdh_field_type << L" for field '" 
                                << f.field_name << L"' in EventID " << provider_name << L" - " << schema.event_id() << L"\n";
                            break;
                        }
                    }
                    catch (const std::exception& e) {
                        if (g_dev_debug) {
                            std::wcerr << L"[!] Error parsing field '" << f.field_name << L"' with type " << f.tdh_field_type 
                                << L" for event " << provider_name << L" - " << schema.event_id() << L"\n";

                            std::string e_msg(e.what());
                            std::wstring msg(e_msg.begin(), e_msg.end());
                            std::wcerr << L"    Exception: " << msg << L"\n";

                            std::wcout << L"[***] Available Properties: ";
                            for (const auto& prop : parser.properties()) {
                                std::wcout << prop.name() << L"  ";
                            }
							std::wcout << L"\n";
                        }
                        current_match = false;
                    }

                    if (!current_match) {
                        all_filters_passed = false;

                        if (g_dev_debug) {
							bool skip_output = false; // some events are very noisy
                            auto prov_it = providers_event_ids_no_debug_output.find(provider_name);
                            if (prov_it != providers_event_ids_no_debug_output.end()) {
								auto ids = prov_it->second;
                                if (std::find(ids.begin(), ids.end(), schema.event_id()) != ids.end()) {
									skip_output = true; // this is a noisy event -> skip
                                }
                            }

                            if (!skip_output) {
                                std::wcout << L"[-] Filter failed: " << provider_name << L" - " << schema.event_id() << L" : (type " << f.tdh_field_type << L") " << f.field_name;
                                if (last_int != -13371337) {
                                    std::wcout << L" actual: " << last_int << L"\n";
                                }
                                else if (last_wstr.length() && std::wcscmp(last_wstr.c_str(), L"dummypl4ceholder1234") != 0) {
                                    std::wcout << L" actual: " << last_wstr << L"\n";
                                }
                                else {
                                    std::wcout << L" actual value could not be parsed\n";
                                }
                            }
                        }
                        break;
                    }
                }
                // 5. If all filters passed, output the event
                if (all_filters_passed) {
                    if (g_dev_debug) { // output all in dev mode
                        std::wcout << L"[+] Matched Event: " << provider_name << L" - " << schema.event_id() << L" : " << e.output << L"\n";
                    }
                    else {
						if (e.output.empty()) { // output generic if no specific output defined for this event
                            std::wcout << L"[+] Matched Event: " << provider_name << L" - " << schema.event_id() << L"\n";
                        }
						else { // output specific descriptor of event
                            std::wcout << timestamp_to_wstring(schema.timestamp()) << ": " << e.output << "\n";
                        }
                    }
                }
            }
		}
        // post parsing logic

        // check if the event marks the start of the attack
        if (g_attack_pid == 0 && provider_name == kernel_process_provider_name && id == 1) { // ProcessStart event
			std::wstring to_check = last_wstr; // the attack path / folder to check against, depending on auto-detect mode

            if (g_autodetect_attack_path) { // remove any.exe from C:\Users\Public\any.exe to compare the folder path for auto-detect mode
                size_t last_backslash = last_wstr.find_last_of(L'\\');
                if (last_backslash != std::wstring::npos) {
                    to_check = last_wstr.substr(0, last_backslash + 1);
                }
            }

            if (filepath_match(to_check, g_attack_path)) {
                try {
                    g_attack_pid = parser.parse<uint32_t>(L"ProcessID");
                } catch (const std::exception& e) {
                    if (g_dev_debug) {
                        std::string e_msg(e.what());
                        std::wstring msg(e_msg.begin(), e_msg.end());
                        std::wcerr << L"[!] Error parsing ProcessID for attack start event: " << msg << L"\n";
                    }
                    g_attack_pid = 0; // reset to 0
				}
				g_attack_pid_str = L"pid:" + std::to_wstring(g_attack_pid);
				//TODO g_attack_main_tid

                if (g_dev_debug) {
                    std::wcout << L"[+] Attack start detected (PID=" << last_int << L"): ProcessStart event for " << last_wstr << L"\n";
                }
				g_attack_pid = last_int;
                g_attack_pid_str = L"pid:" + std::to_wstring(last_int);
                if (g_autodetect_attack_path) {
                    g_attack_path = last_wstr; // set to actual file path for auto-detect mode
                    if (g_dev_debug) {
                        std::wcout << L"[+] Auto-detected new attack file path: " << g_attack_path << L"\n";
					}
				}
            }
		}
		// check if the event marks the end of the attack -> reset attack PID (and path) to be able to detect next attack
        if (provider_name == kernel_process_provider_name && id == 2) { // ProcessStop event
            if (last_int == g_attack_pid) {
                if (g_dev_debug) {
                    std::wcout << L"[+] Attack end detected: ProcessStop event for " << last_wstr << L"\n";
                }
                g_attack_pid = 0;
                g_attack_pid_str = L"";
                if (g_autodetect_attack_path) {
                    g_attack_path = g_attack_path.substr(0, g_attack_path.find_last_of(L'\\') + 1); // reset to folder path
                }
            }
        }
    }
    catch (const std::exception& e) {
        if (g_dev_debug) {
            std::string e_msg(e.what());
            std::wstring msg(e_msg.begin(), e_msg.end());
			std::wcerr << L"[!] Error parsing event: " << msg << L"\n";
        }
        return;
    }
}

// hand over schema for parsing
void event_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    g_trace_started = true;
    parse_etw_event(record, krabs::schema(record, trace_context.schema_locator));
}