#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <iostream>

#include "etwparser.h"
#include "providers.h"
#include "utils.h"

// track attack process start and stop
void track_process(int id, const krabs::schema& schema) {

    // check if the event marks the start of the attack
    if (g_attack_pids.empty() && id == 1) { // ProcessStart event
        krabs::parser parser(schema);

        try {
            // the attack path to check against
            std::wstring image_name = parser.parse<std::wstring>(L"ImageName");

            if (filepath_match(image_name, g_attack_path)) {
                try {
                    int new_proc = parser.parse<uint32_t>(L"ProcessID");
                    g_attack_pids.push_back(new_proc);
                    if (g_debug) {
                        std::wcout << L"[+] Detected start of attack: " << image_name << " -> PID=" << new_proc << L"\n";
                    }
                }
                catch (const std::exception& e) {
                    if (g_dev_debug) {
                        std::wcerr << L"[!] Error parsing ProcessID for attack start event: " << string_to_wstring(e.what()) << L"\n";
                    }
                }
            }
        }
        catch (const std::exception& e) {
            if (g_dev_debug) {
                std::wcerr << L"[!] Error parsing ImageName for attack start event: " << string_to_wstring(e.what()) << L"\n";
            }
        }
    }

    // check if the event marks the start of the main thread
    else if (!g_attack_pids.empty() && g_attack_main_tid == 0 && id == 3) { // ThreadStart event
        krabs::parser parser(schema);

        try {
            int proc_id = parser.parse<uint32_t>(L"ProcessID");
            if (std::find(g_attack_pids.begin(), g_attack_pids.end(), proc_id) != g_attack_pids.end()) {
                g_attack_main_tid = parser.parse<uint32_t>(L"ThreadID");
                if (g_debug) {
                    std::wcout << L"[+] Detected main thread of main attack process -> TID=" << g_attack_main_tid << L"\n";
                }
            }
        }
        catch (const std::exception& e) {
            if (g_dev_debug) {
                std::wcerr << L"[!] Error parsing ThreadStart event for main thread detection: " << string_to_wstring(e.what()) << L"\n";
            }
        }
    }

    // check if the event marks the end of the attack -> reset attack PID (and path) to be able to detect next attack
    else if (!g_attack_pids.empty() && id == 2) { // ProcessStop event
        krabs::parser parser(schema);

        try {
            int proc_id = parser.parse<uint32_t>(L"ProcessID");
            std::string image_name = parser.parse<std::string>(L"ImageName"); // event id 2 uses ansi string

            auto it = std::find(g_attack_pids.begin(), g_attack_pids.end(), proc_id);
            if (it != g_attack_pids.end()) {

                g_attack_pids.erase(it, g_attack_pids.end()); // remove attack pid

                if (g_attack_pids.empty()) {
                    // reset tracking variables and print event log with a delay
                    reset_attack_tracking_and_print_evtl_threaded();

                    if (g_debug) {
                        std::wcout << L"[+] Detected termination of main attack process: " << string_to_wstring(image_name) << L"\n";
                    }
                }
                else {
                    if (g_debug) {
                        std::wcout << L"[+] Detected termination of an attack subprocess: " << string_to_wstring(image_name) << L"\n";
                    }
                }
            }
        }
        catch (const std::exception& e) {
            if (g_dev_debug) {
                std::wcerr << L"[!] Error parsing ProcessID for attack end event: " << string_to_wstring(e.what()) << L"\n";
            }
        }
    }

    // check if the event marks the end of the main thread -> reset main thread TID
    else if (!g_attack_pids.empty() && g_attack_main_tid != 0 && id == 4) { // ThreadStop event
        krabs::parser parser(schema);

        try {
            int proc_id = parser.parse<uint32_t>(L"ProcessID");
            int thread_id = parser.parse<uint32_t>(L"ThreadID");
            if (!g_attack_pids.empty() && proc_id == g_attack_pids[0] && thread_id == g_attack_main_tid) {
                if (g_dev_debug) {
                    std::wcout << L"[+] Detected end of main thread of main attack process\n";
                }
                g_attack_main_tid = 0;
            }
        }
        catch (const std::exception& e) {
            if (g_dev_debug) {
                std::wcerr << L"[!] Error parsing ThreadStop event for main thread detection: " << string_to_wstring(e.what()) << L"\n";
            }
        }
    }
}

void track_file(int id, const krabs::schema& schema) {
    if (id == 30) { // CreateNewFile event
        krabs::parser parser(schema);
        try {
            std::wstring file_path = parser.parse<std::wstring>(L"FileName");
            if (filepath_match(file_path, g_attack_path)) {
                if (g_debug) {
                    std::wcout << L"[+] Detected creation of attack file: " << file_path << L"\n";
                }
                GetSystemTime(&g_last_attack_store);
            }
        }
        catch (const std::exception& e) {
            if (g_dev_debug) {
                std::wcerr << L"[!] Error parsing CreateNewFile event for attack file creation tracking: " << string_to_wstring(e.what()) << L"\n";
            }
        }
    }

    if (id == 26) { // FileDelete event
        krabs::parser parser(schema);
        try {
            std::wstring file_path = parser.parse<std::wstring>(L"FilePath");
            if (filepath_match(file_path, g_attack_path)) {
                if (g_debug) {
                    std::wcout << L"[+] Detected deletion of attack file: " << file_path << L"\n";
                }
                if (g_attack_pids.empty()) { // if attack not started yet, also print malware report
                    reset_attack_tracking_and_print_evtl_threaded();
                }
            }
        }
        catch (const std::exception& e) {
            if (g_dev_debug) {
                std::wcerr << L"[!] Error parsing FileDelete event for attack file deletion tracking: " << string_to_wstring(e.what()) << L"\n";
            }
        }
    }
}

void parse_etw_event(const EVENT_RECORD& record, const krabs::schema& schema) {
    std::wstring provider_name = schema.provider_name();
    int id = schema.event_id();

    // todo: maybe refactor tracking (separate function and structs for proc started/stopped and file created/deleted ?)
    if (provider_name == kernel_process_provider_name) {
        track_process(id, schema);
    }

    // track attack file creation & deletion
    if (provider_name == kernel_file_provider_name) {
        track_file(id, schema);
    }

    // parse the event and check for relevancy
    try {

		// 1.check if this provider is interesting
        const auto it = std::find_if(providers_to_track.begin(), providers_to_track.end(), [&](const provider& p) {
            return p.provider_name == provider_name;
        });
        if (it == providers_to_track.end()) {
            return; // not found
        }
        const provider& prov = *it;

		// 2. check if this event ID is interesting, given the provider
        const auto& events = prov.events_to_track.get(g_level);
        for (const auto& e : events) {
            if (e.id != id) {
                continue;
            }

            // 3. iterate through all filters defined for this specific event & process filters for this specific event
            bool all_filters_passed = true;

            // 4. check originating PID filter (the PID emitting the event) if applicable
            if (e.originating_pid != nullptr) {
                int originating_pid = schema.process_id();
                if (*e.originating_pid != originating_pid) {
                    if (g_dev_debug) {
                        std::wcout << L"[-] Filter failed: " << provider_name << L" - " << id << L"." << schema.task_name()
                            << "." << schema.opcode_name() << L" : (type=uint) process_id" << L" actual: " << originating_pid << L"\n";
                    }
                    continue; // skip field parsing if originating PID filter already fails
                }
			}

            // 5. parse fields
            krabs::parser parser(schema);
			std::wstring add_field_output = L"";

            for (const auto& f : e.filters) {
                bool current_match = false;
                int type = -1;
                int last_int = 0; // dev debug
                std::wstring last_wstr = L""; // dev debug

                try {
                    // get property of given event filter
                    const krabs::property* prop  = nullptr;
                    for (const auto& p : parser.properties()) {
                        if (p.name() == f.field_name) {
							type = p.type();
                            break;
                        }
                    }
                    if (type == -1) { // not found
                        if (g_dev_debug) {
                            std::wcout << L"[-] Filter failed: " << provider_name << L" - " << id << L"." << schema.task_name()
                                << "." << schema.opcode_name() << L" : field '" << f.field_name << L"' not found in event properties\n";
                        }
                        current_match = false;
                        break; // field not found, mark filter as failed and skip to next filter
					}

                    switch (type) {
                    case TDH_INTYPE_UINT16: {
                        uint16_t val = parser.parse<uint16_t>(f.field_name);
                        current_match = f.matches(val);
						last_int = (int)val;
                        break;
                    }
                    case TDH_INTYPE_UINT32:
                    case TDH_INTYPE_HEXINT32: {
                        uint32_t val = parser.parse<uint32_t>(f.field_name);
                        current_match = f.matches(val);
                        last_int = (int)val;
                        break;
                    }
                    case TDH_INTYPE_UNICODESTRING: {
                        std::wstring val = parser.parse<std::wstring>(f.field_name);
                        current_match = f.matches(val);
						last_wstr = val;
                        break;
                    }
                    case TDH_INTYPE_ANSISTRING: {
                        std::string val = parser.parse<std::string>(f.field_name);
                        current_match = f.matches(std::wstring(val.begin(), val.end()));
						last_wstr = std::wstring(val.begin(), val.end());
                        break;
                    }
                    case TDH_INTYPE_POINTER:
                    case TDH_INTYPE_SIZET: {
                        uint64_t val = parser.parse<uint64_t>(f.field_name);
                        current_match = f.matches((int)val);
						last_int = (int)val;
                        break;
                    }
                    default:
                        current_match = false;
						std::wcout << L"[!] Unsupported TDH field type " << type << L" for field '"
                            << f.field_name << L"' in EventID " << provider_name << L" - " << id << L"\n";
                        break;
                    }

                    // if this is the field we also want to output for matched events, store the output value for later
                    if (e.add_output_field == f.field_name) {
                        add_field_output = L" " + f.field_name + L"=";
                        if (type == TDH_INTYPE_UNICODESTRING || type == TDH_INTYPE_ANSISTRING) {
                            add_field_output += last_wstr;
                        }
                        else {
                            // convert last_int to hex
                            std::wstringstream wss;
							wss << L"0x" << std::hex << last_int;
							add_field_output += wss.str();
                        }
					}
                }
                catch (const std::exception& e) {
                    if (g_dev_debug) {
                        std::wcerr << L"[!] Error parsing field '" << f.field_name << L"' (type=" << type << L") " << provider_name << L" - " << id << L"\n";
                        std::wcerr << L"    Exception: " << string_to_wstring(e.what()) << L"\n";

                        std::wcout << L"[***] Available Properties: ";
                        for (const auto& prop : parser.properties()) {
                            std::wcout << prop.name() << L"  ";
                        }
						std::wcout << L"\n";
                    }
                    current_match = false;
                }

                if (!current_match) {
                    if (g_dev_debug) {
                        std::wcout << L"[-] Filter failed: " << provider_name << L" - " << id << L"." <<  schema.task_name()
                            << "." << schema.opcode_name() << L" : (type=" << type << L") " << f.field_name;
                        if (last_int != 0) {
                            std::wcout << L" actual: " << last_int << L"\n";
                        }
                        else if (!last_wstr.empty()) {
                            std::wcout << L" actual: " << last_wstr << L"\n";
                        }
                        else {
                            std::wcout << L" actual value could not be parsed\n";
                        }
                    }

                    // mark event as not matching
                    all_filters_passed = false;
                    break;
                }
            }

            // 6. if all filters passed, output the event
            if (all_filters_passed) {

                // always output timestamp for matches
                std::wcout << timestamp_to_wstring(schema.timestamp()) << ": ";

                // if no specific output defined for this event, output generic info
                if (e.output.empty()) { 
                    std::wcout << id << L"." << schema.task_name() << "." << schema.opcode_name() << L" from " << provider_name << L" (no interpretation defined for event)";
                }
                else { // output defined interpretation
                    std::wcout << e.output;
                }
                if (!e.add_output_field.empty()) { // if specific output field defined, output the value of that field as well
                    if (!add_field_output.empty()) {
                        std::wcout << add_field_output;
                    }
                    else if (g_dev_debug) {
                        std::wcout << L" [!] Output field '" << e.add_output_field << L"' defined but value could not be parsed";
					}
				}

				// and maybe output more debug info
                if (g_dev_debug) { 
                    std::wcout << L" - " << provider_name << L" - " << id;
                }
				std::wcout << L"\n";
            }
		}
    }
    catch (const std::exception& e) {
        if (g_dev_debug) {
			std::wcerr << L"[!] Error parsing event: " << string_to_wstring(e.what()) << L"\n";
        }
        return;
    }
}

// hand over schema for parsing
void event_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    g_trace_started = true;
    parse_etw_event(record, krabs::schema(record, trace_context.schema_locator));
}