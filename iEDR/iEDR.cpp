#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "cxxopts.h"

#include <iostream>
#include <vector>

#include "iEDR.h"
#include "etwreader.h"
#include "utils.h"

bool g_trace_started = false;
bool g_debug = false;
bool g_dev_debug = false;

verbosity_level g_level = MINIMAL;

std::wstring g_attack_path;
int g_attack_pid = 0;
int g_attack_main_tid = 0;


bool is_admin() {
    BOOL is_admin = FALSE;
    PSID admin_group = nullptr;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(
        &NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &admin_group)) {
        CheckTokenMembership(nullptr, admin_group, &is_admin);
        FreeSid(admin_group);
    }
    return is_admin == TRUE;
}

int main(int argc, char* argv[]) {
    std::cout << BANNER;

    if (!is_admin()) {
        std::cerr << "[!] This program must be run as administrator.\n";
        return 1;
	}

    cxxopts::Options options("iEDR");
    options.set_width(120);

    // PARSER OPTIONS
    options.add_options()
        ("h,help", "Print usage")
        ("d,debug", "Enable debug output", cxxopts::value<bool>()->default_value("false"))
		("v,verbose", "Enable development debug output", cxxopts::value<bool>()->default_value("false"))
        ("a,attack", "The file path of the attack to trace", cxxopts::value<std::string>())
        ("l,level", "The verbosity level, between 0 (minimal) and 3 (verbose)", cxxopts::value<int>()->default_value("0"));

    cxxopts::ParseResult result;
    try {
        result = options.parse(argc, argv);
    }
    catch (const cxxopts::exceptions::parsing& e) {
        std::cerr << "Error parsing options: " << e.what() << "\n";
        std::cout << options.help() << "\n";
        return 1;
    }

    // PARSING
    if (result.count("help")) {
        std::cout << options.help() << "\n";
        return 0;
    }
    if (result.count("attack") == 0) {
        std::cerr << "[!] Attack path to track is required.\n";
        std::cout << options.help() << "\n";
        return 1;
    }
    else {
		g_attack_path = result["attack"].as<std::wstring>();
        if (g_attack_path.empty()) {
            std::cerr << "[!] Attack path to track cannot be empty.\n";
            return 1;
		}
        if (g_attack_path[g_attack_path.length() - 1] == (L'\\')) {
			// todo 
            // once attack detected, set g_attack_path to the actual file path, not the directory
            // when done, reset g_attack_path to folder path
			std::wcout << L"[+] Tracking EDR actions against all files in directory: " << g_attack_path << L"\n";
        }
        else {
            std::wcout << L"[+] Tracking EDR actions against attack: " << g_attack_path << L"\n";
        }
    }

    if (result.count("debug")) {
        g_debug = true;
        std::cout << "[+] Debug output enabled.\n";
	}
    if (result.count("verbose")) {
        g_dev_debug = true;
        std::cout << "[+] Development debug output enabled.\n";
    }

    if (result.count("level")) {
        int level = result["level"].as<int>();
        if (level < 0 || level > 2) {
            std::cerr << "[!] Invalid verbosity level. Please provide a value between 0 and 2.\n";
            return 1;
		}
        g_level = static_cast<verbosity_level>(level);
    }
    else {
        g_level = MINIMAL;
    }
    std::cout << "[+] Verbosity level set to: " << g_level << "\n";

    // start ETW traces for monitoring
    std::vector<HANDLE> threads;
    if (!start_etw_traces(threads)) {
        std::cerr << "[!] EDRi: Failed to start ETW traces.\n";
        return 1;
    }

    // temporary solution, wait for g_trace_started == true and exit again
    while (!g_trace_started) {
        if (g_debug) {
            std::cout << "[+] Waiting for ETW traces to start...\n";
		}
        Sleep(5000);
    }
    std::cout << "[+] ETW traces started, stopping again...\n";
	stop_etw_traces();
	std::cout << "[+] ETW traces stopped, exiting...\n";

    // todo define etw listeners 

    // todo print startup complete
    
    // todo define filters and only print relevant events

    // todo get any events from MDE event log

    // todo print end of analysis

    return 0;
}