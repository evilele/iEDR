#include "iEDR.h"
#include "cxxopts.h"
#include <iostream>

int main(int argc, char* argv[]) {
    std::cout << BANNER;

    cxxopts::Options options("iEDR");
    options.set_width(120);

    // PARSER OPTIONS
    options.add_options()
        ("h,help", "Print usage")
        ("a,attackExe", "The exact file path of the attack to be stored and monitored", cxxopts::value<std::string>())
        ("g,genericPath", "A generic folder path to monitor any new executable in it", cxxopts::value<std::string>());

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
    if (result.count("attackExe") + result.count("genericPath") != 1) {
        std::cerr << "[!] Either --attackExe OR --genericPath options is required.\n";
        std::cout << options.help() << "\n";
        return 1;
	}

    std::string attackPathFilter = "";
    if (result.count("attackExe")) {
        attackPathFilter = result["attackExe"].as<std::string>();
        std::cout << "[+] Monitoring path for a given attack executable: " << attackPathFilter << "\n";
    }
    if (result.count("genericPath")) {
        attackPathFilter = result["genericPath"].as<std::string>();
        std::cout << "[+] Monitoring path for any attack executables: " << attackPathFilter << "\n";
	}

    // todo define and start kernel-api-audit and antimalware-engine etw

    // todo define etw listeners 

    // todo print startup complete
    
    // todo define filters and only print relevant events

    // todo get any events from MDE event log

    // todo print end of analysis

    return 0;
}