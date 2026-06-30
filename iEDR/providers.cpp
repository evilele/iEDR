#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tdh.h>

#include "providers.h"
#include "utils.h"


// values to filter on must be variables (C++?)
const std::wstring c_get_hashes = L"GetHashes";
const std::wstring c_build_report = L"spynet_report::build_report";
const std::wstring c_usn_cache_name = L"USN Cache";

const std::wstring def_detection_store = L"ProgramData\\Microsoft\\Windows Defender\\Scans\\History\\Service\\DetectionHistory";
const std::wstring def_scan_store = L"ProgramData\\Microsoft\\Windows Defender\\Scans\\History\\Store";
const std::wstring def_quarantine = L"ProgramData\\Microsoft\\Windows Defender\\Quarantine";

const std::wstring any_match = L"";

/* providers to track */

/* https://github.com/jdu2600/Windows10EtwEvents/blob/main/manifest/Microsoft-Windows-Kernel-Process.tsv
    1 ProcessStart
    2 ProcessStop
    3 ThreadStart
    4 ThreadStop
    5 ImageLoad
    6 ImageUnload
    11 ProcessFreeze
*/
event kp1_m = { 1, nullptr, { { NO, PATH_EQUALS, &g_attack_path, L"ImageName" }, { DEC, ANY, 0, L"ProcessID" } }, L"START --- Attack process started" };
event kp1_s = { 1, nullptr, { { NO, IN_LIST, &g_attack_pids, L"ParentProcessID" }, { DEC, ANY, 0, L"ProcessID" } }, L"START --- Sub-process started" };
event kp2_m = { 2, nullptr, { { DEC, FIRST_IN_LIST, &g_attack_pids, L"ProcessID" } }, L"STOP --- Attack process stopped" };
event kp2_s = { 2, nullptr, { { DEC, NFIRST_IN_LIST, &g_attack_pids, L"ProcessID" } }, L"STOP --- Sub-process stopped" };
event kp3 = { 3, nullptr, { { NO, IN_LIST, &g_attack_pids, L"ProcessID" } }, L"Attack process started a thread" };
event kp4 = { 4, nullptr, { { NO, IN_LIST, &g_attack_pids, L"ProcessID" } }, L"Attack process stopped a thread" };
event kp5 = { 5, nullptr, { { NO, IN_LIST, &g_attack_pids, L"ProcessID" }, { STR, ANY, &any_match, L"ImageName" } }, L"Attack process loaded an image" };
event kp6 = { 6, nullptr, { { NO, IN_LIST, &g_attack_pids, L"ProcessID"}, { STR, ANY, &any_match, L"ImageName" } }, L"Attack process unloaded an image" };
event kp11 = { 11, nullptr, { { NO, IN_LIST, &g_attack_pids, L"FrozenProcessID"} }, L"Attack process frozen" };
provider kernel_process_provider = {
	KERNEL_PROCESS_PROVIDER,
    kernel_process_provider_name,
    {
        { kp1_m, kp1_s, kp2_m, kp2_s, kp11 },
        { kp1_m, kp1_s, kp2_m, kp2_s, kp3, kp4, kp5, kp6, kp11 },
        { kp1_m, kp1_s, kp2_m, kp2_s, kp3, kp4, kp5, kp6, kp11 }
    }
};

/* https://github.com/jdu2600/Windows10EtwEvents/blob/main/manifest/Microsoft-Windows-Kernel-File.tsv
    10 NameCreate
    30 CreateNewFile
*/
event kf10 = { 10, nullptr, { { NO, PATH_EQUALS, &g_attack_path, L"FileName" } }, L"Attack file (name) created" };
event kf11 = { 11, nullptr, { { NO, PATH_EQUALS, &g_attack_path, L"FileName" } }, L"Attack file (disposition) deleted" };
event kf26 = { 26, nullptr, { { STR, PATH_EQUALS, &g_attack_path, L"FilePath"} }, L"DELETE --- Attack file deleted" };
event kf26_any = { 26, nullptr, { { STR, ANY, &any_match, L"FilePath" } }, L"Deleted" };
event kf30 = { 30, nullptr, { { STR, PATH_EQUALS, &g_attack_path, L"FileName" } }, L"STORED --- Attack file created" };
event kf30_def_detected = { 30, nullptr, { { STR, CONTAINS_STR, &def_detection_store, L"FileName"} }, L"Defender detection file created" };
event kf30_def_scanned = { 30, nullptr, { { STR, CONTAINS_STR, &def_scan_store, L"FileName"} }, L"Defender scan file created" };
event kf30_def_quarantine = { 30, nullptr, { { STR, CONTAINS_STR, &def_quarantine, L"FileName"} }, L"Defender detection file created" };
event kf30_any = { 30, nullptr, { { STR, ANY, &any_match, L"FileName"} }, L"Created" };
provider kernel_file_provider = {
	KERNEL_FILE_PROVIDER,
    kernel_file_provider_name,
    {
        { kf26, kf30, kf30_def_scanned },
        { kf10, kf11, kf26, kf30, kf30_def_detected, kf30_def_scanned, kf30_def_quarantine },
        { kf10, kf11, kf26, kf26_any, kf30, kf30_def_detected, kf30_def_scanned, kf30_def_quarantine }
    }
};

// todo this could also be filtered for Microsoft IPs, maybe with https://www.microsoft.com/en-us/download/details.aspx?id=56519
/* https://github.com/jdu2600/Windows10EtwEvents/blob/main/manifest/Microsoft-Windows-Kernel-Network.tsv
    12 TCPIPConnectionattempted
    15 TCPIPConnectionaccepted
    28 TCPIPConnectionattempted
    31 TCPIPConnectionaccepted
    42 UDPIPDatasentoverUDPprotocol
    43 UDPIPDatareceivedoverUDPprotocol
    58 UDPIPDatasentoverUDPprotocol
    59 UDPIPDatareceivedoverUDPprotocol
*/
event kn12 = { 12, nullptr, {  { } } };
event kn15 = { 15, nullptr, {  { } } };
event kn28 = { 28, nullptr, {  { } } };
event kn31 = { 31, nullptr, {  { } } };
event kn42 = { 42, nullptr, {  { } } };
event kn43 = { 43, nullptr, {  { } } };
event kn58 = { 58, nullptr, {  { } } };
event kn59 = { 59, nullptr, {  { } } };
provider kernel_network_provider = {
	KERNEL_NETWORK_PROVIDER,
    kernel_network_provider_name,
    {
        { },
        { },
        { kn12, kn15, kn28, kn31, kn42, kn43, kn58, kn59 }
    }
};

/* https://github.com/jdu2600/Windows10EtwEvents/blob/main/manifest/Microsoft-Windows-Kernel-Audit-API-Calls.tsv
    1: PspLogAuditSetLoadImageNotifyRoutineEvent(kernel)
    2: PspLogAuditTerminateRemoteProcessEvent
    3: NtCreateSymbolicLink
    4: PspSetContextThreadInternal
    5: PspLogAuditOpenProcessEvent
    6: PspLogAuditOpenThreadEvent
    7: IoRegisterLastChanceShutdownNotification(kernel)
    8: IoRegisterShutdownNotification(kernel)
*/
//event ka3 = { 3, nullptr, { { NO, EQUALS, &g_attack_path, L"LinkSourceName" } }, L"Created link from attack file to X" }; // reverse would be interesting, maybe?
event ka4 = { 4, nullptr, { { } } };
event ka5_m = { 5, &g_edr_pid, { { DEC, FIRST_IN_LIST, &g_attack_pids, L"TargetProcessId" }, { HEX, CONTAINS_FLAG, 0x10, L"DesiredAccess" } }, MsMpEng + L" opened attack process with read access" };
event ka5_s = { 5, &g_edr_pid, { { DEC, NFIRST_IN_LIST, &g_attack_pids, L"TargetProcessId" }, { HEX, CONTAINS_FLAG, 0x10, L"DesiredAccess" } }, MsMpEng + L" opened sub-process with read access" };
event ka6 = { 6, nullptr, { { NO, EQUALS, g_attack_main_tid, L"ThreadId"} } };
provider kernel_api_provider = {
    KERNEL_AUDIT_API_PROVIDER,
    kernel_api_audit_provider_name,
    {
        { ka5_m, ka5_s },
        { ka5_m, ka5_s },
        { ka4, ka5_m, ka5_s, ka6 }
    }
};

/* https://github.com/jdu2600/Windows10EtwEvents/blob/main/manifest/Microsoft-Antimalware-Engine.tsv
* https://blog.levi.wiki/post/2026-01-09-defender-detection-mechanisms
*/
// minimal
event am1path = { 1, nullptr, { { NO, PATH_EQUALS, &g_attack_path, L"First Resource Path" } }, L"Emulation of attack file started" };
event am1proc = { 1, nullptr, { { STR, PID_STR_EQUALS, &g_attack_pids, L"First Resource Path" } }, L"Emulation of attack proc started" }; // check against "pid:1234"
event am5_m = { 5, nullptr, { { NO, IN_LIST, &g_attack_pids, L"PID" }, { STR, ANY, &any_match, L"Path" } }, L"Heuristic scan of attack file started" }; // contains both the PID and the corresponding imagename (path), match by pid and output path
event am5_r = { 5, nullptr, { { NO, IN_LIST, &g_attack_pids, L"PID" }, {STR, ANY, &any_match, L"Path" } }, L"Heuristic scan of attack-related file started" }; // contains both the PID and the corresponding imagename (path), match by pid and output path
event am7 = { 7, nullptr, { { STR, PATH_EQUALS, &g_attack_path, L"Path" } }, L"Heuristic scan of attack file skipped" };
event am43sig = { 43, nullptr, { { NO, PATH_EQUALS, &g_attack_path, L"Name" }, { NO, EQUALS, &c_get_hashes, L"Message" } }, L"Get hashes of attack file" };
event am43spy = { 43, nullptr, { { NO, PATH_EQUALS, &g_attack_path, L"Name"}, { NO, EQUALS, &c_build_report, L"Message"} }, L"Submit scan report" };

// relevant
event am30 = { 30, nullptr, { { NO, EQUALS, &g_attack_path, L"FilePath"} }, L"UFS emulation of attack file started" };
event am32 = { 32, nullptr, { { NO, EQUALS, &g_attack_path, L"FilePath"} }, L"UFS emulation of attack proc (loaded modules scan) started" };
event am35 = { 35, nullptr, { { NO, PATH_EQUALS, &g_attack_path, L"ScanSource"}, { STR, ANY, &any_match, L"Result"} }, L"Add (part of) attack to MOAC cache" };
event am36 = { 36, nullptr, { { NO, PATH_EQUALS, &g_attack_path, L"ScanSource"}, {HEX, ANY, 0, L"Result"} }, L"Lookup (part of) attack in MOAC cache" };
event am37 = { 37, nullptr, { { NO, PATH_EQUALS, &g_attack_path, L"ScanSource"}, {HEX, ANY, 0, L"Result"} }, L"Revoke (part of) attack from MOAC cache" };
event am38 = { 38, nullptr, { { NO, PATH_EQUALS, &g_attack_path, L"FileName"}, { STR, EQUALS, &c_usn_cache_name, L"CacheName"}, {HEX, ANY, 0, L"Result"} }, L"Lookup (part of) attack in USN Cache" };
event am39 = { 39, nullptr, { { NO, PATH_EQUALS, &g_attack_path, L"FileName"}, { STR, EQUALS, &c_usn_cache_name, L"CacheName"}, {HEX, ANY, 0, L"Result"} }, L"Lookup (part of) attack in" };

// all
event am2 = { 2, nullptr, {  } };
event am3 = { 3, nullptr, {  } };
event am4 = { 4, nullptr, {  } };
event am6 = { 6, nullptr, {  } };
event am11 = { 11, nullptr, {  } };
event am15 = { 15, nullptr, {  } };
event am16 = { 16, nullptr, {  } };
event am26 = { 26, nullptr, {  } };
event am31 = { 31, nullptr, {  } };
event am33 = { 33, nullptr, {  } };
event am44 = { 44, nullptr, {  }, L"Stored metadata" }; // meta store task (stores identifiers)
event am46 = { 46, nullptr, {  } };
event am53 = { 53, nullptr, {  } };
event am59 = { 59, nullptr, {  } };
event am60 = { 60, nullptr, {  } };
event am62 = { 62, nullptr, {  } };
event am67 = { 67, nullptr, {  } };
event am70 = { 70, nullptr, {  } };
event am71 = { 71, nullptr, {  } };
event am72 = { 72, nullptr, {  } };
event am73 = { 73, nullptr, {  } };
event am74 = { 74, nullptr, {  } };
event am95 = { 95, nullptr, {  } };
event am103 = { 103, nullptr, {  } };
event am104 = { 104, nullptr, {  } };
event am105 = { 105, nullptr, {  } };
event am109 = { 109, nullptr, {  } };
event am110 = { 110, nullptr, {  } };
event am111 = { 111, nullptr, {  } };
event am112 = { 112, nullptr, {  } };

provider antimalware_provider = {
    ANTIMALWARE_ENGINE_PROVIDER,
    antimalware_provider_name,
    {
        { am1path, am1proc, am5_m, am5_r, am7, am32, am43sig, am43spy },
        { am1path, am1proc, am5_m, am5_r, am7, am30, am32, am35, am36, am37, am38, am39, am43sig, am43spy },
        { am1path, am1proc, am2, am3, am4, am5_m, am5_r, am6, am11, am15, am16, am26, am30, am31, am32, am33, am35, am36, am37, am38, am39, am43sig, am43spy, am44, am53, am59, am60, am62, am67, am70, am71, am72, am73, am74, am95, am103, am104, am105, am109, am110, am111, am112 }
    }
};

std::vector<provider> providers_to_track = {
    kernel_process_provider,
    kernel_file_provider,
    kernel_network_provider,
    kernel_api_provider,
    antimalware_provider
};
