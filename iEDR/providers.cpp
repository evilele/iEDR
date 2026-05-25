#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tdh.h>

#include "providers.h"
#include "utils.h"

const std::wstring c_get_hashes = L"GetHashes";
const std::wstring c_build_report = L"spynet_report::build_report";

// todo define global start and stop event(s) of recordings?

// the providers to track
/* https://github.com/jdu2600/Windows10EtwEvents/blob/main/manifest/Microsoft-Windows-Kernel-Process.tsv
    1 ProcessStart
    2 ProcessStop
    3 ThreadStart
    4 ThreadStop
    5 ImageLoad
    6 ImageUnload
    11 ProcessFreeze
*/
event kp1 = { 1, nullptr, { {L"ImageName", {operation::Type::PATH_EQUALS}, &g_attack_path} }, L"START --- Attack process started" };
event kp2 = { 2, nullptr, { {L"ProcessID", {operation::Type::EQUALS}, &g_attack_pid} }, L"STOP --- Attack process stopped" };
event kp3 = { 3, nullptr, { {L"ProcessID", {operation::Type::EQUALS}, &g_attack_pid} }, L"Attack process started a thread" };
event kp4 = { 4, nullptr, { {L"ProcessID", {operation::Type::EQUALS}, &g_attack_pid} }, L"Attack process stopped a thread" };
event kp5 = { 5, nullptr, { {L"ImageName", {operation::Type::PATH_EQUALS}, &g_attack_path} }, L"" };
event kp6 = { 6, nullptr, { {L"ImageName", {operation::Type::PATH_EQUALS}, &g_attack_path} }, L"" };
event kp11 = { 11, nullptr, { {L"FrozenProcessID", {operation::Type::EQUALS}, &g_attack_pid} }, L"Attack process frozen" };
provider kernel_process_provider = {
    kernel_process_provider_name,
    {
        { kp1, kp2, kp11 },
        { kp1, kp2, kp3, kp4, kp5, kp6, kp11 },
        { kp1, kp2, kp3, kp4, kp5, kp6, kp11 }
    }
};

/* https://github.com/jdu2600/Windows10EtwEvents/blob/main/manifest/Microsoft-Windows-Kernel-File.tsv
    10 NameCreate
    30 CreateNewFile
*/
event kf10 = { 10, nullptr, { {L"FileName", {operation::Type::PATH_EQUALS}, &g_attack_path} }, L"Attack file (name) created" };
event kf30 = { 30, nullptr, { {L"FileName", {operation::Type::PATH_EQUALS}, &g_attack_path} }, L"STORED --- Attack file created" };
// todo: event kf30 is not matched in auto-detect mode, no dedicated start message
provider kernel_file_provider = {
    kernel_file_provider_name,
    {
        { kf30 },
        { kf10, kf30 },
        { kf10, kf30 }
    }
};

// todo this could also be filtered, for Microsoft ips for example
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
event ka3 = { 3, nullptr, { {L"LinkSourceName", {operation::Type::EQUALS}, &g_attack_path} } };
event ka4 = { 4, nullptr, { { } } };
event ka5 = { 5, &g_edr_pid, {
    {L"TargetProcessId", {operation::Type::EQUALS}, &g_attack_pid} , 
    {L"DesiredAccess", {operation::Type::CONTAINS_FLAG}, 0x400} ,
}, MDE_name + L" opened attack process with VM read access:",  L"DesiredAccess" };
event ka6 = { 6, nullptr, { {L"ThreadId", {operation::Type::EQUALS}, &g_attack_main_tid} } };
provider kernel_api_provider = {
    kernel_api_audit_provider_name,
    {
        { ka5 },
        { ka5 },
        { ka3, ka4, ka5, ka6 }
    }
};

/*  https://github.com/jdu2600/Windows10EtwEvents/blob/main/manifest/Microsoft-Antimalware-Engine.tsv
* https://blog.levi.wiki/post/2026-01-09-defender-detection-mechanisms
*/
// minimal
event am1path = { 1, nullptr, { {L"First Resource Path", {operation::Type::PATH_EQUALS}, &g_attack_path} }, L"Emulation of attack file started" };
event am1proc = { 1, nullptr, { {L"First Resource Path", {operation::Type::PID_STR_EQUALS}, &g_attack_pid} }, L"Emulation of attack proc started" }; // should match "pid:1234"
event am5 = { 5, nullptr, { {L"PID", {operation::Type::EQUALS}, &g_attack_pid} }, L"Heuristic scan of attack file started" };
event am7 = { 7, nullptr, { {L"Path", {operation::Type::PATH_EQUALS}, &g_attack_path} }, L"Heuristic scan of attack file skipped" };
event am43sig = { 43, nullptr, { {L"Name", {operation::Type::PATH_EQUALS}, &g_attack_path} , {L"Message", {operation::Type::EQUALS}, &c_get_hashes} }, L"Get hashes of attack file" };
event am43spy = { 43, nullptr, { {L"Name", {operation::Type::PATH_EQUALS}, &g_attack_path} , {L"Message", {operation::Type::EQUALS}, &c_build_report} }, L"Submit scan report" };

// relevant
event am30 = { 30, nullptr, { {L"FilePath", {operation::Type::EQUALS}, &g_attack_path} }, L"UFS emulation of attack file ( ? ) started" };
event am32 = { 32, nullptr, { {L"FilePath", {operation::Type::EQUALS}, &g_attack_path} }, L"UFS emulation of attack proc (loaded modules scan) started" };
event am36 = { 36, nullptr, { {L"FileName", {operation::Type::EQUALS}, &g_attack_path} } };
event am44 = { 44, nullptr, {  } }; // meta store task (stores identifiers)

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
event am38 = { 38, nullptr, {  } };
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
    antimalware_provider_name,
    {
        { am1path, am1proc, am5, am7, am43sig, am43spy },
        { am1path, am1proc, am5, am7, am30, am32, am36, am43sig, am43spy, am44, am46 },
        { am1path, am1proc, am2, am3, am4, am5, am6, am11, am15, am16, am26, am30, am31, am32, am33, am36, am38, am43sig, am43spy, am44, am53, am59, am60, am62, am67, am70, am71, am72, am73, am74, am95, am103, am104, am105, am109, am110, am111, am112 }
    }
};

std::map<std::wstring, provider> providers_to_track = {
    {kernel_process_provider.provider_name, kernel_process_provider},
    {kernel_file_provider.provider_name, kernel_file_provider},
    {kernel_network_provider.provider_name, kernel_network_provider},
    {kernel_api_provider.provider_name, kernel_api_provider},
    {antimalware_provider.provider_name, antimalware_provider}
};