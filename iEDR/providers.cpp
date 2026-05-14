#include <tdh.h>

#include "providers.h"
#include "utils.h"

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
event kp1 = { 1,  { {L"ImageName", TDH_INTYPE_UNICODESTRING, {operation::Type::EQUALS}, g_attack_path} }, "Attack process started" };
event kp2 = { 2,  { {L"ImageName", TDH_INTYPE_UNICODESTRING, {operation::Type::EQUALS}, g_attack_path} }, "Attack process stopped" };
event kp3 = { 3,  { {L"ProcessID", TDH_INTYPE_UINT32, {operation::Type::EQUALS}, &g_attack_pid} }, "" };
event kp4 = { 4,  { {L"ProcessID", TDH_INTYPE_UINT32, {operation::Type::EQUALS}, &g_attack_pid} }, "" };
event kp5 = { 5,  { {L"ImageName", TDH_INTYPE_UNICODESTRING, {operation::Type::EQUALS}, g_attack_path} }, "" };
event kp6 = { 6,  { {L"ImageName", TDH_INTYPE_UNICODESTRING, {operation::Type::EQUALS}, g_attack_path} }, "" };
event kp11 = { 11, { {L"FrozenProcessID", TDH_INTYPE_UINT32, {operation::Type::EQUALS}, &g_attack_pid} }, "Attack process frozen" };
provider kernel_process_provider = {
    L"Microsoft-Windows-Kernel-Process",
    {
        { {kp1.id, kp1}, {kp2.id, kp2}, {kp11.id, kp11} },
        { {kp1.id, kp1}, {kp2.id, kp2}, {kp3.id, kp3}, {kp4.id, kp4}, {kp5.id, kp5}, {kp6.id, kp6}, {kp11.id, kp11} },
        { {kp1.id, kp1}, {kp2.id, kp2}, {kp3.id, kp3}, {kp4.id, kp4}, {kp5.id, kp5}, {kp6.id, kp6}, {kp11.id, kp11} }
    }
};

/* https://github.com/jdu2600/Windows10EtwEvents/blob/main/manifest/Microsoft-Windows-Kernel-File.tsv
    10 NameCreate
    30 CreateNewFile
*/
event kf10 = { 10, { {L"FileName", TDH_INTYPE_UNICODESTRING, {operation::Type::EQUALS}, g_attack_path} }, "Attack file (name) created" };
event kf30 = { 30, { {L"FileName", TDH_INTYPE_UNICODESTRING, {operation::Type::EQUALS}, g_attack_path} }, "Attack file created" };
provider kernel_file_provider = {
    L"Microsoft-Windows-Kernel-File",
    {
        { {kf30.id, kf30} },
        { {kf10.id, kf10}, {kf30.id, kf30} },
        { {kf10.id, kf10}, {kf30.id, kf30} }
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
event kn12 = { 12, {  { } } };
event kn15 = { 15, {  { } } };
event kn28 = { 28, {  { } } };
event kn31 = { 31, {  { } } };
event kn42 = { 42, {  { } } };
event kn43 = { 43, {  { } } };
event kn58 = { 58, {  { } } };
event kn59 = { 59, {  { } } };
provider kernel_network_provider = {
    L"Microsoft-Windows-Kernel-Network",
    {
        { },
        { },
        { {kn12.id, kn12}, {kn15.id, kn15}, {kn28.id, kn28}, {kn31.id, kn31}, {kn42.id, kn42}, {kn43.id, kn43}, {kn58.id, kn58}, {kn59.id, kn59} }
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
event ka3 = { 3, { {L"LinkSourceName", TDH_INTYPE_UNICODESTRING, {operation::Type::EQUALS}, g_attack_path} } };
event ka4 = { 4, { { } } };
event ka5 = { 5, { {L"TargetProcessId", TDH_INTYPE_UINT32, {operation::Type::EQUALS}, &g_attack_pid} , {L"DesiredAccess", TDH_INTYPE_UINT32, {operation::Type::CONTAINS_FLAG}, 0x400} } };
event ka6 = { 6, { {L"ThreadId", TDH_INTYPE_UINT32, {operation::Type::EQUALS}, &g_attack_main_tid} } };
provider kernel_api_provider = {
    L"Microsoft-Windows-Kernel-Audit-API-Calls",
    {
        { {ka5.id, ka5} },
        { {ka5.id, ka5} },
        { {ka3.id, ka3}, {ka4.id, ka4}, {ka5.id, ka5}, {ka6.id, ka6} }
    }
};

/*  https://github.com/jdu2600/Windows10EtwEvents/blob/main/manifest/Microsoft-Antimalware-Engine.tsv
*/
// minimal
event am1 = { 1, { {L"filepath", TDH_INTYPE_UNICODESTRING, {operation::Type::EQUALS}, g_attack_path} }, "Emulation of attack file started" };
event am1 = { 1, { {L"filepath", TDH_INTYPE_UNICODESTRING, {operation::Type::EQUALS}, g_attack_path} }, "Emulation of attack file done" };
event am5 = { 5, { {L"opid", TDH_INTYPE_UINT32, {operation::Type::EQUALS}, &g_attack_pid} }, "Heuristic scan of attack file started" };
event am30 = { 6, { {L"filepath", TDH_INTYPE_UNICODESTRING, {operation::Type::EQUALS}, g_attack_path} }, "Heuristic scan of attack file done" };
event am32 = { 32, { {L"filepath", TDH_INTYPE_UNICODESTRING, {operation::Type::EQUALS}, g_attack_path} }, "Scanning loaded modules" };
event am43 = { 43, { {L"filepath", TDH_INTYPE_UNICODESTRING, {operation::Type::EQUALS}, g_attack_path}, { L"data", TDH_INTYPE_UINT32, {operation::Type::EQUALS}, &g_attack_pid } }, "Get hashes of attack file" };

// relevant
event am36 = { 36, { {L"filepath", TDH_INTYPE_UNICODESTRING, {operation::Type::EQUALS}, g_attack_path} } };
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
    L"Microsoft-Antimalware-Engine",
    {
        { {am1.id, am1}, {am5.id, am5}, {am30.id, am30}, {am32.id, am32}, {am43.id, am43} },
        { {am1.id, am1}, {am5.id, am5}, {am30.id, am30}, {am32.id, am32}, {am36.id, am36}, {am43.id, am43}, {am44.id, am44}, {am46.id, am46} },
        { {am1.id, am1}, {am2.id, am2}, {am3.id, am3}, {am4.id, am4}, {am5.id, am5}, {am6.id, am6}, {am7.id, am7}, {am11.id, am11}, {am15.id, am15}, {am16.id, am16}, {am26.id, am26}, {am30.id, am30}, {am31.id, am31}, {am32.id, am32}, {am33.id, am33}, {am36.id, am36}, {am38.id, am38}, {am43.id, am43}, {am44.id, am44}, {am53.id, am53}, {am59.id, am59}, {am60.id, am60}, {am62.id, am62}, {am67.id, am67}, {am70.id, am70}, {am71.id, am71}, {am72.id, am72}, {am73.id, am73}, {am74.id, am74}, {am95.id, am95}, {am103.id, am103}, {am104.id, am104}, {am105.id, am105}, {am109.id, am109}, {am110.id, am110}, {am111.id, am111}, {am112.id, am112} }
    }
};

std::map<std::wstring, provider> providers_to_track = {
    {kernel_process_provider.provider_name, kernel_process_provider},
    {kernel_file_provider.provider_name, kernel_file_provider},
    {kernel_network_provider.provider_name, kernel_network_provider},
    {kernel_api_provider.provider_name, kernel_api_provider},
    {antimalware_provider.provider_name, antimalware_provider}
};