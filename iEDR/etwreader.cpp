#include <iostream>
#include <krabs.hpp>

#include "etwreader.h"
#include "etwparser.h"

krabs::user_trace trace_etw(L"iEDR");

bool with_stack_trace = false;

DWORD WINAPI t_start_traces(LPVOID param) {
    try {
        // https://github.com/jdu2600/Etw-SyscallMonitor/tree/main/src/ETW

        // KERNEL //
        /*
            1 ProcessStart
            2 ProcessStop
            3 ThreadStart
            4 ThreadStop
            5 ImageLoad
            6 ImageUnload
            11 ProcessFreeze
        */
        krabs::provider<> kernel_process_provider(KERNEL_PROCESS_PROVIDER_W);
        std::vector<unsigned short> process_event_ids = { 1, 2, 3, 4, 5, 6, 11 };
        krabs::event_filter process_filter(process_event_ids);
        if (with_stack_trace) {
            kernel_process_provider.trace_flags(kernel_process_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
        }
        process_filter.add_on_event_callback(event_callback);
        kernel_process_provider.add_filter(process_filter);
        std::cout << "[+] ETW: Enabling " << KERNEL_PROCESS_PROVIDER << ": 1, 2, 3, 4, 5, 6, 11\n";
        trace_etw.enable(kernel_process_provider);

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
        krabs::provider<> kernelfile_provider(KERNEL_FILE_PROVIDER_W);
        std::vector<unsigned short> kernelfile_event_ids = { 10, 30 };
        krabs::event_filter kernelfile_filter(kernelfile_event_ids);
        if (with_stack_trace) {
            kernelfile_provider.trace_flags(kernelfile_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
        }
        kernelfile_filter.add_on_event_callback(event_callback);
        kernelfile_provider.add_filter(kernelfile_filter);
        std::cout << "[+] ETW: Enabling " << KERNEL_FILE_PROVIDER << ": 10, 30\n";
        trace_etw.enable(kernelfile_provider);

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
        krabs::provider<> kernelnetwork_provider(KERNEL_NETWORK_PROVIDER_W);
        std::vector<unsigned short> kernelnetwork_event_ids = { 12, 15, 28, 31, 42, 43, 58, 59 };
        krabs::event_filter kernelnetwork_filter(kernelnetwork_event_ids);
        if (with_stack_trace) {
            kernelnetwork_provider.trace_flags(kernelnetwork_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
        }
        kernelnetwork_filter.add_on_event_callback(event_callback);
        kernelnetwork_provider.add_filter(kernelnetwork_filter);
        std::cout << "[+] ETW: Enabling " << KERNEL_NETWORK_PROVIDER << ": 12, 15, 28, 31, 42, 43, 58, 59\n";
        trace_etw.enable(kernelnetwork_provider);

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
        krabs::provider<> kernel_auditapi_provider(KERNEL_API_PROVIDER_W);
        std::vector<unsigned short> auditapi_event_ids = { 3, 4, 5, 6 };
        krabs::event_filter auditapi_filter(auditapi_event_ids);
        if (with_stack_trace) {
            kernel_auditapi_provider.trace_flags(kernel_auditapi_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
        }
        auditapi_filter.add_on_event_callback(event_callback);
        kernel_auditapi_provider.add_filter(auditapi_filter);
        std::cout << "[+] ETW: Enabling " << KERNEL_API_PROVIDER << ": 3, 4, 5, 6\n";
        trace_etw.enable(kernel_auditapi_provider);

        // ANTIMALWARE //
        krabs::provider<> antimalwareengine_provider(ANTIMALWARE_PROVIDER_W);
        antimalwareengine_provider.add_on_event_callback(event_callback);
        std::cout << "[+] ETW: Enabling " << ANTIMALWARE_PROVIDER << " (all)\n";
        trace_etw.enable(antimalwareengine_provider);

        // trace_start is blocking, hence threaded
        std::cout << "[+] ETW: Traces registered, starting...\n";
        trace_etw.start();
    }
    catch (const std::exception& e) {
        std::cout << "[!] ETW: Traces exception: " << e.what() << "\n";
    }
    catch (...) {
        std::cout << "[!] ETW: Traces unknown exception\n";
    }

    std::cout << "[+] ETW: Traces thread finished\n";
    return 0;
}

bool start_etw_traces(std::vector<HANDLE>& threads) {
    HANDLE thread = CreateThread(NULL, 0, t_start_traces, NULL, 0, NULL);
    if (thread == NULL) {
        std::cerr << "[!] ETW: Could not start ETW thread\n";
        return false;
    }
    threads.push_back(thread);
    return true;
}

void stop_etw_traces() {
    try {
        trace_etw.stop();
    }
    catch (...) {
        std::cerr << "[!] ETW: Failed to stop traces\n";
    }
}