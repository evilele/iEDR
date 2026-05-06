#pragma once

#include <winnt.h>
#include <vector>

// the names of the providers to track
static const std::string KERNEL_PROCESS_PROVIDER = "Microsoft-Windows-Kernel-Process";
static const std::wstring KERNEL_PROCESS_PROVIDER_W = std::wstring(KERNEL_PROCESS_PROVIDER.begin(), KERNEL_PROCESS_PROVIDER.end());
static const std::string KERNEL_API_PROVIDER = "Microsoft-Windows-Kernel-Audit-API-Calls";
static const std::wstring KERNEL_API_PROVIDER_W = std::wstring(KERNEL_API_PROVIDER.begin(), KERNEL_API_PROVIDER.end());
static const std::string KERNEL_FILE_PROVIDER = "Microsoft-Windows-Kernel-File";
static const std::wstring KERNEL_FILE_PROVIDER_W = std::wstring(KERNEL_FILE_PROVIDER.begin(), KERNEL_FILE_PROVIDER.end());
static const std::string KERNEL_NETWORK_PROVIDER = "Microsoft-Windows-Kernel-Network";
static const std::wstring KERNEL_NETWORK_PROVIDER_W = std::wstring(KERNEL_NETWORK_PROVIDER.begin(), KERNEL_NETWORK_PROVIDER.end());
static const std::string ANTIMALWARE_PROVIDER = "Microsoft-Antimalware-Engine";
static const std::wstring ANTIMALWARE_PROVIDER_W = std::wstring(ANTIMALWARE_PROVIDER.begin(), ANTIMALWARE_PROVIDER.end());
static const std::string THREAT_INTEL_PROVIDER = "Microsoft-Windows-Threat-Intelligence";
static const std::wstring THREAT_INTEL_PROVIDER_W = std::wstring(THREAT_INTEL_PROVIDER.begin(), THREAT_INTEL_PROVIDER.end());

bool start_etw_traces(std::vector<HANDLE>& threads);
void stop_etw_traces();
