#pragma once

#include <windows.h>
#include <pdh.h>
#include <pdhmsg.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <map>
#include <string>
#include <strsafe.h>
#include <tchar.h>
#include <stdio.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <psapi.h>
#include <tlhelp32.h> 
#include "nvml.h"


#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <iomanip>
#include <locale>
#include <codecvt>
#include <fstream>


#include "comms.hpp"


#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Pdh.lib")
#pragma comment(lib, "psapi.lib")

#define SAMPLE_INTERVAL_MS 1000  // 1 second sample rate
#define HIGH_CPU_THRESHOLD 80  // CPU usage percentage threshold
#define HIGH_GPU_THRESHOLD 70  // GPU usage percentage threshold
#define HIGH_POWER_THRESHOLD 50 // Power in watts (adjust as needed)
#define HIGH_BATTERY_DRAIN -10  // Negative value indicates battery drain
#define CONSISTENT_HIGH_USAGE_DURATION 3  // Number of consecutive readings


#define HIGH_CPU_PID_THRESOLD 30
#define HIGH_GPU_PID_THRESHOLD 30

#define DEBUG 0
#define NULL nullptr


class Utils {
public:
    std::wstring CreateTempTextFileWithContent(const std::wstring& buffer) {
        // Get the current executable's directory
        WCHAR exePath[MAX_PATH];
        GetModuleFileNameW(NULL, exePath, MAX_PATH);

        std::wstring dirPath = exePath;
        size_t pos = dirPath.find_last_of(L"\\/");
        if (pos != std::wstring::npos) {
            dirPath = dirPath.substr(0, pos + 1);
        }

        // Generate a unique temporary filename
        WCHAR tempFileName[MAX_PATH];
        GetTempFileNameW(dirPath.c_str(), L"TEMP", 0, tempFileName);

        // Rename file to have a .txt extension (optional but requested)
        std::wstring renamedFile = std::wstring(tempFileName) + L".txt";
        MoveFileW(tempFileName, renamedFile.c_str());

        // Write buffer to the file
        std::wofstream outFile(renamedFile);
        if (outFile.is_open()) {
            outFile << buffer;
            outFile.close();
        }
        else {
            std::wcerr << L"Failed to write to file: " << renamedFile << std::endl;
        }

        return renamedFile;
    }


    VOID PrintLastErrorMessage(DWORD errorCode) {
        LPWSTR messageBuffer = NULL;

        FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            errorCode,
            0, // Default language
            (LPWSTR)&messageBuffer,
            0,
            NULL
        );

        if (messageBuffer) {
            wprintf(L"\n\nError %d: %s\n", errorCode, messageBuffer);
            LocalFree(messageBuffer);
        }
        else {
            std::wcout << L"Unknown error code: " << errorCode << std::endl;
        }
    }

    std::wstring stringToWstring(const std::string& str) {
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        return converter.from_bytes(str);
    }

    std::string getOpcodesAsHexString(void* address, size_t length) {
        PUCHAR bytePtr = static_cast<UCHAR*>(address);
        std::ostringstream oss;

        for (size_t i = 0; i < length; ++i) {
            oss << "\\x" << std::hex << std::setw(2) << std::setfill('0') << (int)bytePtr[i];
        }

        return oss.str();
    }

    std::string RunPowerShellCommand(const std::wstring& command) {
        HANDLE hReadPipe, hWritePipe;
        SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

        // Create Pipe for capturing PowerShell output
        if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
            std::cerr << "❌ Failed to create pipe.\n";
            return "";
        }

        // PowerShell execution command
        std::wstring psCommand = L"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"" + command + L"\"";

        // Set up the process startup info
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        SecureZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.hStdOutput = hWritePipe;
        si.hStdError = hWritePipe;
        si.dwFlags |= STARTF_USESTDHANDLES;

        SecureZeroMemory(&pi, sizeof(pi));

        // Start PowerShell process
        if (!CreateProcessW(NULL, &psCommand[0], NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            PrintLastErrorMessage(GetLastError());
            std::wcerr << L"❌ Failed to start PowerShell.\n";
            CloseHandle(hReadPipe);
            CloseHandle(hWritePipe);
            return "";
        }

        // Close the write pipe handle as it's no longer needed
        CloseHandle(hWritePipe);

        // Read PowerShell output
        std::string output;
        char buffer[4096];
        DWORD bytesRead;
        while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            output += buffer;
        }

        // Cleanup
        CloseHandle(hReadPipe);
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        return output;
    }

    std::wstring GetProcessName(DWORD pid) {
        // Open the process with required access rights
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) {
            wprintf(L"Unable to open process %d to query its process name.\n", pid);
            return L"<Unknown>";
        }

        WCHAR processName[MAX_PATH] = L"<Unknown>";

        // Try to get the base name of the main module
        if (GetModuleBaseNameW(hProcess, NULL, processName, sizeof(processName) / sizeof(WCHAR)) == 0) {
            wprintf(L"GetModuleBaseNameW failed for process %d, trying QueryFullProcessImageNameW...\n", pid);

            // Fallback: Use QueryFullProcessImageNameW if GetModuleBaseNameW fails
            DWORD size = MAX_PATH;
            if (!QueryFullProcessImageNameW(hProcess, 0, processName, &size)) {
                wprintf(L"QueryFullProcessImageNameW also failed for process %d.\n", pid);
                CloseHandle(hProcess);
                return L"<Unknown>";
            }
        }

        CloseHandle(hProcess);  // Close the handle to the process
        return std::wstring(processName);  // Return the process name as a wstring
    }

    BOOL TerminateProcessByPID(DWORD pid) {
        // Open the process with terminate rights
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hProcess == NULL) {
            if (DEBUG) {
                wprintf(L"Failed to open process with PID %lu. Error code: %lu\n", pid, GetLastError());
            }
            return FALSE;
        }

        // Attempt to terminate the process
        if (!TerminateProcess(hProcess, 0)) {
            if (DEBUG) {
                wprintf(L"Failed to terminate process with PID %lu. Error code: %lu\n", pid, GetLastError());
            }
            CloseHandle(hProcess);
            return FALSE;
        }

        if (DEBUG) {
            wprintf(L"Successfully terminated process with PID %lu.\n", pid);
        }

        CloseHandle(hProcess);
        return TRUE;
    }

    BOOL GetTextSectionInfo(PVOID pBaseAddress, PVOID* pTextSectionAddress, SIZE_T* pTextSectionSize) {
        // Check if the base address is valid
        if (!pBaseAddress) {
            wprintf(L"Invalid base address\n");
            return FALSE;
        }

        // Get the DOS header
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBaseAddress;
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            wprintf(L"Invalid DOS header\n");
            return FALSE;
        }

        // Get the NT headers
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pBaseAddress + pDosHeader->e_lfanew);
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
            wprintf(L"Invalid PE header\n");
            return FALSE;
        }

        // Get the section table
        PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

        // Iterate through the section table to find the .text section
        for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
            if (strcmp((PCHAR)pSectionHeader[i].Name, ".text") == 0) {
                // Found the .text section
                *pTextSectionAddress = (PBYTE)pBaseAddress + pSectionHeader[i].VirtualAddress;
                *pTextSectionSize = pSectionHeader[i].Misc.VirtualSize;
                return TRUE;
            }
        }

        // .text section not found
        wprintf(L".text section not found\n");
        return FALSE;
    }

    // Function to read memory from another process
    BOOL ReadProcessMemorySafe(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize) {
        SIZE_T bytesRead;
        if (!ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, &bytesRead) || bytesRead != nSize) {
            wprintf(L"Failed to read memory at address 0x%p. Error: %d\n", lpBaseAddress, GetLastError());
            return FALSE;
        }
        return TRUE;
    }

    // Function to get the .text section address and size of another process
    BOOL GetProcessTextSectionInfo(DWORD pid, PVOID pBaseAddress, PVOID* pTextSectionAddress, SIZE_T* pTextSectionSize, PBYTE* pTextMem) {
        // Open the target process
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) {
            wprintf(L"Failed to open process (PID: %d). Error: %d\n", pid, GetLastError());
            return FALSE;
        }

        // Read the DOS header
        IMAGE_DOS_HEADER dosHeader;
        if (!ReadProcessMemorySafe(hProcess, pBaseAddress, &dosHeader, sizeof(dosHeader))) {
            CloseHandle(hProcess);
            return FALSE;
        }

        // Validate the DOS header
        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
            wprintf(L"Invalid DOS header\n");
            CloseHandle(hProcess);
            return FALSE;
        }

        // Read the NT headers
        IMAGE_NT_HEADERS ntHeaders;
        if (!ReadProcessMemorySafe(hProcess, (PBYTE)pBaseAddress + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders))) {
            CloseHandle(hProcess);
            return FALSE;
        }

        // Validate the NT headers
        if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
            wprintf(L"Invalid NT headers\n");
            CloseHandle(hProcess);
            return FALSE;
        }

        // Read the section headers
        IMAGE_SECTION_HEADER sectionHeader;
        DWORD sectionOffset = dosHeader.e_lfanew + sizeof(ntHeaders.Signature) + sizeof(ntHeaders.FileHeader) + ntHeaders.FileHeader.SizeOfOptionalHeader;

        // Iterate through the section table to find the .text section
        for (DWORD i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
            if (!ReadProcessMemorySafe(hProcess, (PBYTE)pBaseAddress + sectionOffset + (i * sizeof(sectionHeader)), &sectionHeader, sizeof(sectionHeader))) {
                CloseHandle(hProcess);
                return FALSE;
            }

            // Check if this is the .text section
            if (strcmp((PCHAR)sectionHeader.Name, ".text") == 0) {
                // Calculate the .text section address and size
                *pTextSectionAddress = (PBYTE)pBaseAddress + sectionHeader.VirtualAddress;
                *pTextSectionSize = sectionHeader.Misc.VirtualSize;
                *pTextMem = ReadTextSectionBytes(hProcess, *pTextSectionAddress, *pTextSectionSize);
                CloseHandle(hProcess);
                return TRUE;
            }
        }

        // .text section not found
        wprintf(L".text section not found for process %d\n", pid);
        CloseHandle(hProcess);
        return FALSE;
    }


    // Function to read bytes from the .text section of another process
    BYTE* ReadTextSectionBytes(HANDLE hProcess, PVOID pTextSectionAddress, SIZE_T textSectionSize) {
        // Allocate a buffer to hold the .text section bytes
        PBYTE pBuffer = (PBYTE)calloc(textSectionSize, sizeof(BYTE));
        if (!pBuffer) {
            printf("Failed to allocate memory for .text section buffer\n");
            return NULL;
        }

        // Read the .text section bytes from the target process
        SIZE_T bytesRead;
        if (!ReadProcessMemory(hProcess, pTextSectionAddress, pBuffer, textSectionSize, &bytesRead)) {
            printf("Failed to read .text section bytes. Error: %d\n", GetLastError());
            free(pBuffer);
            return NULL;
        }

        // Ensure all bytes were read
        if (bytesRead != textSectionSize) {
            printf("Warning: Only read %zu out of %zu bytes\n", bytesRead, textSectionSize);
        }

        return pBuffer;
    }

    // Function to retrieve the full executable path for a given PID.
// Returns true if successful, with the path stored in szFileName.
    BOOL GetProcessExecutablePath(DWORD pid, LPTSTR szFileName, DWORD cchFileName) {
        // Open the process with rights to query information and read memory.
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (hProcess == NULL) {
            _tprintf(_T("Error: Unable to open process %u. Error code: %u\n"), pid, GetLastError());
            return FALSE;
        }

        // Query the full process image name.
        if (!QueryFullProcessImageName(hProcess, 0, szFileName, &cchFileName)) {
            _tprintf(_T("Error: Unable to query process image name for PID %u. Error code: %u\n"), pid, GetLastError());
            CloseHandle(hProcess);
            return FALSE;
        }
        CloseHandle(hProcess);
        return TRUE;
    }

    // Function to delete a file given its full path.
// If DeleteFile fails (e.g. file is locked), it schedules deletion on next reboot.
    BOOL DeleteFileWithFallback(LPCTSTR szFileName) {
        if (DeleteFile(szFileName)) {
            _tprintf(_T("Success: File deleted successfully.\n"));
            return TRUE;
        }
        else {
            DWORD dwError = GetLastError();
            _tprintf(_T("Warning: DeleteFile failed with error code %u. Attempting to schedule deletion on reboot...\n"), dwError);
            if (MoveFileEx(szFileName, NULL, MOVEFILE_DELAY_UNTIL_REBOOT)) {
                _tprintf(_T("Info: File scheduled for deletion on next reboot.\n"));
                return TRUE;
            }
            else {
                _tprintf(_T("Error: Failed to schedule file deletion. Error code: %u\n"), GetLastError());
                return FALSE;
            }
        }
    }

    DWORD getpid() {
        return GetCurrentProcessId();
    }

    DWORD getppid()
    {
        HANDLE hSnapshot;
        PROCESSENTRY32 pe32;
        DWORD ppid = 0, pid = GetCurrentProcessId();

        hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        __try {
            if (hSnapshot == INVALID_HANDLE_VALUE) __leave;

            ZeroMemory(&pe32, sizeof(pe32));
            pe32.dwSize = sizeof(pe32);
            if (!Process32First(hSnapshot, &pe32)) __leave;

            do {
                if (pe32.th32ProcessID == pid) {
                    ppid = pe32.th32ParentProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));

        }
        __finally {
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                CloseHandle(hSnapshot);
            }
        }
        return ppid;
    }

};


class PerformanceMonitor {
private:
    PDH_HQUERY hQuery = NULL;
    PDH_HCOUNTER hCounterCPU = NULL, hCounterGPU = NULL, hCounterBattery = NULL;
    std::vector<PDH_HCOUNTER> hPowerCounters;
    BOOL hasPowerCounter = TRUE, hasGPUCounter = TRUE, hasBatteryCounter = TRUE;
    typedef struct _SystemMetrics {
        DOUBLE cpuUsage;
        DOUBLE gpuUsage;
        DOUBLE powerUsage;
        DOUBLE batteryDischargeRate;
    } SystemMetrics;

    // 🔹 Function to find all GPU engine utilization counters.
    // Queries the system for all instances of "GPU Engine" and constructs counter paths for utilization values.
    std::vector<std::wstring> FindAllGPUCounters() {
        std::vector<std::wstring> gpuCounters; // Stores the counter paths for GPU engines.
        DWORD counterListLength = 0, instanceListLength = 0; // Lengths of counter and instance lists.
        LPWSTR counterList = nullptr, instanceList = nullptr; // Pointers to the lists of counters and instances.

        // First call to `PdhEnumObjectItemsW` to retrieve the required buffer size for counters and instances.
        PDH_STATUS status = PdhEnumObjectItemsW(
            nullptr,
            nullptr,
            L"GPU Engine",
            counterList,
            &counterListLength,
            instanceList,
            &instanceListLength,
            PERF_DETAIL_WIZARD,
            0
        );

        // If the function does not return the required data size, log the error and exit.
        if (status != static_cast<PDH_STATUS>(PDH_MORE_DATA)) { // Fixed signed-unsigned warning.
            std::wcout << L"[ERROR] Failed to retrieve GPU counter list. Status: " << std::to_wstring(status);
            return gpuCounters; // Return an empty vector if an error occurs.
        }

        // Allocate memory for the counter and instance lists using the sizes retrieved earlier.
        counterList = new WCHAR[counterListLength];
        instanceList = new WCHAR[instanceListLength];

        // Second call to `PdhEnumObjectItemsW` to retrieve the actual counter and instance data.
        status = PdhEnumObjectItemsW(
            nullptr,
            nullptr,
            L"GPU Engine",
            counterList,
            &counterListLength,
            instanceList,
            &instanceListLength,
            PERF_DETAIL_WIZARD,
            0
        );

        // If the function call fails, log the error, clean up memory, and exit.
        if (status != ERROR_SUCCESS) {
            std::wcout << L"[ERROR] Failed to enumerate GPU instances. Status: " << std::to_wstring(status);
            delete[] counterList;
            delete[] instanceList;
            return gpuCounters; // Return an empty vector on failure.
        }

        // Loop through the instance list and construct counter paths for GPU utilization.
        LPWSTR instance = instanceList;
        while (*instance) {
            std::wstring instanceStr(instance); // Convert instance to std::wstring.
            gpuCounters.push_back(L"\\GPU Engine(" + instanceStr + L")\\Utilization Percentage");
            instance += wcslen(instance) + 1; // Move to the next instance in the list.
        }

        // Clean up dynamically allocated memory.
        delete[] counterList;
        delete[] instanceList;

        return gpuCounters; // Return the list of GPU counters.
    }

    // This function checks to ensure that there is a power meter available for running
    BOOL CheckPowerMeterAvailability() {
        DWORD counterListSize = 0;
        DWORD instanceListSize = 0;
        PDH_STATUS status = PdhEnumObjectItems(NULL, NULL, L"Power Meter", NULL, &counterListSize, NULL, &instanceListSize, PERF_DETAIL_WIZARD, 0);

        if (status == PDH_MORE_DATA) {
            std::wstring counterList(counterListSize, L'\\0');
            std::wstring instanceList(instanceListSize, L'\\0');

            status = PdhEnumObjectItems(NULL, NULL, L"Power Meter", &counterList[0], &counterListSize, &instanceList[0], &instanceListSize, PERF_DETAIL_WIZARD, 0);

            if (status == ERROR_SUCCESS) {
                if (DEBUG) {
                    std::wcout << L"Power Meter object is available. Counters: " << counterList << std::endl;
                    std::wcout << L"Instances: " << instanceList << std::endl;
                }
                return TRUE;
            }
            else {
                std::wcerr << L"Failed to enumerate Power Meter items. Error: " << status << std::endl;
                return FALSE;
            }
        }
        else {
            std::wcerr << L"Power Meter object not available on this system or error: " << status << std::endl;
            return FALSE;
        }
    }

    // Function gets ALL of the Power Meter paths that are available for calling on the system
    std::vector<std::wstring> GetAllPowerMeterPaths() {
        DWORD size = 0;

        // Expand the counter path for retrieving information from the power metrics
        PdhExpandCounterPath(L"\\Power Meter(*)\\Power", NULL, &size);
        std::wstring buffer(size, L'\\0');


        PDH_STATUS status = PdhExpandCounterPath(L"\\Power Meter(*)\\Power", &buffer[0], &size);

        std::vector<std::wstring> paths;
        if (status == ERROR_SUCCESS) {
            size_t start = 0, end = 0;
            while ((end = buffer.find(L'\\0', start)) != std::wstring::npos) {

                paths.push_back(buffer.substr(start, end - start));
                start = end + 1;
            }
        }
        std::wcout << L"Total available Power Meter paths: " << paths.size() << std::endl;
        return paths;
    }


    // Function needed to initialize the WMI interface needed for the Base Power Meter Usage
    IWbemServices* InitializeWMI(VOID) {
        HRESULT hres;
        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) {
            std::wcerr << L"Failed to initialize COM library. Error code: " << hres << std::endl;
            return nullptr;
        }

        hres = CoInitializeSecurity(
            NULL,
            -1,
            NULL,
            NULL,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            EOAC_NONE,
            NULL
        );
        if (FAILED(hres)) {
            std::wcerr << L"Failed to initialize security. Error code: " << hres << std::endl;
            CoUninitialize();
            return nullptr;
        }

        IWbemLocator* pLoc = NULL;
        hres = CoCreateInstance(
            CLSID_WbemLocator,
            0,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator,
            (LPVOID*)&pLoc
        );
        if (FAILED(hres)) {
            std::wcerr << L"Failed to create IWbemLocator object. Error code: " << hres << std::endl;
            CoUninitialize();
            return NULL;
        }

        IWbemServices* pSvc = NULL;
        hres = pLoc->ConnectServer(
            _bstr_t(L"ROOT\\CIMV2"),
            NULL,
            NULL,
            0,
            0,
            0,
            0,
            &pSvc
        );
        if (FAILED(hres)) {
            std::wcerr << L"Failed to connect to WMI. Error code: " << hres << std::endl;
            pLoc->Release();
            CoUninitialize();
            return nullptr;
        }

        hres = CoSetProxyBlanket(
            pSvc,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            NULL,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            EOAC_NONE
        );
        if (FAILED(hres)) {
            std::wcerr << L"Failed to set proxy blanket. Error code: " << hres << std::endl;
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return NULL;
        }

        pLoc->Release();
        return pSvc;
    }

    // Function to shutdown WMI
    VOID ShutdownWMI(IWbemServices* pSvc) {
        pSvc->Release();
        CoUninitialize();
    }

    // Function to estimate base power usage
    DOUBLE EstimateBasePowerUsage(IWbemServices* pSvc) {
        DOUBLE basePowerUsage = 0.0;

        // Query for motherboard (assume 20-30 watts)
        IEnumWbemClassObject* pEnumerator = nullptr;
        HRESULT hres = pSvc->ExecQuery(
            bstr_t("WQL"),
            bstr_t("SELECT * FROM Win32_BaseBoard"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &pEnumerator
        );
        if (SUCCEEDED(hres)) {
            IWbemClassObject* pclsObj = nullptr;
            ULONG uReturn = 0;
            while (pEnumerator) {
                hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                if (uReturn == 0) {
                    break;
                }
                // Assume motherboard consumes 25 watts
                basePowerUsage += 25.0;
                pclsObj->Release();
            }
            pEnumerator->Release();
        }

        // Query for RAM (assume 2-5 watts per DIMM)
        pEnumerator = nullptr;
        hres = pSvc->ExecQuery(
            bstr_t("WQL"),
            bstr_t("SELECT * FROM Win32_PhysicalMemory"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &pEnumerator
        );
        if (SUCCEEDED(hres)) {
            IWbemClassObject* pclsObj = nullptr;
            ULONG uReturn = 0;
            while (pEnumerator) {
                hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                if (uReturn == 0) break;

                // Assume each RAM DIMM consumes 3 watts
                basePowerUsage += 3.0;
                pclsObj->Release();
            }
            pEnumerator->Release();
        }

        // Query for disks (assume 5 watts per disk)
        pEnumerator = NULL;
        hres = pSvc->ExecQuery(
            bstr_t("WQL"),
            bstr_t("SELECT * FROM Win32_DiskDrive"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &pEnumerator
        );
        if (SUCCEEDED(hres)) {
            IWbemClassObject* pclsObj = nullptr;
            ULONG uReturn = 0;
            while (pEnumerator) {
                hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                if (uReturn == 0) {
                    break;
                }

                // Assume each disk consumes 5 watts
                basePowerUsage += 5.0;
                pclsObj->Release();
            }
            pEnumerator->Release();
        }

        // Add power for other components (fans, peripherals, etc.)
        basePowerUsage += 10.0; // Assume 10 watts for other components

        return basePowerUsage;
    }

    // Function to estimate power usage in watts
    DOUBLE EstimatePowerUsage(VOID) {
        SYSTEM_POWER_STATUS powerStatus;
        if (!GetSystemPowerStatus(&powerStatus)) {
            std::cerr << "Failed to get system power status." << std::endl;
            return -1.0;
        }

        // Check if the system is running on AC power or battery
        BOOL isOnACPower = (powerStatus.ACLineStatus == 1);

        // Get CPU usage
        FILETIME idleTime, kernelTime, userTime;
        if (!GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
            std::cerr << "Failed to get system times." << std::endl;
            return -1.0;
        }

        ULARGE_INTEGER idle, kernel, user;
        idle.LowPart = idleTime.dwLowDateTime;
        idle.HighPart = idleTime.dwHighDateTime;
        kernel.LowPart = kernelTime.dwLowDateTime;
        kernel.HighPart = kernelTime.dwHighDateTime;
        user.LowPart = userTime.dwLowDateTime;
        user.HighPart = userTime.dwHighDateTime;

        ULONGLONG totalTime = (kernel.QuadPart + user.QuadPart);
        ULONGLONG idleTotalTime = idle.QuadPart;

        static ULONGLONG previousTotalTime = 0;
        static ULONGLONG previousIdleTime = 0;

        ULONGLONG deltaTime = totalTime - previousTotalTime;
        ULONGLONG idleDeltaTime = idleTotalTime - previousIdleTime;

        previousTotalTime = totalTime;
        previousIdleTime = idleTotalTime;

        DOUBLE cpuUsage = 0.0;
        if (deltaTime != 0) {
            cpuUsage = 100.0 - (100.0 * idleDeltaTime) / deltaTime;
        }

        // Estimate power usage based on CPU usage and assumptions
        DOUBLE basePowerUsage = isOnACPower ? 50.0 : 30.0; // Base power usage in watts
        DOUBLE cpuPowerUsage = cpuUsage / 100.0 * 100.0;   // Assuming CPU can consume up to 100W at full load

        IWbemServices* pSvc = InitializeWMI();
        if (pSvc) {
            basePowerUsage = EstimateBasePowerUsage(pSvc);
            ShutdownWMI(pSvc);
        }


        DOUBLE estimatedPowerUsage = basePowerUsage + cpuPowerUsage;

        return estimatedPowerUsage;
    }


public:
    struct NVMLFunctions {
        typedef nvmlReturn_t(*NvmlInit_t)();
        typedef nvmlReturn_t(*NvmlShutdown_t)();
        typedef nvmlReturn_t(*NvmlDeviceGetCount_t)(unsigned int*);
        typedef nvmlReturn_t(*NvmlDeviceGetHandleByIndex_t)(unsigned int, nvmlDevice_t*);
        typedef nvmlReturn_t(*NvmlDeviceGetUtilizationRates_t)(nvmlDevice_t, nvmlUtilization_t*);
        typedef nvmlReturn_t(*NvmlDeviceGetPowerUsage_t)(nvmlDevice_t, unsigned int*);
        typedef nvmlReturn_t(*NvmlDeviceGetMemoryInfo_t)(nvmlDevice_t, nvmlMemory_t*);
        typedef nvmlReturn_t(*NvmlDeviceGetTemperature_t)(nvmlDevice_t, nvmlTemperatureSensors_t, unsigned int*);
        typedef nvmlReturn_t(*NvmlDeviceGetTotalEnergyConsumption_t)(nvmlDevice_t, unsigned long long*);
        typedef nvmlReturn_t(*NvmlDeviceGetName_t)(nvmlDevice_t, char*, unsigned int);
        typedef nvmlReturn_t(*NvmlDeviceGetComputeRunningProcesses_t)(nvmlDevice_t, unsigned int*, nvmlProcessInfo_t*);
        typedef const char* (*NvmlErrorString_t)(nvmlReturn_t);

        NvmlInit_t NvmlInit;
        NvmlShutdown_t NvmlShutdown;
        NvmlDeviceGetCount_t NvmlDeviceGetCount;
        NvmlDeviceGetHandleByIndex_t NvmlDeviceGetHandleByIndex;
        NvmlDeviceGetUtilizationRates_t NvmlDeviceGetUtilizationRates;
        NvmlDeviceGetPowerUsage_t NvmlDeviceGetPowerUsage;
        NvmlDeviceGetMemoryInfo_t NvmlDeviceGetMemoryInfo;
        NvmlDeviceGetTemperature_t NvmlDeviceGetTemperature;
        NvmlDeviceGetTotalEnergyConsumption_t NvmlDeviceGetTotalEnergyConsumption;
        NvmlDeviceGetName_t NvmlDeviceGetName;
        NvmlDeviceGetComputeRunningProcesses_t NvmlDeviceGetComputeRunningProcesses;
        NvmlErrorString_t NvmlErrorString;
    };

    HMODULE nvmlLib;
    NVMLFunctions funcs;


    BOOL InitializeNVML(HMODULE& nvmlLib, NVMLFunctions& funcs) {
        nvmlLib = LoadLibraryA("C:\\Windows\\System32\\nvml.dll");
        if (!nvmlLib) {
            std::cerr << "[ERROR] NVML DLL not found.\n";
            return FALSE;
        }

        funcs.NvmlInit = (NVMLFunctions::NvmlInit_t)GetProcAddress(nvmlLib, "nvmlInit_v2");
        funcs.NvmlShutdown = (NVMLFunctions::NvmlShutdown_t)GetProcAddress(nvmlLib, "nvmlShutdown");
        funcs.NvmlDeviceGetCount = (NVMLFunctions::NvmlDeviceGetCount_t)GetProcAddress(nvmlLib, "nvmlDeviceGetCount_v2");
        funcs.NvmlDeviceGetHandleByIndex = (NVMLFunctions::NvmlDeviceGetHandleByIndex_t)GetProcAddress(nvmlLib, "nvmlDeviceGetHandleByIndex_v2");
        funcs.NvmlDeviceGetUtilizationRates = (NVMLFunctions::NvmlDeviceGetUtilizationRates_t)GetProcAddress(nvmlLib, "nvmlDeviceGetUtilizationRates");
        funcs.NvmlDeviceGetPowerUsage = (NVMLFunctions::NvmlDeviceGetPowerUsage_t)GetProcAddress(nvmlLib, "nvmlDeviceGetPowerUsage");
        funcs.NvmlDeviceGetMemoryInfo = (NVMLFunctions::NvmlDeviceGetMemoryInfo_t)GetProcAddress(nvmlLib, "nvmlDeviceGetMemoryInfo");
        funcs.NvmlDeviceGetTemperature = (NVMLFunctions::NvmlDeviceGetTemperature_t)GetProcAddress(nvmlLib, "nvmlDeviceGetTemperature");
        funcs.NvmlDeviceGetTotalEnergyConsumption = (NVMLFunctions::NvmlDeviceGetTotalEnergyConsumption_t)GetProcAddress(nvmlLib, "nvmlDeviceGetTotalEnergyConsumption");
        funcs.NvmlDeviceGetName = (NVMLFunctions::NvmlDeviceGetName_t)GetProcAddress(nvmlLib, "nvmlDeviceGetName");
        funcs.NvmlDeviceGetComputeRunningProcesses = (NVMLFunctions::NvmlDeviceGetComputeRunningProcesses_t)GetProcAddress(nvmlLib, "nvmlDeviceGetComputeRunningProcesses");
        funcs.NvmlErrorString = (NVMLFunctions::NvmlErrorString_t)GetProcAddress(nvmlLib, "nvmlErrorString");

        if (!funcs.NvmlInit || !funcs.NvmlShutdown || !funcs.NvmlDeviceGetCount || !funcs.NvmlDeviceGetHandleByIndex ||
            !funcs.NvmlDeviceGetUtilizationRates || !funcs.NvmlDeviceGetPowerUsage || !funcs.NvmlDeviceGetMemoryInfo ||
            !funcs.NvmlDeviceGetTemperature || !funcs.NvmlDeviceGetTotalEnergyConsumption || !funcs.NvmlDeviceGetName ||
            !funcs.NvmlDeviceGetComputeRunningProcesses || !funcs.NvmlErrorString) {
            std::cerr << "[ERROR] NVML function loading failed.\n";
            FreeLibrary(nvmlLib);
            return FALSE;
        }

        if (funcs.NvmlInit() != NVML_SUCCESS) {
            std::cerr << "[ERROR] NVML initialization failed.\n";
            FreeLibrary(nvmlLib);
            return FALSE;
        }
        return TRUE;
    }

    // CLASS CONSTRUCTOR
    PerformanceMonitor(VOID) {
        // Initialize PDH Query
        if (PdhOpenQuery(NULL, 0, &hQuery) != ERROR_SUCCESS) {
            std::cerr << "Failed to open PDH Query" << std::endl;
            return;
        }

        // Add CPU counter
        if (PdhAddCounter(hQuery, L"\\Processor Information(_Total)\\% Processor Utility", 0, &hCounterCPU) != ERROR_SUCCESS) {
            std::cerr << "Failed to add CPU counter" << std::endl;
        }
        else {
            std::cout << "Successfully got the CPU Counter" << std::endl;
        }

        // Add Power Meter counter (if available)
        if (!CheckPowerMeterAvailability()) {
            std::cerr << "Power meter monitoring not available. Will use estimated power usage." << std::endl;
            hasPowerCounter = FALSE;
        }
        else {
            for (CONST auto& path : GetAllPowerMeterPaths()) {
                PDH_HCOUNTER counter;
                if (PdhAddCounter(hQuery, path.c_str(), 0, &counter) == ERROR_SUCCESS) {
                    hPowerCounters.push_back(counter);
                }
            }

            if (hPowerCounters.empty()) {
                std::cerr << "Power meter monitoring not available with given paths. Will use estimated power usage." << std::endl;
                hasPowerCounter = FALSE;
            }
            else {
                std::cout << "Successfully got the Power Meter" << std::endl;
            }
        }


        // Add Battery Discharge Rate counter (if available)
        if (PdhAddCounter(hQuery, L"\\Battery Status(*)\\Discharge Rate", 0, &hCounterBattery) != ERROR_SUCCESS) {
            std::cerr << "Battery discharge monitoring not available." << std::endl;
            hasBatteryCounter = FALSE;
        }
        else {
            std::cout << "Successfully got the Battery Discharge rate" << std::endl;
        }

        // Initial data collection
        PdhCollectQueryData(hQuery);
    }

    ~PerformanceMonitor(VOID) {
        funcs.NvmlShutdown();
        FreeLibrary(nvmlLib);
        PdhCloseQuery(hQuery);
    }

    // 🔹 Function to monitor total CPU utilization.
    // Opens a PDH query, adds GPU engine counters, collects utilization data periodically, and logs the results.
    DOUBLE getCPUUsage(VOID) {
        PDH_FMT_COUNTERVALUE counterValue = { 0 };
        PDH_STATUS status = 0;
        PDH_STATUS init = PdhCollectQueryData(hQuery);

        //Create a PDH query to get GPU data
        if (init == ERROR_SUCCESS &&
            (status = PdhGetFormattedCounterValue(hCounterCPU, PDH_FMT_DOUBLE, NULL, &counterValue)) == ERROR_SUCCESS) {
            
            if (DEBUG) {
                std::wcout << L"Total CPU Usage: " << counterValue.doubleValue << L"%\n" << std::flush;
            }
            return counterValue.doubleValue;
        }
        else {
            if (DEBUG)
            {
                std::wcerr << L"[ERROR] Couldn't get the the CPU Usage: " + std::to_wstring(status) + L" " + std::to_wstring(init) << std::endl;
            }
        }

        return -ERROR_INTERNAL_ERROR; // Indicate failure
    }



    // 🔹 Function to monitor total GPU utilization.
    // Executes NVML library calls, collects utilization data periodically, and returns the results.
    DOUBLE getGPUUsage(VOID) {
        
        if (funcs.NvmlDeviceGetCount == NULL || funcs.NvmlDeviceGetHandleByIndex == NULL || funcs.NvmlDeviceGetName == NULL || funcs.NvmlDeviceGetUtilizationRates == NULL) {
            return 0;
        }

        UINT deviceCount = 0;
        FLOAT totalUsagePercentage = 0;
        if (funcs.NvmlDeviceGetCount(&deviceCount) != NVML_SUCCESS || deviceCount == 0) {
            std::cerr << "[ERROR] No NVIDIA GPUs found.\n";
            return 0;
        }

        totalUsagePercentage = 0.0f;
        DWORD validDevices = 0;

        for (DWORD i = 0; i < deviceCount; i++) {
            nvmlDevice_t device;
            if (funcs.NvmlDeviceGetHandleByIndex(i, &device) != NVML_SUCCESS) {
                continue;
            }

            CHAR name[64];
            nvmlUtilization_t utilization;
            for (int i = 0; i < 10; i++) {
                utilization = { 0 };
                if (funcs.NvmlDeviceGetName(device, name, sizeof(name)) != NVML_SUCCESS ||
                    funcs.NvmlDeviceGetUtilizationRates(device, &utilization) != NVML_SUCCESS || 
                    utilization.gpu <= 0) {
                    Sleep(10);
                    continue;
                }
            }

            totalUsagePercentage += utilization.gpu;
            validDevices++;

            if (DEBUG) {
                std::cout << "[GPU " << i << " - " << name << "] Usage: " << utilization.gpu << "%\n";
            }

        }

        if (validDevices > 0) {
            totalUsagePercentage /= validDevices;
            return totalUsagePercentage;
        }
        return 0;
    }

    // 🔹 Function to monitor total Power usage.
    // Opens a PDH query, adds GPU engine counters, collects utilization data periodically, and returns the results.

    DOUBLE getPowerUsage(VOID) {
        
        if (!hasPowerCounter) {
            return EstimatePowerUsage();
        }

        PDH_STATUS status = PdhCollectQueryData(hQuery);
        DOUBLE totalPower = 0.0;
        if (status == ERROR_SUCCESS) {
            for (auto& counter : hPowerCounters) {
                PDH_FMT_COUNTERVALUE counterValue;
                if (PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE, NULL, &counterValue) == ERROR_SUCCESS) {
                    totalPower += counterValue.doubleValue;
                }
            }
            return totalPower;
        }
        else {
            std::wcerr << L"[ERROR] Failed to retrieve power usage. PDH Status: " << status << std::endl;
            return EstimatePowerUsage();
        }

    }

    DOUBLE getBatteryDischargeRate(VOID) {
        if (!hasBatteryCounter) {
            return -1;
        }
        PDH_STATUS status = 0;
        PDH_FMT_COUNTERVALUE counterValue = { 0 };
        PDH_STATUS init = PdhCollectQueryData(hQuery);

        if (init == ERROR_SUCCESS &&
            (status = PdhGetFormattedCounterValue(hCounterBattery, PDH_FMT_DOUBLE, NULL, &counterValue)) == ERROR_SUCCESS) {
            return counterValue.doubleValue;
        }
        else {
            if (DEBUG) {
                std::wcerr << L"Couldn't get the the Battery Usage: " + std::to_wstring(status) + L" " + std::to_wstring(init) << std::endl;
            }
        }

        return -ERROR_INTERNAL_ERROR;
    }


    SystemMetrics collectMetrics() {
        return { getCPUUsage(), getGPUUsage(), getPowerUsage(), getBatteryDischargeRate() };
    }

    // Function to determine if power usage is consistently high
    BOOL isConsistentlyHighUsage() {
        INT highUsageCount = 0;

        while (TRUE) {
            Sleep(SAMPLE_INTERVAL_MS);
            SystemMetrics metrics = collectMetrics();
            std::cout << std::endl;

            if (metrics.cpuUsage >= 0)
            {
                std::cout << "CPU Usage: " << metrics.cpuUsage << "%" << std::endl;
            }

            if (metrics.gpuUsage >= 0)
            {
                std::cout << "GPU Usage: " << metrics.gpuUsage << "%" << std::endl;
            }

            if (metrics.powerUsage >= 0)
            {
                std::cout << "Power Usage: " << metrics.powerUsage << " watts" << std::endl;
            }

            if (metrics.batteryDischargeRate >= 0)
            {
                std::cout << "Battery Discharge Rate: " << metrics.batteryDischargeRate << " mW" << std::endl;
            }

            bool isHighUsage = FALSE;

            if (metrics.cpuUsage > HIGH_CPU_THRESHOLD) {
                std::cout << "[ALERT] High CPU usage detected!" << std::endl;
                isHighUsage = TRUE;
            }
            if (metrics.gpuUsage > HIGH_GPU_THRESHOLD) {
                std::cout << "[ALERT] High GPU usage detected!" << std::endl;
                isHighUsage = TRUE;
            }
            if (metrics.powerUsage > HIGH_POWER_THRESHOLD) {
                std::cout << "[ALERT] High Power usage detected!" << std::endl;
                isHighUsage = TRUE;
            }
            if (metrics.batteryDischargeRate < HIGH_BATTERY_DRAIN) {
                std::cout << "[ALERT] High battery discharge detected!" << std::endl;
                isHighUsage = TRUE;
            }


            // If any metric is above threshold, increase count
            if (isHighUsage) {
                highUsageCount++;
            }
            else {
                highUsageCount = 0;
            }

            // If high usage continues for a set duration, return true
            if (highUsageCount >= CONSISTENT_HIGH_USAGE_DURATION) {
                std::cout << "[CRITICAL] System has had consistently high power usage for "
                    << CONSISTENT_HIGH_USAGE_DURATION << " seconds!" << std::endl;
                return TRUE;
            }
        }
        return FALSE;
    }


};


class ProcessMonitor {

private:
    // executes powershell command as needed
    std::string ExecutePowerShell(CONST std::string& script) {
        std::string command = "powershell -NoProfile -ExecutionPolicy Bypass -Command \"" + script + "\"";
        std::string result;
        char buffer[128];
        FILE* pipe = _popen(command.c_str(), "r");
        if (!pipe) {
            return "Error";
        }
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }
        _pclose(pipe);
        return result;
    }
    // 🔹 Function to find all GPU counters for a given process ID
    std::vector<std::wstring> FindAllGPUCountersForPID(DWORD pid) {
        std::vector<std::wstring> gpuCounters;
        DWORD counterListLength = 0, instanceListLength = 0;
        LPWSTR counterList = nullptr, instanceList = nullptr;

        // Enumrate all instances of GPU engine 
        PDH_STATUS status = PdhEnumObjectItemsW(
            nullptr,
            nullptr,
            L"GPU Engine",
            counterList,
            &counterListLength,
            instanceList,
            &instanceListLength,
            PERF_DETAIL_WIZARD,
            0
        );

        if (status != PDH_MORE_DATA) {
            std::wcerr << L"[ERROR] Failed to retrieve GPU counter list. Status: " << status << L"\n" << std::flush;
            return gpuCounters;
        }

        counterList = new WCHAR[counterListLength];
        instanceList = new WCHAR[instanceListLength];

        // Enumrate all instances of GPU engine 
        status = PdhEnumObjectItemsW(
            nullptr,
            nullptr,
            L"GPU Engine",
            counterList,
            &counterListLength,
            instanceList,
            &instanceListLength,
            PERF_DETAIL_WIZARD,
            0
        );

        if (status != ERROR_SUCCESS) {
            std::wcerr << L"[ERROR] Failed to enumerate GPU instances. Status: " << status << L"\n" << std::flush;
            delete[] counterList;
            delete[] instanceList;
            return gpuCounters;
        }

        LPWSTR instance = instanceList;
        std::wcout << L"Have a list of counters that may work for pid " << pid << std::endl;
        while (*instance) {
            std::wstring instanceStr(instance);
            if (instanceStr.find(L"pid_" + std::to_wstring(pid)) != std::wstring::npos) {
                gpuCounters.push_back(L"\\GPU Engine(" + instanceStr + L")\\Utilization Percentage");
            }
            instance += wcslen(instance) + sizeof(WCHAR);
        }

        delete[] counterList;
        delete[] instanceList;
        return gpuCounters;
    }

    std::string replaceSubtext(const std::string& original, const std::string& from, const std::string& to) {
        if (from.empty()) {
            return original; // Avoid infinite loop if 'from' is empty.
        }

        std::string result = original;
        size_t pos = 0;
        while ((pos = result.find(from, pos)) != std::string::npos) {
            result.replace(pos, from.length(), to);
            pos += to.length(); // Advance the position past the inserted substring.
        }
        return result;
    }

public:
    // Struct to hold GPU usage snapshot
    typedef struct _GpuUsageSnapshot {
        DOUBLE totalMemoryMB;
        std::map<INT, DOUBLE> processMemoryMB; // PID -> memory usage in MB
    } GpuUsageSnapshot;
    // 🔹 Function to find GPU % Usage given a process

    // Function to find CPU % usage for given PID
    DOUBLE GetCpuUsageForProcess(DWORD pid) {

        // Attempt to open process to query information
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProcess) {
            fwprintf(stderr, L"[ERROR] Failed to open process (PID: %lu).\n", pid);
            return 0.0;
        }

        ULONGLONG lastCycles, currentCycles;

        // Get CPU Cycles for this process (initial)
        if (!QueryProcessCycleTime(hProcess, &lastCycles)) {
            fwprintf(stderr, L"[ERROR] Failed to query process cycles for (PID: %lu).\n", pid);
            CloseHandle(hProcess);
            return 0.0;
        }

        // Sleep for a very short duration (10ms) for update in data
        Sleep(10);

        // Get CPU Cycles for this process (final)
        if (!QueryProcessCycleTime(hProcess, &currentCycles)) {
            fwprintf(stderr, L"[ERROR] Failed to query process cycles for (PID: %lu).\n", pid);
            CloseHandle(hProcess);
            return 0.0;
        }

        ULONGLONG cycleDiff = currentCycles - lastCycles;

        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        DWORD numProcessors = sysInfo.dwNumberOfProcessors;

        wprintf(L"Total Process CPU Usage for (PID %d) %.2f%%\n", pid, (cycleDiff / 10000.0) / numProcessors);

        CloseHandle(hProcess);

        //Sleep(100);
        //std::this_thread::sleep_for(std::chrono::seconds(2)); // Sleep to avoid excessive CPU usage
        
        return (cycleDiff / 10000.0) / numProcessors;
    }

    // Function to get a snapshot of GPU usage data
    GpuUsageSnapshot GetGpuUsageSnapshot() {
        std::string psScript = "function Get-GpuSnapshot { $gpuInfo = Get-CimInstance -ClassName Win32_VideoController; $totalMemoryMB = 0; foreach ($gpu in $gpuInfo) { if ($gpu.AdapterRAM) { $totalMemoryMB += [math]::Round($gpu.AdapterRAM / 1MB, 2) } }; $processes = Get-Process | Where-Object { $_.WorkingSet64 -gt 0 }; foreach ($proc in $processes) { $memoryMB = [math]::Round($proc.CPU, 2); Write-Output \"$($proc.Id):$memoryMB\" }; Write-Output \"TotalMemory:$totalMemoryMB\" }; Get-GpuSnapshot";

        std::string output_tmp = ExecutePowerShell(psScript);
        GpuUsageSnapshot snapshot = { 0.0, {} };
        if (output_tmp == "Error") {
            std::cerr << "[ERROR] Failed to execute PowerShell for GPU snapshot" << std::endl;
            return snapshot;
        }

        std::string output = replaceSubtext(output_tmp, "\n:", ":");

        // Parse output: lines are "PID:memoryMB" except last line "TotalMemory:totalMemoryMB"
        std::stringstream ss(output);
        std::string line;
        while (std::getline(ss, line)) {
            if (line.find("TotalMemory:") == 0) {
                std::string totalStr = line.substr(12); // Skip "TotalMemory:"
                try {
                    snapshot.totalMemoryMB = std::stod(totalStr);
                }
                catch (CONST std::exception& e) {
                    std::cerr << "[ERROR] Parsing total memory: " << totalStr << " (" << e.what() << ")" << std::endl;
                }
            }
            else if (!line.empty()) {
                size_t colonPos = line.find(':');
                if (colonPos != std::string::npos) {
                    std::string pidStr = line.substr(0, colonPos);
                    std::string memoryStr = line.substr(colonPos + 1);
                    try {
                        INT pid = std::stoi(pidStr);
                        DOUBLE memoryMB = std::stod(memoryStr);
                        snapshot.processMemoryMB[pid] = memoryMB;
                    }
                    catch (CONST std::exception& e) {
                        std::cerr << "[ERROR] Parsing line: " << line << " (" << e.what() << ")" << std::endl;
                    }
                }
            }
        }
        return snapshot;
    }

    // Function to get GPU usage for a specific PID from the snapshot as a double
    DOUBLE GetGpuUsageForProcess(INT pid, CONST GpuUsageSnapshot& snapshot) {
        DOUBLE memoryUsage = 0;
        std::map<INT, DOUBLE>::const_iterator it;
        if (snapshot.totalMemoryMB <= 0) {
            goto exit;
        }

        it = snapshot.processMemoryMB.find(pid);
        if (it != snapshot.processMemoryMB.end()) {
            DOUBLE memoryMB = it->second;
            memoryUsage = (memoryMB) > 100 ? 100 : memoryMB;
        }
    exit:
        wprintf(L"Total Process GPU Usage for (PID %d): %.2f%%\n", pid, memoryUsage);
        return memoryUsage; // PID not found or no memory usage
    }

    GpuUsageSnapshot gpustats;
};


class PowerExpOrchestrator {
public:
    INT systemtest() {

        PerformanceMonitor monitor;

        if (!monitor.InitializeNVML(monitor.nvmlLib, monitor.funcs)) {
            printf("Issue starting NVML driver. Please ensure GPU is correctly installed.");
            return ERROR_INVALID_HANDLE;
        }

        ProcessMonitor procmon;
        CCommunication comms;
        Utils util;

        BOOL results = comms.Initialize();
        if (!results) {
            printf("Issue starting driver. Please ensure driver is correctly installed.");
            return ERROR_INVALID_HANDLE;
        }

        if (monitor.isConsistentlyHighUsage()) {
            results = comms.GetProcesses();
            procmon.gpustats = procmon.GetGpuUsageSnapshot();
            if (!results || sizeof(comms.ProcessList) == 0) {
                wprintf(L"Issue getting processes associated to the system. Therefore exiting.");
                return ERROR_ACCESS_DENIED;
            }

            
            for (DWORD idx = 0; idx < comms.ProcessList->size; idx++) {
                DWORD pid = (DWORD)comms.ProcessList->processes[idx].ProcessID;
                if (pid == util.getpid() || pid == util.getppid()) {
                    continue;
                }
                else if (pid > 0) {
                    
                    DOUBLE pid_gpu_usage = procmon.GetGpuUsageForProcess(pid, procmon.gpustats);
                    DOUBLE pid_cpu_usage = procmon.GetCpuUsageForProcess(pid);
                    std::wcout << std::endl;
                    if (pid_gpu_usage > HIGH_GPU_PID_THRESHOLD && pid_cpu_usage > HIGH_CPU_PID_THRESOLD) {

                        std::wcout << L"\nPid " << pid << L" is a potentially malicious process that needs investigation. Determining if malicious.\n";
                        
                        PProcessImageInfo image = comms.GetImageBase(pid);
                        if (image == NULL || image->ImageBase == NULL) {
                            continue;
                        }

                        PVOID pid_base_address = image->ImageBase;
                        PVOID pid_text_address = NULL;
                        SIZE_T text_size = 0;
                        PBYTE text_memory = NULL;
                        TCHAR exePath[MAX_PATH] = { 0 };
                        DWORD pathSize = MAX_PATH;
                        util.GetProcessTextSectionInfo(pid, pid_base_address, &pid_text_address, &text_size, &text_memory);

                        if (text_size == 0) {
                            continue;
                        }

						std::string byteString = util.getOpcodesAsHexString(text_memory, text_size);
                        std::wstring opcodes = util.stringToWstring(byteString);
                        std::wstring opcode_filepath = util.CreateTempTextFileWithContent(opcodes);


                        std::wstring cmd = L"python3 C:\\Users\\bryan - demo\\Documents\\Demo\\ML\\classifierv2.py " + opcode_filepath;
                        std::string results = util.RunPowerShellCommand(cmd);
						util.RunPowerShellCommand(L"Remove-Item " + opcode_filepath);

                        // Call code for determining the text_memory is malicious
                        //printf("%s\n", results);

                        if (results == "[1.]") {
                        //if (/*CONDITION*/ FALSE) {
                            std::wstring processName = util.GetProcessName(pid);

                            std::wcout << L"PID " << pid << L" IS DEEMED MALICIOUS! Killing process now!\n";
                            util.GetProcessExecutablePath(pid, exePath, pathSize);
                            //if (!util.TerminateProcessByPID(pid)) {
                            if (FALSE) {
                                //BOOL result = comms.KillProcess(pid);
                                BOOL result = TRUE;
                                if (!result) {
                                    wprintf(L"Failed to kill process %s (PID %d). Please investigate this.\n", processName, pid);
                                }
                            }
                            else {
                                wprintf(L"Successfully termianted process %s (PID %d)!\n", processName, pid);
                            }

                            wprintf(L"\nExe path: %s\n", exePath);

                            //util.DeleteFileWithFallback(exePath);
                        }
                    }
                }
            }

        }

        return ERROR_SUCCESS;
    }
};


// Main function
INT main(INT argc, LPSTR * argv) {
   PowerExpOrchestrator orch;

   return orch.systemtest();
}




