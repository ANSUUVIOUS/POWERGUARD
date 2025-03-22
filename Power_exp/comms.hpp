#pragma once

#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#define NULL nullptr
#define DRIVER_NAME L"ProcInspectDriver"
#define  DEVICE_LINK L"\\\\.\\ProcessInvestigator"
#define IOCTL_GET_PROCESSES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS) 
#define IOCTL_GET_IMAGE_INFO  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KILL_PROCESS   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS) 


typedef struct _DRIVER_LIST_ENTRY {
	uintptr_t modBaseAddress;
	ULONG modSize;
	WCHAR FilePath[MAX_PATH];
	WCHAR ServiceName[MAX_PATH];
	uintptr_t DriverObject;
	BOOLEAN isHidden;
	LIST_ENTRY Entry; // list chain
} DRIVER_LIST_ENTRY, * PDRIVER_LIST_ENTRY;

typedef struct _DETECT_LIST_ENTRY {
	LIST_ENTRY Entry; // list chain
	UINT PatternNo;
	uintptr_t BaseAddress;
	UINT Offset;
} DETECT_LIST_ENTRY, * PDETECT_LIST_ENTRY;

typedef struct _PLIST {
	ULONGLONG ProcessID;
} PLIST, * PPLIST;

typedef struct ITER_PLIST {
	PPLIST processes;
	DWORD size;
} IPLIST, * PIPLIST;

// Define a structure to hold image information
typedef struct _ProcessImageInfo {
	PVOID ImageBase;
	UCHAR ImageName[1024];
	//SIZE_T ImageSize;
} ProcessImageInfo, * PProcessImageInfo;

class CCommunication
{
public:
	CCommunication();
	~CCommunication();
	HANDLE GetProcessesDriver;
	PIPLIST ProcessList;
	BOOL GetProcesses();
	BOOL KillProcess(ULONGLONG);
	PProcessImageInfo GetImageBase(ULONGLONG);
	BOOL Initialize();
	void Finalize();
};
