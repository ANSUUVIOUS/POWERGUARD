#include "comms.hpp"

CCommunication::CCommunication(){
	GetProcessesDriver = NULL;
	ProcessList = NULL;
}

CCommunication::~CCommunication(){
	Finalize();
}

BOOL CCommunication::Initialize(){
	TCHAR szPath[MAX_PATH] = { 0, };
	TCHAR szCurrentDir[MAX_PATH] = { 0, };

	GetCurrentDirectory(MAX_PATH, szCurrentDir);
	swprintf_s(szPath, MAX_PATH, L"%s\\%s", szCurrentDir, DRIVER_NAME);

	GetProcessesDriver = CreateFileW(DEVICE_LINK, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, NULL);
	if (INVALID_HANDLE_VALUE == GetProcessesDriver)
	{
		wprintf(L"[I/O driver] CreateFile Error : %d\n", GetLastError());
		wprintf(L"Cannot initialize comms to the driver unfortunately.\n");
		return FALSE;
	}
	return TRUE;

}

VOID CCommunication::Finalize(VOID){
	if (GetProcessesDriver){
		CloseHandle(GetProcessesDriver);
		GetProcessesDriver = NULL;
	}

	if (ProcessList != NULL && ProcessList->processes != NULL){
		SIZE_T size = _msize(ProcessList->processes);
		RtlSecureZeroMemory(ProcessList->processes, size);
		free(ProcessList->processes);
		size = _msize(ProcessList);
		RtlSecureZeroMemory(ProcessList, size);
		free(ProcessList);
		ProcessList = NULL;
	}
}

PProcessImageInfo CCommunication::GetImageBase(ULONGLONG pid){
	DWORD dwRetBytes = 0;
	wprintf(L"Getting the Image base for pid %d\n", pid);
	PProcessImageInfo process_image_base = (PProcessImageInfo)calloc(sizeof(ProcessImageInfo), 1);
	if (process_image_base == NULL){
		return NULL;
	}

	BOOL bSuccess = DeviceIoControl(GetProcessesDriver, IOCTL_GET_IMAGE_INFO, &pid, sizeof(ULONGLONG), process_image_base, sizeof(ProcessImageInfo), &dwRetBytes, NULL);
	if (!bSuccess || process_image_base == NULL || process_image_base->ImageBase == NULL || process_image_base->ImageBase == 0)
	{
		RtlSecureZeroMemory(process_image_base, sizeof(ProcessImageInfo));
		free(process_image_base);
		return NULL;
	}
	return process_image_base;

}

BOOL CCommunication::KillProcess(ULONGLONG pid) {
	DWORD dwRetBytes = 0;
	wprintf(L"Going to kill pid %d\n", pid);

	BOOL bSuccess = DeviceIoControl(GetProcessesDriver, IOCTL_KILL_PROCESS, &pid, sizeof(ULONGLONG), NULL, 0, &dwRetBytes, NULL);
	if (!bSuccess){
		return FALSE;
	}
	return TRUE;

}

BOOL CCommunication::GetProcesses(VOID){
	DWORD dwRetBytes = 0;
	wprintf(L"Getting the processes - code: %ld\n", IOCTL_GET_PROCESSES);
	ProcessList = (PIPLIST)calloc(sizeof(IPLIST), 1);
	if (ProcessList == NULL){
		return FALSE;
	}

	BOOL bSuccess = DeviceIoControl(GetProcessesDriver, IOCTL_GET_PROCESSES, NULL, 0, NULL, 0, &dwRetBytes, NULL);
	if (!bSuccess){
		wprintf(L"Could not retrieve the process list size from the system. Please investigate the driver.\n");
		RtlSecureZeroMemory(ProcessList, sizeof(IPLIST));
		free(ProcessList);
		ProcessList = NULL;
		return FALSE;
	}

	DWORD size = dwRetBytes;
	wprintf(L"Process list size is %d %d\n", size, sizeof(PLIST) * size);
	PPLIST entries = new PLIST[size];

	bSuccess = DeviceIoControl(GetProcessesDriver, IOCTL_GET_PROCESSES, NULL, 0, entries, sizeof(PLIST) * size, &dwRetBytes, NULL);
	if (!bSuccess){
		wprintf(L"Could not retrieve the process list from the system. Please investigate the driver.\n");
		RtlSecureZeroMemory(ProcessList, sizeof(IPLIST));
		free(ProcessList);
		ProcessList = NULL;
		return FALSE;
	}

	ProcessList->size = size;
	wprintf(L"Process list size is %d\n", ProcessList->size);
	ProcessList->processes = new PLIST[size];
	RtlCopyMemory(ProcessList->processes, entries, sizeof(PLIST) * ProcessList->size);

	return TRUE;
}