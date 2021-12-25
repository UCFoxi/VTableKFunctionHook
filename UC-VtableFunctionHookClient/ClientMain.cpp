#include <Windows.h>
#include <iostream>
#include <ntstatus.h>
#include <TlHelp32.h>

typedef struct RequestData {
	uint8_t type;
	PVOID args;
}*pRequestData;

NTSTATUS(*NtUserMessageCall)(HWND hWnd, UINT msg, PVOID wParam, PVOID lParam, ULONG_PTR ResultInfo, DWORD dwType, BOOLEAN bAnsi) = nullptr;
HWND ValidHwnd;
UINT MsgKey;

bool InitHandles() {
	LoadLibraryA("user32.dll");
	LoadLibraryA("win32u.dll");
	LoadLibraryA("ntdll.dll");

	*(PVOID*)&NtUserMessageCall = GetProcAddress(
		GetModuleHandleA("win32u.dll"),
		"NtUserMessageCall"
	);
	if (!NtUserMessageCall)
		return false;

	srand(GetTickCount64() * GetCurrentProcessId() * GetCurrentThreadId());
	MsgKey = 0xbd4 + (rand() % 0x1ffff);

	ValidHwnd = FindWindowA("WorkerW", 0);
	if (INVALID_HANDLE_VALUE != ValidHwnd)
		return true;
	return false;
}

template <uint8_t type>
NTSTATUS syscall(PVOID args) {
	RequestData data = {
		type,
		args
	};
	return NtUserMessageCall(ValidHwnd, MsgKey, &data, 0, 0xDEAD420, 16, 0);
}

NTSTATUS main() {
	printf("InitHandles!\n");
	if (InitHandles()) {
		int ret = 0x420;
		const auto status = syscall<3>(&ret);
		printf("ret: 0x%llx | 0x%llx\n", ret, status);
		system("pause");
		return STATUS_SUCCESS;
	}
	return STATUS_UNSUCCESSFUL;
}