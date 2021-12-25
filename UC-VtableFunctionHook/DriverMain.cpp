#include <ntifs.h>
#include <windef.h>
#include <cstdint>
#include <intrin.h>

#define dbgprint(format, ...) DbgPrintEx(0, 0, format, __VA_ARGS__)
#define RVA(addr, size)       ((uintptr_t)((uintptr_t)(addr) + *(PINT)((uintptr_t)(addr) + ((size) - sizeof(INT))) + (size)))

typedef struct _SYSTEM_MODULE_ENTRY {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG Count;
	SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

extern "C" {
	NTSTATUS NTAPI ZwQuerySystemInformation(_In_ ULONG SystemInformationClass, _Inout_ PVOID SystemInformation, _In_ ULONG SystemInformationLength, _Out_opt_ PULONG ReturnLength);
};

NTSTATUS find_kernel_module(const char* moduleName, uintptr_t* moduleStart, size_t* moduleSize) {
		DWORD size = 0x0;
	ZwQuerySystemInformation((0xB), nullptr, size, reinterpret_cast<PULONG>(&size));

	auto listHeader = ExAllocatePool(NonPagedPool, size);

	if (!listHeader)
		return STATUS_MEMORY_NOT_ALLOCATED;


	if (const auto status = ZwQuerySystemInformation((0xB), listHeader, size, reinterpret_cast<PULONG>(&size))) {
		ExFreePoolWithTag(listHeader, 0);
		return status;
	}

	auto currentModule = reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(listHeader)->Module;

	for (size_t i{}; i < reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(listHeader)->Count; ++i, ++currentModule) {
		const auto currentModuleName = reinterpret_cast<const char*>(currentModule->FullPathName + currentModule->OffsetToFileName);
		if (!strcmp(moduleName, currentModuleName)) {
			*moduleStart = reinterpret_cast<uintptr_t>(currentModule->ImageBase);
			*moduleSize = currentModule->ImageSize;
			ExFreePoolWithTag(listHeader, 0);
			return STATUS_SUCCESS;
		}
	}
	ExFreePoolWithTag(listHeader, 0);
	return STATUS_NOT_FOUND;
}

bool data_compare(const char* pdata, const char* bmask, const char* szmask)
{
	for (; *szmask; ++szmask, ++pdata, ++bmask)
	{
		if (*szmask == ("x")[0] && *pdata != *bmask)
			return false;
	}

	return !*szmask;
}

__forceinline uintptr_t find_pattern(const uintptr_t base, const size_t size, const char* bmask, const char* szmask)
{
	for (size_t i = 0; i < size; ++i)
		if (data_compare(reinterpret_cast<const char*>(base + i), bmask, szmask))
			return base + i;

	return 0;
}
#define index 16 //MAX 25 OR START AT 0 (26 == index[0], 27 == index[1])

typedef struct RequestData {
	uint8_t type;
	PVOID args;
}*pRequestData;

NTSTATUS(__fastcall* OriginalFunction)(ULONG64 arg0, UINT arg1, PVOID arg2, PVOID arg3, ULONG64 arg4);
NTSTATUS __fastcall HookFunction(ULONG64 arg0, UINT arg1, PVOID arg2, PVOID arg3, ULONG64 arg4) {
	dbgprint("HookFunction Call\n");

	if (arg4 == (0xDEAD420)) {
		if (pRequestData data = reinterpret_cast<pRequestData>(arg2)) {
			dbgprint("data->type: %i\n", data->type);
			dbgprint("data->args: 0x%llx\n", *(int*)data->args);
			*(int*)data->args = 0x99;
		}
		return STATUS_SUCCESS;
	}
	return OriginalFunction(arg0, arg1, arg2, arg3, arg4);
}

NTSTATUS InstallHook(const ULONG64 vtable_inst) {
	ULONG64 vtable_addr = RVA(vtable_inst, (7));
	ULONG64* vtable = (ULONG64*)vtable_addr;
	BYTE vindex = (((BYTE)index + (6)) & (0x1F));
	if (MmIsAddressValid((void*)vtable[vindex])) {
		*(ULONG64*)&OriginalFunction = vtable[vindex];

		// disable write protect bit in cr0...
		/* {
			auto cr0 = __readcr0();
			cr0 &= (0xfffffffffffeffff);
			__writecr0(cr0);
			_disable();
		}*/
		dbgprint("vtable[vindex]: 0x%llx\n", vtable[vindex]);
		vtable[vindex] = (ULONG64)HookFunction;

		// enable write protect bit in cr0...
		/* {
			auto cr0 = __readcr0();
			cr0 |= (0x10000);
			_enable();
			__writecr0(cr0);
		}*/
		return STATUS_SUCCESS;
	}
	return STATUS_UNSUCCESSFUL;
}


NTSTATUS DrvEntry(ULONG64 base_address) {
	uintptr_t drvbase;
	size_t drvsize;
	const auto driver_status = find_kernel_module("win32kfull.sys", &drvbase, &drvsize);
	if (NT_SUCCESS(driver_status)) {
		auto vtable_inst = find_pattern(drvbase, drvsize, "\x48\x8D\x05\x00\x00\x00\x00\x41\x83\xC2\x06\x41\x83\xE2\x1F\x4A\x8B\x04\xD0\x4C\x8B\x54\x24\x00\x4C\x89\x54\x24\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x38\xC3", "xxx????xxxxxxxxxxxxxxxx?xxxx?xx????xxxxx");
		if (MmIsAddressValid((void*)vtable_inst) && vtable_inst != 0) {
			return InstallHook(vtable_inst);
		}
		else {
			vtable_inst = find_pattern(drvbase, drvsize, "\x48\x8D\x05\x00\x00\x00\x00\x41\x83\xC1\x06\x41\x83\xE1\x1F\x4A\x8B\x04\xC8\x4C\x8B\x44\x24\x00\x8B\xD7", "xxx????xxxxxxxxxxxxxxxx?xx");
			if (MmIsAddressValid((void*)vtable_inst)) {
				return InstallHook(vtable_inst);
			}
		}
	}
	return STATUS_UNSUCCESSFUL;
}
