#include <iostream>
#include <string>
#include <algorithm>

#include <Windows.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <tchar.h>
#include <stdio.h>

using namespace std;

#if _WIN32 || _WIN64
#if _WIN64
#define ENV64BIT
#else
#define ENV32BIT
#endif
#endif

typedef NTSTATUS (*_RtlMultiByteToUnicodeN)(
	_Out_           PWCH   UnicodeString,
	_In_            ULONG  MaxBytesInUnicodeString,
	_Out_opt_       PULONG BytesInUnicodeString,
	_In_      const CHAR   *MultiByteString,
	_In_            ULONG  BytesInMultiByteString
);

typedef HMODULE (WINAPI *_LoadLibrary)(
	_In_ LPCTSTR lpFileName
);

_RtlMultiByteToUnicodeN RtlMultiByteToUnicodeN;
_LoadLibrary MyLoadLibrary;

void ErrMsg(string msg) {
	cout << "[Error] " << msg << endl;
}

DWORD GetPid(string target) {
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 entry;

	BOOL result = Process32First(hSnap, &entry);
	string exe;
	do {
		exe = entry.szExeFile;

		transform(target.begin(), target.end(), target.begin(), ::tolower);
		transform(exe.begin(), exe.end(), exe.begin(), ::tolower);

		if (exe == target) {
			return entry.th32ProcessID;
		}
		result = Process32Next(hSnap, &entry);
	} while (result);

	CloseHandle(hSnap);

	return (DWORD)-1;
}

void TargetSuspend(DWORD target) {
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	THREADENTRY32 entry;

	entry.dwSize = sizeof(THREADENTRY32);
	BOOL result = Thread32First(hSnap, &entry);
	DWORD tid, own;
	do {
		tid = entry.th32ThreadID;
		own = entry.th32OwnerProcessID;

		if (own == target) {
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
			if (hThread == INVALID_HANDLE_VALUE) {
				ErrMsg("OpenThread");
				CloseHandle(hSnap);
				return;
			}

			if (SuspendThread(hThread) < 0) {
				ErrMsg("SuspendThread");
				CloseHandle(hSnap);
				return;
			}
			CloseHandle(hThread);
		}
		result = Thread32Next(hSnap, &entry);
	} while (result);

	CloseHandle(hSnap);
}

bool Init() {
	RtlMultiByteToUnicodeN = (_RtlMultiByteToUnicodeN)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlMultiByteToUnicodeN");
	if (RtlMultiByteToUnicodeN == NULL)
		return false;
	
	MyLoadLibrary = (_LoadLibrary)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	if (MyLoadLibrary == NULL)
		return false;

	return true;
}

int main() {
	if (Init() == false)
		ErrMsg("Init");

	bool is_open = false;
	while (1) {
		DWORD pid = GetPid("kakaotalk.exe");
		HANDLE hProc;
		cout << pid << endl;

		hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (hProc == INVALID_HANDLE_VALUE) {
			ErrMsg("OpenProcess");
			continue;
		}

		is_open = true;

		if (is_open == true) {
			string dll;
#ifdef ENV32BIT
			dll = "C:\\Hooka.dll";
#else
			dll = "C:\\Users\\KuroNeko\\Desktop\\Hooka\\x64\\Debug\\Hooka.dll";
#endif
			void *mem = VirtualAllocEx(hProc, NULL, dll.length() + 1, MEM_COMMIT, PAGE_READWRITE);
			if (mem == NULL) {
				ErrMsg("VirtualAllocEx");
				continue;
			}

			SIZE_T written;
			BOOL result = WriteProcessMemory(hProc, mem, dll.c_str(), dll.length(), &written);
			if (result == FALSE) {
				ErrMsg("WriteProcessMemory");
				continue;
			}

			HANDLE hRemote = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)MyLoadLibrary, mem, 0, NULL);
			if (hRemote == INVALID_HANDLE_VALUE) {
				ErrMsg("CreateRemoteThread");
				continue;
			}

			CloseHandle(hRemote);
			is_open = false;
		}
		CloseHandle(hProc);
	}
	getchar();

	return 0;
}