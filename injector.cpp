#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <string>
#include <iomanip>
#include <commdlg.h>

// Error occured while (stuff here):\n GetLastError()
void displayError(std::string typefailure)
{
	std::cout << "Error occurred while " + typefailure + ":\n" << GetLastError() << std::endl;
	system("PAUSE");
}

int main() {

	std::cout << "This DLL injector was made by Robert Motrogeanu for educational purposes. Its contents can be found on my GitHub linked below." << std::endl;
	std::cout << "github.com/robertmotr" << std::endl << std::endl;
	std::cout << "Select a DLL file to inject." << std::endl;

	Sleep(1500);

	// create and enter OPENFILENAMEA structure fields
	OPENFILENAMEA ofnDialog;
	char dllPath[MAX_PATH];
	ZeroMemory(&ofnDialog, sizeof(ofnDialog));
	ofnDialog.lpstrFile = dllPath;
	ofnDialog.lpstrFile[0] = '\0';
	ofnDialog.lpstrFilter = "Dynamic Link Libraries\0*.dll\0";
	ofnDialog.nFilterIndex = 1;
	ofnDialog.lStructSize = sizeof(ofnDialog);
	ofnDialog.lpstrFileTitle = NULL;
	ofnDialog.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_FORCESHOWHIDDEN;
	ofnDialog.lpstrInitialDir = NULL;
	ofnDialog.nMaxFile = MAX_PATH;

	// loop the file dialog menu to ensure user selects a DLL
	while(true) {
		// if user did not select a file (or error occurred, anything wacky)
		if(GetOpenFileNameA(&ofnDialog) == 0) {
			std::cout << "CommDlg error code: 0x" << std::uppercase << std::hex << CommDlgExtendedError() << std::endl;
			system("PAUSE");
			MessageBoxA(NULL, "Please select a DLL.", "Error: Select valid DLL", 0);
		}
		else {
			std::cout << "Path of DLL: " << dllPath << " selected." << std::endl;
			break;
		}
	};

	LPSTR newDllPath = dllPath; // hack to take care of error

	// enumerate over all processes, do this by getting tlh32 snapshot first
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe32;
	if(!hSnap) { 
		displayError("trying to call toolhelp32 snapshot in main()");
		return -1;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if(!Process32First(hSnap, &pe32)) {
		displayError("trying to call Process32First() in main()");
		return -1;
	}
	else {
		std::cout << "Process name: " << std::setw(40) << pe32.szExeFile << std::setw(40) << "Process ID: " << std::setw(40) << pe32.th32ProcessID << std::endl;
	}

	while(Process32Next(hSnap, &pe32)) {
		std::cout << "Process name: " << std::setw(40) << pe32.szExeFile << std::setw(40) << "Process ID: " << std::setw(40) << pe32.th32ProcessID << std::endl;
	}

	DWORD procId = 0;
	std::cout << std::endl;
	std::cout << "Enter a process ID from the list that you'd like to inject into." << std::endl;
	std::cin >> procId;

    HANDLE hTarget = OpenProcess(PROCESS_ALL_ACCESS, NULL, procId);

    // check if handle is valid
    if(hTarget) {

		// kernel32.dll is located at the same address for every process.
		// so, we get a handle to kernel32.dll and then get the address of LoadLibraryA.
		// afterwards, we create a remote thread in the target process using the dll path.

		// get handle to kernel32.dll 
        HMODULE kModuleHandle = GetModuleHandleA("kernel32.dll");

		// check if null
		if(!kModuleHandle) {
			displayError("getting module handle to kernel32.dll");
			return -1;
		}

		// get address of LoadLibraryA
        FARPROC loadLibraryAddress = GetProcAddress(kModuleHandle, "LoadLibraryA");

		if(!loadLibraryAddress) {
			displayError("calling GetProcAddress to get LoadLibraryA function address with kernel32.dll as parameters");
			return -1;
		}

        // allocate size of dll path into process
		// https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
        LPVOID dllAlloc = VirtualAllocEx(hTarget, NULL, strlen(newDllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if(!dllAlloc) {
			displayError("calling VirtualAllocEx in main()");
			return -1;
		}

		// write the dll path into the new allocated memory in the process
		if(!WriteProcessMemory(hTarget, dllAlloc, newDllPath, strlen(newDllPath) + 1, NULL)) {
			displayError("WPM dll path in main()");
			return -1;
		}

		// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
		HANDLE remoteThread = CreateRemoteThread(hTarget, NULL, NULL, (LPTHREAD_START_ROUTINE) loadLibraryAddress, dllAlloc, NULL, 0);

        if(!remoteThread) {
			displayError("creating remote thread in target process");
			return -1;
		}

		// wait until thread starts
        WaitForSingleObject(remoteThread, INFINITE);

		// now that the DLL is injected, we can free the memory we allocated for the dll path
        VirtualFreeEx(hTarget, dllAlloc, strlen(newDllPath) + 1, MEM_RELEASE);
        CloseHandle(remoteThread);
        CloseHandle(hTarget);
		CloseHandle(hSnap);
    }
	else {
		displayError("getting handle to target process");
		return -1;
	}

	std::cout << "Injection finished!" << std::endl << std::endl;
	system("PAUSE");
    return 0;
}