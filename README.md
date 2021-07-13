# dll-injector
 Easy to use Windows DLL injector that you can operate by command line. 
 
 This injector works firstly by opening a PROCESS_ALL_ACCESS handle to the user's desired target process. Then, we get a handle to the kernel32.dll module and find the address of the LoadLibraryA function. Considering kernel32.dll is mapped to the same address in every process' virtual memory, if we find the address of this function in the process we are operating in, the address of this function will be the same in the target process. We then allocate the size of the DLL's path as a string in the virtual memory of the target process, and write the DLL path in the process using WriteProcessMemory. Afterwards, we create a thread in the target process at the address of LoadLibraryA which executes the said function with the DLL path as a parameter.
 
# Compilation:

I compiled this injector using Microsoft's MSVC compiler using the following options:

cl.exe /EHsc /Wall injector.cpp user32.lib comdlg32.lib /link /out:injector.exe

Note that comdlg32.lib is required because I've decided to use GetOpenFileNameA() and its associated struct OPENFILENAMEA.

# Screenshots:

![Screenshot](https://github.com/robertmotr/injector/blob/main/screenshot1.PNG)

Start-up text.

![Screenshot](https://github.com/robertmotr/injector/blob/main/screenshot2.PNG)

Injector prompts you to select a DLL to inject.

![Screenshot](https://github.com/robertmotr/injector/blob/main/screenshot3.PNG)

After selecting a DLL, the injector displays a list of all running processes and their associated PIDs. You will need to select a PID in order to inject into that process.

![Screenshot](https://github.com/robertmotr/injector/blob/main/screenshot4.PNG)

After the injection is finished. In this demonstration, I used a dummy DLL for assault cube that when called displays a message box.


