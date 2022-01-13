#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <iomanip>
#include <Shlwapi.h>
#pragma comment( lib, "shlwapi.lib")

#define print(format, ...) fprintf (stderr, format, __VA_ARGS__)

DWORD GetProcId(const char* pn)
{
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pE;
        pE.dwSize = sizeof(pE);

        if (Process32First(hSnap, &pE))
        {
            if (!pE.th32ProcessID)
                Process32Next(hSnap, &pE);
            do
            {
                if (!_stricmp(pE.szExeFile, pn))
                {
                    procId = pE.th32ProcessID;
                    print("Process : 0x%lX\n", pE);
                    break;
                }
            } while (Process32Next(hSnap, &pE));
        }
    }
    CloseHandle(hSnap);
    return procId;
}


int InjectDLL(DWORD procID, const char* dllPath)
{
    BOOL WPM = 0;

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, procID);
    if (hProc == INVALID_HANDLE_VALUE)
    {
        return -1;
    }
    void* loc = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!loc)
    {
        CloseHandle(hProc);
        return -1;
    }
    WPM = WriteProcessMemory(hProc, loc, dllPath, strlen(dllPath) + 1, 0);
    if (!WPM)
    {
        CloseHandle(hProc);
        return -1;
    }
    print("DLL Injected Succesfully 0x%lX\n", WPM);
    HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, 0);
    if (!hThread)
    {
        VirtualFree(loc, strlen(dllPath) + 1, MEM_RELEASE);
        CloseHandle(hProc);
        return -1;
    }
    print("Thread Created Succesfully 0x%lX\n", hThread);
    CloseHandle(hProc);
    VirtualFree(loc, strlen(dllPath) + 1, MEM_RELEASE);
    CloseHandle(hThread);
    return 0;
}
int wmain(void)
{
    WIN32_FIND_DATA dllpath;
    HANDLE hFind;
    hFind = FindFirstFile("RtlSetProcessIsCriticalBypass.dll", &dllpath);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        printf("DLL File does NOT exist! please download it from here !(%d)\n", GetLastError());
        ShellExecute(0, 0, "https://github.com/ZeroM3m0ry/BypassRtlSetProcessIsCritical/releases/tag/BypassRtlSetProcessIsCritical", 0, 0, SW_SHOW);
        return  -1;
    }
    std::string pname;
    print("process name (The name of process to inject ) :");
    std::cin >> pname;
    system("cls");
    DWORD procId = 0;
    procId = GetProcId(pname.c_str());
    if (procId == NULL)
    {
        FindClose(hFind);
        return -1;
    }
    else
        InjectDLL(procId, dllpath.cFileName);
    FindClose(hFind);
    system("pause");
    return EXIT_SUCCESS;
}
