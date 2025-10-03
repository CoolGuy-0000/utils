#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#define GetFileEntryPoint(nt, sec) (nt->OptionalHeader.AddressOfEntryPoint - sec->VirtualAddress + sec->PointerToRawData)

LPVOID g_filedll = NULL;
HANDLE g_hDLLFile = INVALID_HANDLE_VALUE;
HANDLE g_hDLLFileMap = NULL;

const char* g_szDllFile = NULL;
const char* g_szInitBin = NULL;
char g_szBackupFile[MAX_PATH];

IMAGE_DOS_HEADER* g_pDosHeader = NULL;
IMAGE_NT_HEADERS64* g_pNtHeader = NULL;
IMAGE_SECTION_HEADER* g_pSectionHeaders = NULL;

IMAGE_SECTION_HEADER* g_pCodeSectionHeader = NULL;

BOOL BackupDLL() {
    if (!g_filedll) return FALSE;

	HANDLE hBackupFile = CreateFileA(g_szBackupFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hBackupFile == INVALID_HANDLE_VALUE)return FALSE;

  	DWORD fileSize = GetFileSize(hBackupFile, NULL);
  	ReadFile(hBackupFile, (BYTE*)g_filedll + GetFileEntryPoint(g_pNtHeader, g_pCodeSectionHeader), fileSize, NULL, NULL);
  	CloseHandle(hBackupFile);

    DeleteFileA(g_szBackupFile);
    return TRUE;
}

BOOL CreateBackupFile(DWORD size) {
    if (!g_filedll) return FALSE;

    HANDLE hBackupFile = CreateFileA(g_szBackupFile, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hBackupFile == INVALID_HANDLE_VALUE)return FALSE;

    WriteFile(hBackupFile, (BYTE*)g_filedll + GetFileEntryPoint(g_pNtHeader, g_pCodeSectionHeader), size, NULL, NULL);
    
    CloseHandle(hBackupFile);
    return TRUE;
}

BOOL PatchDLL() {
    if (!g_filedll) return FALSE;

    HANDLE hInitBin = CreateFileA(g_szInitBin, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hInitBin == INVALID_HANDLE_VALUE)return FALSE;

    DWORD fileSize = GetFileSize(hInitBin, NULL) - 0x200;
    if (!CreateBackupFile(fileSize))return FALSE;

  	SetFilePointer(hInitBin, 0x200, NULL, FILE_BEGIN);
    ReadFile(hInitBin, (BYTE*)g_filedll + GetFileEntryPoint(g_pNtHeader, g_pCodeSectionHeader), fileSize, NULL, NULL);

    CloseHandle(hInitBin);
    return TRUE;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: patcher.exe <dll_file> <init_bin or backup option -bk>\n");
        return 1;
    }

    g_szDllFile = argv[1];
    g_szInitBin = argv[2];
    
    g_hDLLFile = CreateFileA(g_szDllFile, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if(g_hDLLFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Failed to load DLL: %s\n", g_szDllFile);
        return -1;
	  }

    g_hDLLFileMap = CreateFileMappingA(g_hDLLFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (g_hDLLFileMap == NULL) {
        fprintf(stderr, "Failed to create file mapping: %s\n", g_szDllFile);
        CloseHandle(g_hDLLFile);
        return -1;
    }

  	g_filedll = MapViewOfFile(g_hDLLFileMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);

    if(g_filedll == NULL) {
        fprintf(stderr, "Failed to map view of file: %s\n", g_szDllFile);
        CloseHandle(g_hDLLFileMap);
        CloseHandle(g_hDLLFile);
        return -1;
	  }

	  // Parse PE headers
	  g_pDosHeader = (IMAGE_DOS_HEADER*)g_filedll;
	  g_pNtHeader = (IMAGE_NT_HEADERS64*)((BYTE*)g_filedll + g_pDosHeader->e_lfanew);
	  g_pSectionHeaders = (IMAGE_SECTION_HEADER*)(g_pNtHeader + 1);

    for(DWORD i = 0; i < g_pNtHeader->FileHeader.NumberOfSections; i++) {
        if (g_pNtHeader->OptionalHeader.BaseOfCode == g_pSectionHeaders[i].VirtualAddress) {
            g_pCodeSectionHeader = &g_pSectionHeaders[i];
            break;
        }
	}

  	snprintf(g_szBackupFile, sizeof(g_szBackupFile), "%s.bak", g_szDllFile);
  
    if(strcmp(g_szInitBin, "-bk") == 0) {
        if(!BackupDLL()) {
            fprintf(stderr, "Failed to backup DLL: %s\n", g_szDllFile);
        } else {
            fprintf(stdout, "Backup successful: %s\n", g_szDllFile);
        }
  	}
    else {
        if (PatchDLL()) fprintf(stdout, "Patch successful: %s\n", g_szDllFile);
        else fprintf(stdout, "Failed to patch DLL: %s\n", g_szDllFile);
    }

	FlushViewOfFile(g_filedll, 0);
	UnmapViewOfFile(g_filedll);
    CloseHandle(g_hDLLFileMap);
    CloseHandle(g_hDLLFile);
    return 0;
}
