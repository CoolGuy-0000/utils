#include <Windows.h>
#include <stdint.h>


static bool LdrSetupRelocations(HMODULE module, uint64_t newBase)
{
    auto dos = (PIMAGE_DOS_HEADER)module;
    auto nt = (PIMAGE_NT_HEADERS64)((uint8_t*)module + dos->e_lfanew);

    uint64_t oldBase = nt->OptionalHeader.ImageBase;
    int64_t delta = (int64_t)(newBase - oldBase);
    if (delta == 0)
        return true;

    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0)
        return true;

    auto relocDir = (PIMAGE_BASE_RELOCATION)((uint8_t*)module +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

    while (relocDir->VirtualAddress && relocDir->SizeOfBlock)
    {
        uint32_t count = (relocDir->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        auto relocData = (WORD*)((uint8_t*)relocDir + sizeof(IMAGE_BASE_RELOCATION));

        for (uint32_t i = 0; i < count; i++)
        {
            WORD typeOffset = relocData[i];
            WORD type = typeOffset >> 12;
            WORD offset = typeOffset & 0xFFF;

            if (type == IMAGE_REL_BASED_DIR64)
            {
                uint64_t* patchAddr = (uint64_t*)((uint8_t*)module + relocDir->VirtualAddress + offset);
                *patchAddr += delta;
            }
            else if (type == IMAGE_REL_BASED_HIGHLOW)
            {
                uint32_t* patchAddr = (uint32_t*)((uint8_t*)module + relocDir->VirtualAddress + offset);
                *patchAddr += (uint32_t)delta;
            }
        }

        relocDir = (PIMAGE_BASE_RELOCATION)((uint8_t*)relocDir + relocDir->SizeOfBlock);
    }

    return true;
}

static bool LdrSetupIAT(HMODULE module)
{
    auto dos = (PIMAGE_DOS_HEADER)module;
    auto nt = (PIMAGE_NT_HEADERS64)((uint8_t*)module + dos->e_lfanew);

    auto importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress == 0)
        return true;

    auto importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((uint8_t*)module + importDir.VirtualAddress);

    while (importDesc->Name)
    {
        LPCSTR dllName = (LPCSTR)((uint8_t*)module + importDesc->Name);
        HMODULE hDLL = LoadLibraryA(dllName);

        if (!hDLL)
            return false;

        auto thunkOrig = (PIMAGE_THUNK_DATA64)((uint8_t*)module + importDesc->OriginalFirstThunk);
        auto thunkIAT = (PIMAGE_THUNK_DATA64)((uint8_t*)module + importDesc->FirstThunk);

        for (; thunkOrig->u1.AddressOfData; ++thunkOrig, ++thunkIAT)
        {
            if (thunkOrig->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
            {
                thunkIAT->u1.Function = (ULONGLONG)GetProcAddress(hDLL,
                    (LPCSTR)(thunkOrig->u1.Ordinal & 0xFFFF));
            }
            else
            {
                auto importByName = (PIMAGE_IMPORT_BY_NAME)((uint8_t*)module + thunkOrig->u1.AddressOfData);
                thunkIAT->u1.Function = (ULONGLONG)GetProcAddress(hDLL, (LPCSTR)importByName->Name);
            }
        }

        importDesc++;
    }

    return true;
}

static void ProtectSections(BYTE* moduleBase)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(moduleBase + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (sec->SizeOfRawData == 0)
            continue;

        DWORD protect = PAGE_NOACCESS;
        BOOL exec = (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        BOOL read = (sec->Characteristics & IMAGE_SCN_MEM_READ) != 0;
        BOOL write = (sec->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

        if (exec) {
            if (read) protect = write ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
            else protect = write ? PAGE_EXECUTE_WRITECOPY : PAGE_EXECUTE;
        }
        else {
            if (read) protect = write ? PAGE_READWRITE : PAGE_READONLY;
            else protect = write ? PAGE_WRITECOPY : PAGE_NOACCESS;
        }

        DWORD oldProt;
        VirtualProtect(moduleBase + sec->VirtualAddress,
            sec->Misc.VirtualSize,
            protect,
            &oldProt);
    }
}


HMODULE MyLoadLibraryA(const char* path){
	HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return NULL;
    }
	HANDLE hFileMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if(!hFileMapping) {
        CloseHandle(hFile);
        return NULL;
	}

    BYTE* fileData = (BYTE*)MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)fileData;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
		UnmapViewOfFile(fileData);
		CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return NULL;
    }

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(fileData + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        UnmapViewOfFile(fileData);
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return NULL;
    }

    BYTE* base = (BYTE*)VirtualAlloc(NULL, nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!base) {
        UnmapViewOfFile(fileData);
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return NULL;
    }

    memcpy(base, fileData, nt->OptionalHeader.SizeOfHeaders);

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        memcpy(base + sec->VirtualAddress,
            fileData + sec->PointerToRawData,
            sec->SizeOfRawData);
    }

    if (!LdrSetupRelocations((HMODULE)base, (UINT64)base)) {
        VirtualFree(base, 0, MEM_RELEASE);
        return NULL;
    }

    if (!LdrSetupIAT((HMODULE)base)) {
        VirtualFree(base, 0, MEM_RELEASE);
        return NULL;
    }

    ProtectSections(base);

    if (nt->OptionalHeader.AddressOfEntryPoint != 0) {
        BOOL(WINAPI * DllMain)(HINSTANCE, DWORD, LPVOID);
        DllMain = (BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID))(base + nt->OptionalHeader.AddressOfEntryPoint);
        DllMain((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);
    }


	UnmapViewOfFile(fileData);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);

    return (HMODULE)base;
}