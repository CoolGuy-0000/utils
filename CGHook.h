#pragma once

#include <Windows.h>

typedef struct
{
    void* HookRoutine;        // 0x00
    void* OriginalAddress;    // 0x08
    void* ReturnAddress;      // 0x10
    void* HookMain;           // 0x18
    void* CallerRetAddress;   // 0x20

    DWORD64 rsp;              // 0x28
    DWORD64 rbp;              // 0x30

    DWORD64 rcx;              // 0x38
    DWORD64 rdx;              // 0x40
    DWORD64 r8;               // 0x48
    DWORD64 r9;               // 0x50

    BYTE _align0[8];          // 0x58

    M128A Xmm0;               // 0x60
    M128A Xmm1;               // 0x70
    M128A Xmm2;               // 0x80
    M128A Xmm3;               // 0x90

    BYTE BackupCode[0x10];    // 0xA0
    BYTE ExitCode[0x10];      // 0xB0

    DWORD BackupSize;         // 0xC0
    DWORD bHandled;           // 0xC4

    DWORD64 RetValue;         // 0xC8

    DWORD StackUsage;         // 0xD0
    DWORD bSTDCALL;           // 0xD4

} CGHookObject;

typedef CGHookObject* (__cdecl *CGHookFunc)(CGHookObject* myself, ...);

extern "C" CGHookObject* CGHook(void* target, CGHookFunc hook_func, DWORD stack_usage, BOOL bSTDCALL);
extern "C" void CGUnHook(CGHookObject* obj);