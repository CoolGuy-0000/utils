#include <Windows.h>
#include <distorm.h>
#include "CGHook.h"

CRITICAL_SECTION g_CritSection;

extern "C" void CGHookRoutine();

static BYTE hook_shell_code_64[] = {
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xFF, 0x20
};

extern "C" void CGUnHook(CGHookObject* obj) {
	DWORD oldProtect;
	EnterCriticalSection(&g_CritSection);

	VirtualProtect(obj->OriginalAddress, obj->BackupSize, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(obj->OriginalAddress, obj->BackupCode, obj->BackupSize);
	VirtualProtect(obj->OriginalAddress, obj->BackupSize, oldProtect, &oldProtect);

	free(obj);

	LeaveCriticalSection(&g_CritSection);
}

extern "C" CGHookObject* CGHook(void* target, CGHookFunc hook_func, DWORD stack_usage, BOOL bSTDCALL) {

	CGHookObject* temp = (CGHookObject*)malloc(sizeof(CGHookObject));

	if (temp) {
		EnterCriticalSection(&g_CritSection);

		DWORD oldProtect;
		VirtualProtect(temp, sizeof(CGHookObject), PAGE_EXECUTE_READWRITE, &oldProtect);

		*(size_t*)((size_t)hook_shell_code_64 + 2) = (size_t)temp;

		temp->HookRoutine = CGHookRoutine;
		temp->HookMain = hook_func;
		temp->OriginalAddress = target;
		temp->BackupSize = 0;
		temp->bHandled = FALSE;
		temp->StackUsage = stack_usage;
		temp->bSTDCALL = bSTDCALL;

		_CodeInfo ci;
		_DInst* inst = (_DInst*)malloc(sizeof(_DInst) * sizeof(hook_shell_code_64));
		UINT instruction_count;

		ci.code = (BYTE*)target;
		ci.codeLen = 0x30;
		ci.codeOffset = 0;
		ci.addrMask = -1;
		ci.dt = Decode64Bits;
		ci.features = DF_USE_ADDR_MASK;

		distorm_decompose64(&ci, inst, sizeof(hook_shell_code_64), &instruction_count);

		for (size_t i = 0; i < instruction_count; i++) {
			if (temp->BackupSize >= sizeof(hook_shell_code_64))break;
			temp->BackupSize += inst[i].size;
		}

		free(inst);

		temp->ReturnAddress = (void*)((size_t)target + temp->BackupSize);

		VirtualProtect(target, temp->BackupSize, PAGE_EXECUTE_READWRITE, &oldProtect);

		memset(temp->BackupCode, 0x90, sizeof(temp->BackupCode)); //nop padding
		memcpy(temp->BackupCode, target, temp->BackupSize);
		
		memcpy(target, hook_shell_code_64, sizeof(hook_shell_code_64));

		int blank = temp->BackupSize - sizeof(hook_shell_code_64);

		if (blank > 0)
			memset((void*)((size_t)target + sizeof(hook_shell_code_64)), 0x90, blank);

		VirtualProtect(target, temp->BackupSize, oldProtect, &oldProtect);
		
		*(size_t*)((size_t)hook_shell_code_64 + 2) = (size_t)temp->ReturnAddress;
		memcpy(temp->ExitCode, hook_shell_code_64, sizeof(hook_shell_code_64));

		LeaveCriticalSection(&g_CritSection);
		return temp;
	}

	return NULL;
}
