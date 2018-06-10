#include "trampoline.h"

void* sendAddr;

__declspec(naked) int __stdcall sendTrampoline(SOCKET s, const char *buf, int len, int flags)
{
	__asm
	{
		push ebp
		mov ebp, esp
		mov eax, [sendAddr]
		add eax, 5
		jmp eax
	}
}

bool hook(void *callback)
{
	HMODULE hMod = GetModuleHandleA("WS2_32.dll");
	sendAddr = (void*)GetProcAddress(hMod, "send");
	DWORD oldProtect, newProtect;
	DWORD offset = (DWORD)callback - (DWORD)sendAddr - 5;
	if (!(VirtualProtect((LPVOID)sendAddr, 5, PAGE_EXECUTE_READWRITE, &oldProtect) &&
		WriteProcessMemory(GetCurrentProcess(), (LPVOID)sendAddr, new byte{ 0xe9 }, 1, NULL) &&
		WriteProcessMemory(GetCurrentProcess(), (LPVOID)((DWORD)sendAddr + 1), &offset, 4, NULL) &&
		VirtualProtect((LPVOID)sendAddr, 5, oldProtect, &newProtect)))
	{
		return false;
	}
	return true;
}
