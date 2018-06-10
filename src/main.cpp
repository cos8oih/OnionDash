#include "socks5.h"
#include <windows.h>
#include <string>

int __stdcall sendHook(SOCKET s, const char *buf, int len, int flags)
{
	closesocket(s);
	socks5_connect_with_TOR(&s, 9050);
	socks5_clientsgreet(s);
	socks5_request(s, "boomlings.com", 80);
	return sendTrampoline(s, buf, len, flags);
}

void main()
{
	hook(sendHook);
	return;
}

BOOL WINAPI DllMain(HINSTANCE hInstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		CreateThread(0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(&main), 0, 0, 0);
		return TRUE;
	}
	return FALSE;
}
