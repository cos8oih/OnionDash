#pragma comment(lib, "WS2_32.lib")

#ifndef _trampoline_h
#define _trampoline_h

#include <WinSock2.h>

int __stdcall sendTrampoline(SOCKET s, const char *buf, int len, int flags);
bool hook(void *callback);

#endif
