
#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>

#include "consts.h"

#include <Ws2tcpip.h>
#include <winsock2.h>
#include <windows.h> 
#include <iphlpapi.h>
#include <WinDNS.h>

#include <atlbase.h>
#include <atlconv.h>

#include "windivert.h"

#ifdef _WIN64
#pragma comment(lib, "WinDivert.lib")
#else
#pragma comment(lib, "WinDivert32.lib")
#endif

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "dnsapi.lib")
