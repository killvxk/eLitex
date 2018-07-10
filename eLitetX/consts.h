#pragma once


#define MAXBUF  0xFFFF
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

#define JIMMY_SRC 0
#define JIMMY_DST 1

#define ELTXTOK		_T("elitex.ext.caraconnects.us")
#define DEBUG_MSG	_T("eLitex Service: An ERROR occurred")
