
#include "eLitexMain.h"
#include "stdafx.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cstring>
#include <atlstr.h>
#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <Ws2tcpip.h>
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <WinDNS.h>

#include <atlbase.h>
#include <atlconv.h>

#include "windivert.h"
#pragma comment(lib, "WinDivert.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "dnsapi.lib")

using namespace std;
using std::ofstream;

HANDLE handleDst;
HANDLE handleSrc;
UINT16 tar_port;
UINT16 tar_port_origin;

bool verbose = false;
bool retrvSwtch = true;

wstring eltxToken(ELTXTOK);
char* tarAddrIn;
char* tarPortIn;

string readParam(const char* in, int opt);
void intercpt(int opt, HANDLE handel);
int retrv();

int init() {

	string truncPolicDst = "";
	string truncPolicSrc = "";

	retrv();
	truncPolicDst = readParam(tarAddrIn, JIMMY_DST) + " and " + readParam(tarPortIn, JIMMY_DST);
	truncPolicSrc = readParam(tarAddrIn, JIMMY_SRC) + " and " + readParam(tarPortIn, JIMMY_SRC);

	handleDst = WinDivertOpen(truncPolicDst.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
	handleSrc = WinDivertOpen(truncPolicSrc.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);

	if (handleDst == INVALID_HANDLE_VALUE)
		exit(1);

	thread asyncDst(intercpt, JIMMY_DST, handleDst);
	thread asyncSrc(intercpt, JIMMY_SRC, handleSrc);

	asyncDst.join();
	asyncSrc.join();

	return 0;
}

string readParam(const char* in, int opt) {

	string dstAddrLang = "ip.DstAddr=";
	string srcAddrLang = "ip.SrcAddr=";
	string dstPortLang = "tcp.DstPort=";
	string srcPortLang = "tcp.SrcPort=";

	string tarPortMatch = "";
	struct sockaddr_in sa;
	char* strdupe = _strdup(in);
	char* delimiter = _strdup("-");

	if (strstr(strdupe, delimiter) != NULL) {
		char* tarPortMatchStr = _strdup(strtok(strdupe, delimiter));
		char* tarPortStr = _strdup(strtok(NULL, delimiter));
		tar_port_origin = htons(atoi(tarPortMatchStr));
		tar_port = htons(atoi(tarPortStr));
		tarPortMatch = tarPortMatchStr;

		if (opt == JIMMY_DST)
			return dstPortLang + tarPortMatch;
		else if (opt == JIMMY_SRC)
			return srcPortLang + string(tarPortStr);
		else
			return "";
	}
	else if (inet_pton(AF_INET, strdupe, &(sa.sin_addr)) == 1) {
		if (opt == JIMMY_DST)
			return dstAddrLang + string(strdupe);
		else if (opt == JIMMY_SRC)
			return srcAddrLang + string(strdupe);
		else
			return "";
	}
	return "";
}

void intercpt(int opt, HANDLE handel) {

	WINDIVERT_ADDRESS windivt_addr;

	char packet[MAXBUF];
	UINT packetLen;
	PWINDIVERT_IPHDR  ip_header;
	PWINDIVERT_TCPHDR tcp_header;
	bool control = true;

	while (control) {

		WinDivertRecv(handel, packet, sizeof(packet), &windivt_addr, &packetLen);
		WinDivertHelperParsePacket(packet, packetLen, &ip_header, NULL, NULL, NULL, &tcp_header, NULL, NULL, NULL);

		if (opt == JIMMY_DST)
			tcp_header->DstPort = tar_port;

		else if (opt == JIMMY_SRC)
			tcp_header->SrcPort = tar_port_origin;

		WinDivertHelperCalcChecksums((PVOID)packet, packetLen, &windivt_addr, 0);
		WinDivertSend(handel, packet, packetLen, &windivt_addr, NULL);

		//control = false;
	}

}

int retrv() {

	DNS_STATUS dnsStatus;
	IN_ADDR ipaddr;
	PDNS_RECORD ppQueryResultsSet, ppQueryResultsSetPort, p;
	PIP4_ARRAY pSrvList = NULL;
	int iRecord = 0;
	bool ready = true;

	pSrvList = (PIP4_ARRAY)LocalAlloc(LPTR, sizeof(IP4_ARRAY));
	if (!pSrvList)
		ready = false;

	FIXED_INFO *pFixedInfo;
	ULONG ulOutBufLen;
	DWORD dwRetVal;

	pFixedInfo = (FIXED_INFO *)MALLOC(sizeof(FIXED_INFO));
	if (pFixedInfo == NULL)
		ready = false;

	ulOutBufLen = sizeof(FIXED_INFO);

	// Make an initial call to GetAdaptersInfo to get
	// the necessary size into the ulOutBufLen variable
	if (GetNetworkParams(pFixedInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		FREE(pFixedInfo);
		pFixedInfo = (FIXED_INFO *)MALLOC(ulOutBufLen);
		if (pFixedInfo == NULL)
			ready = false;
	}

	if (dwRetVal = GetNetworkParams(pFixedInfo, &ulOutBufLen) == NO_ERROR) {

		pSrvList->AddrArray[0] = inet_addr(pFixedInfo->DnsServerList.IpAddress.String); //DNS (ASCII) to IP address
		pSrvList->AddrCount = 1;

		dnsStatus = DnsQuery(
			eltxToken.c_str(),
			DNS_TYPE_A,
			DNS_QUERY_STANDARD, // TCP Queries?
			pSrvList, // Documented as reserved, but can take a PIP4_ARRAY for the DNS server
			&ppQueryResultsSet,
			NULL); // Reserved

		dnsStatus = DnsQuery(
			eltxToken.c_str(),
			DNS_TYPE_TEXT,
			DNS_QUERY_STANDARD, // TCP Queries?
			pSrvList, // Documented as reserved, but can take a PIP4_ARRAY for the DNS server
			&ppQueryResultsSetPort,
			NULL); // Reserved

		if (dnsStatus)
			ready = false;

		if (ready) {
			p = ppQueryResultsSet;
			ipaddr.S_un.S_addr = (p->Data.A.IpAddress);
			tarAddrIn = inet_ntoa(ipaddr);
			LPTSTR *pStrArr;
			pStrArr = ppQueryResultsSetPort->Data.TXT.pStringArray;

			char buffer[MAXBUF];
			wcstombs(buffer, *pStrArr, sizeof(buffer));
			tarPortIn = buffer;

			if (pSrvList) LocalFree(pSrvList);
			DnsRecordListFree(ppQueryResultsSet, DnsFreeRecordList);

			ofstream configWrite("eltx.conf");
			configWrite << tarAddrIn << endl;
			configWrite << tarPortIn << endl;
			configWrite.close();
		}
		else {
			ifstream configRead("eltx.conf");
			string tarAddrIn_ = "";
			string tarPortIn_ = "";
			getline(configRead, tarAddrIn_);
			getline(configRead, tarPortIn_);
			tarAddrIn = _strdup(tarAddrIn_.c_str());
			tarPortIn = _strdup(tarPortIn_.c_str());
			configRead.close();
		}
	}
	return 0;
}