
#include "net.h"

void __stdcall nm_network_cards(void *NetworkCardsKeyHandle, UNICODE_STRING *path)
{
	unsigned long status;

	KEY_CACHED_INFORMATION cachedInfo;
	unsigned long returnLength;

	char infoBuffer[512];
	KEY_BASIC_INFORMATION *basicInfo;
	KEY_VALUE_PARTIAL_INFORMATION *valueInfo;

	OBJECT_ATTRIBUTES oa = {0};
	UNICODE_STRING valueName = {0};

	void *NetworkCardKeyHandle;
	ACCESS_MASK access;

	access.mask = KEY_QUERY_VALUE;

	oa.SizeOf = sizeof(oa);
	oa.ObjectName = path;

	unsigned long nameLength;

	char nicGUID[64];

	
// Get the number of subkeys
	status = NtQueryKey(
		NetworkCardsKeyHandle,
		KeyCachedInformation,
		&cachedInfo,
		sizeof(KEY_CACHED_INFORMATION),
		&returnLength);
	if(status > 0)
	{
		LogMessageA("NtQueryKey failed: 0x%1!x!\n", status);
		return;
	}


	wchar_t *pathEnd = (wchar_t*)((char*)path->Buffer + path->Length);	
	*pathEnd++ = L'\\';
	path->Length++;

	valueName.Buffer = L"ServiceName";
	valueName.Length = 11 << 1;
	valueName.MaximumLength = 0;

	
// enumerate each subkey and get the ServiceName value which is a GUID
// representing the network interface card device name
	for(int i = 0; i < cachedInfo.SubKeys; ++i)
	{
		basicInfo = (KEY_BASIC_INFORMATION*)infoBuffer;
		status = NtEnumerateKey(
			NetworkCardsKeyHandle,
			i,
			KeyBasicInformation, 
			basicInfo,
			512,
			&returnLength);
		if(status > 0)
		{
			LogMessageA("NtEnumerateKey failed: 0x%1!x!\n", status);
			return;
		}

		nameLength = basicInfo->NameLength << 1;

		nm_memcpy(pathEnd, basicInfo->Name, nameLength);

		path->Length += nameLength;

		status = NtOpenKey(&NetworkCardKeyHandle, access, &oa);
		if(status > 0)
		{
			LogMessageA("NtOpenKey failed: 0x%1!x!\n", status);
			return;
		}

		// do something with network card key handle here
		valueInfo = (KEY_VALUE_PARTIAL_INFORMATION*)infoBuffer;
		status = NtQueryValueKey(
			NetworkCardKeyHandle,
			&valueName,
			KeyValuePartialInformation,
			valueInfo,
			512,
			&returnLength);
		if(status > 0)
		{
			LogMessageA("NtQueryValueKey failed: 0x%1!x!\n", status);	
			return;
		}

		LogMessageW(L"Value: %1!.*s!\n", valueInfo->DataLength, valueInfo->Data);
			

		// Open a handle to the NIC device


		NtClose(NetworkCardKeyHandle);
		
		path->Length -= nameLength; 
	}

}


void __stdcall LoadWinsock()
{
	unsigned long status;
	void *DllHandle;
	UNICODE_STRING FileName;
	ANSI_STRING ProcName = {0};

	wchar_t *searchPath = L"\\??\\C:\\Windows\\SysWOW64";
	FileName.Buffer = L"ws2_32.dll";
	FileName.Length = 10 << 1; //34 << 1;
	FileName.MaximumLength = FileName.Length;

	status = LdrGetDllHandle(searchPath, 0, &FileName, &DllHandle);
	if(status > 0)
	{
		//LogMessageA("LdrGetDllHandle failed: 0x%1!x!\n", status);	
		if(status != STATUS_DLL_NOT_FOUND)
		{
			// Error, do something;
		}

		status = LdrLoadDll(searchPath, 0, &FileName, &DllHandle);
		if(status > 0)
		{
			LogMessageA("LdrLoadDll failed: 0x%1!x!\n", status);	
			//return;
		}

	}
	else
	{
		return;	
	}

	LogMessageA("DllHandle: 0x%1!p!\n", DllHandle);

	ProcName.Length = 10;
	ProcName.Buffer = "WSAStartup";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &WSAStartup);

	// Minimum support Windows 8.1
	ProcName.Buffer = "WSASocketW";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &WSASocketW);

	ProcName.Buffer = "WSAConnect";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &WSAConnect);

	ProcName.Length = 15;
	ProcName.Buffer = "WSAGetLastError";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &WSAGetLastError);

	ProcName.Length = 7;
	ProcName.Buffer= "connect";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &connect);

	ProcName.Buffer = "WSASend";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &WSASend);

	ProcName.Buffer = "WSARecv";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &WSARecv);

	ProcName.Length = 4;
	ProcName.Buffer = "send";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &send);

	ProcName.Buffer = "recv";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &recv);

	ProcName.Buffer = "bind";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &bind);

	ProcName.Length = 9;
	ProcName.Buffer = "WSASendTo";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &WSASendTo);

	ProcName.Buffer = "WSARecvEx";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &WSARecvEx);

	ProcName.Length = 6;
	ProcName.Buffer = "sendto";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &sendto);

	ProcName.Buffer = "listen";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &listen);

	ProcName.Buffer = "socket";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &socket);

	ProcName.Length = 8;
	ProcName.Buffer = "shutdown";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &shutdown);

	ProcName.Buffer = "recvfrom";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &recvfrom);

	ProcName.Buffer = "WSAIoctl";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &WSAIoctl);

	ProcName.Length = 11;
	ProcName.Buffer = "ioctlsocket";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &ioctlsocket);

	ProcName.Buffer = "WSARecvFrom";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &WSARecvFrom);
}


/**
 * Invalid argument
 */
#define WSAEINVAL      10022
#define WSAEWOULDBLOCK 10035
#define WSAETIMEDOUT   10060


#define AF_INET  2
#define AF_INET6 23
#define AF_IRDA  26
#define AF_BTH   32

#define SOCK_STREAM 1
#define SOCK_DGRAM  2
#define SOCK_RAW    3

#define IPPROTO_ICMP    1
#define IPPROTO_IGMP    2
#define BTHPROTO_RFCOMM 3
#define IPPROTO_TCP     6
#define IPPROTO_UDP    17
#define IPPROTO_ICMPV6 58


// nm_dns_t
/*
0x08080808
0x04040808
0x01206048, 0x60480000, 0x00000000, 0x00008888 
0x01206048, 0x60480000, 0x00000000, 0x00008844
*/

uint32_t dns_ipv4[] = {
	// Google Ipv4
	0x08080808, 0x04040808,
};

uint32_t dns_ipv6[] = {
	// Google Ipv6
	0x01206048, 0x60480000, 0x00000000, 0x00008888,
	0x01206048, 0x60480000, 0x00000000, 0x00008844,
};


// getsockopt SO_MAX_MSG_SIZE

#define IOCPARAM_MASK  0x7f
#define IOC_OUT        0x40000000
#define IOC_IN         0x80000000
#define IOC_INOUT      0xC0000000

#define _IOW(x,y,t)  (IOC_IN|(((long)sizeof(t)&IOCPARAM_MASK)<<16)|((x)<<8)|(y))


#define SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER 0xc8000024 // (IOC_INOUT| 0x08000000 | 36)

#define FIONBIO     0x8004667e  // _IOW('f', 125, long)
#define FIONASYNC   0x8004667d  // _IOW('f', 126, long)


enum qtype
{
	QTYPE_A         = 0x0100, // Ipv4 host address
	NS        = 0x0200,
	CNAME     = 0x0500, // Canonical Name
	SOA       = 0x0600,
	PTR       = 0x0c00,
	MX        = 0x0f00,
	TXT       = 0x1000,
	AAAA      = 0x1c00, // Ipv6 host address
	DNAME     = 0x2700,
};

typedef struct nm_dns
{
	// an unsigned 16 bit integer specifying the number of question entries
	short qdcount;


	// buffer to hold the query message
	WSABUF sendbuf;

	// buffer to hold the response message
	WSABUF recvbuf;

} nm_dns_t;



uint16_t __stdcall bswap16(uint16_t n16);


uint32_t __stdcall bswap32(uint32_t n32);


uint64_t __stdcall bswap64(uint64_t n64);




void dns_add_qname(nm_dns_t *dns, char *host, int len)
{
	char *ptr = dns->sendbuf.buf, *tmp = host;
	char _len;
	int i;

	for(i = 0; i < len; ++i)
	{
		if(host[i] != '.') continue;
		*ptr = &host[i] - tmp;

		nm_memcpy(ptr+1, tmp, *ptr);
		ptr += *ptr+1;
		tmp = &host[i+1];
	}

	*ptr = 0;
}


int dns_add_query_a(nm_dns_t *dns, char *host, int len)
{
	uint16_t id = 1337;
	char *ptr = dns->sendbuf.buf;
	
	*((uint32_t*)ptr) = (id << 16) | 0x0100;
	ptr += 4;
	/*
	*((uint16_t*)ptr) = 1337;
	ptr += 2;

	*((uint16_t*)ptr) = 0x0100; // set flags
	ptr += 2;
	*/



	*((uint32_t*)ptr) = (uint32_t)(bswap16(++dns->qdcount) << 16);
	ptr += 4;
	/*
	*((uint16_t*)ptr) = bswap16(++dns->qdcount);
	ptr += 2;

	*((uint16_t*)ptr) = 0;  // ancount
	ptr += 2;
	*/


	*((uint32_t*)ptr) = 0x0;
	ptr += 4;
	/*
	*((uint16_t*)ptr) = 0;  // nscount
	ptr += 2;
	
	*((uint16_t*)ptr) = 0;  // arcount
	ptr += 2;
	*/

	
	// Set the QNAME
	nm_memcpy(ptr, "\x6""google""\x3""com""\x0", 12);
	ptr += 12;


	*((uint32_t*)ptr) = (0x0100 << 16) | 0x0100;
	 ptr += 4;
	// Set the QTYPE
	/*
	*((uint16_t*)ptr) = 0x0100; //QTYPE_A;
	ptr += 2;

	// Set the QCLASS for IN address
	*((uint16_t*)ptr) = 0x0100;
	ptr += 2;
	*/

	//LogMessageA("QDCOUNT: 0x%1!p!\n", bswap16(dns->qdcount));
	//LogMessageA("QDCOUNT: 0x%1!p!\n", bswap16(0x0402));


	return ptr - dns->sendbuf.buf;
}



int dns_add_query_aaaa(nm_dns_t *dns, char *host, int len)
{
	return 0;
}


int dns_add_query_cname(nm_dns_t *dns, char *host, int len)
{
	return 0;
}


int dns_add_query_mx(nm_dns_t *dns, char *host, int len)
{
	return 0;
}


void __stdcall SendCompletionRoutine(
	DWORD Error,
	DWORD NumTransferred,
	OVERLAPPED *Overlapped,	
	DWORD Flags)
{

	LogMessageA("SendCompletionRoutine: %1!u!\n", NumTransferred);
}


void LoadExtensions(int Socket)
{

	/*
	WSAIoctl(
		Socket,
	*/
		

	/*
	WSAIoctl(
		Socket,
		SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER,
		0,
		sizeof(GUID),
		RIOTable,
		sizeof(RIOTable),
		0, 0, 0);
	*/
		

}



#define INADDR_ANY  0x0
#define DNS_PORT    0x3500

void dns_connect(nm_dns_t *dns)
{
	SOCKADDR Addr = {0};

	LoadWinsock();

	WSADATA WSAData;
	int error;

	error = WSAStartup(0x0202, &WSAData);
	if(error)
	{
		LogMessageA("WSAStartup failed: %1!u!\n", error);	
		return ;
	}

	// Create an Ipv4 UDP socket
	int s = 0;
	s = WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0, 0, 0);
	if(~0 == s)
	{
		LogMessageA("WSASocketW failed: %1!u!\n", WSAGetLastError()); 
		return ;
	}

	LogMessageA("Socket: 0x%1!p!\n", s);


	/*
	unsigned long isblocking = 0;
	error = ioctlsocket(s, FIONBIO, &isblocking);
	if(error)
	{
		LogMessageA("ioctlsocket failed: 0x%1!x!\n", WSAGetLastError());
		return;
	}
	*/




	int len;
	int fromLen;


	Addr.Family = AF_INET;
	Addr.Port = DNS_PORT;
	Addr.Ipv4 = dns_ipv4[0];


	/*
	LogMessageA("Connecting...\n");
	error = WSAConnect(s, &Addr, sizeof(Addr), 0, 0, 0, 0);
	if(error)
	{
		LogMessageA("WSAConnect failed: %1!u!\n", WSAGetLastError());	
		return;
	}
	*/

	len = dns_add_query_a(dns, 0, 0);


	
	DWORD numBytes = len;
	int fromlen = sizeof(Addr);
	DWORD flags = 0; // MSG_PARTIAL if query count is greater than 1
	//len = WSASend(s, &dns->sendbuf, 1, &numBytes, flags, 0, 0);
	len = WSASendTo(s, &dns->sendbuf, 1, &numBytes, flags, &Addr, fromlen, 0, SendCompletionRoutine);
	if(len == -1)
	{
		LogMessageA("WSASendTo failed: %1!u!\n", WSAGetLastError());
		return;	
	}

	LogMessageA("Data Sent: %1!u!\n", numBytes);

	LogMessageA("Receiving...\n");


	/*
	Addr.Port = 0;
	Addr.Ipv4 = INADDR_ANY;
	error = Bind(socket, &Addr, sizeof(Addr));
	if(error)
	{
		LogMessageA("Bind failed: %1!u!\n", WSAGetLastError());	
		return;
	}
	*/


	//len = WSARecv(s, &dns->recvbuf, 1, &numBytes, &flags, 0, 0);
	/*
	len = WSARecvFrom(s, &dns->recvbuf, 1, &numBytes, &flags, &Addr, &fromlen, 0, 0);
	if(len == -1)
	{
		LogMessageA("RecvFrom failed: %1!u!\n", WSAGetLastError());	
		return;
	}
	*/

	LogMessageA("recvfrom len: %1!u! | %2!u!\n", len, fromlen);

	
	LARGE_INTEGER li = {0, -1000};
	//NtDelayExecution(0, &li);

	unsigned long status;
	status = NtWaitForSingleObject(socket, true, 0);
	if(status > 0)
	{
		LogMessageA("NtWaitForSingleObject(dns_connect) failed: 0x%1!x!\n", status);
		return;	
	}


	LogMessageA("buf: %1!.*s!\n", 28, dns->recvbuf.buf);

	//shutdown(socket, 0x1); // shutdown send operations operations
	
	return ;
}


// nm_net_t
void  * nm_net_init(void *obj)
{
	void * KeyHandle = 0;
	unsigned long status;
	ACCESS_MASK access;
	OBJECT_ATTRIBUTES oa = {0};
	UNICODE_STRING path;

	access.mask = KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS;
	oa.SizeOf = sizeof(OBJECT_ATTRIBUTES);
	oa.ObjectName = &path;


	wchar_t buffer[512];

	path.Length = 75 << 1;
	nm_memcpy(
		buffer,
		L"\\Registry\\Machine\\Software\\Microsoft"
		"\\Windows NT\\CurrentVersion\\NetworkCards",
		path.Length
	);

	path.Buffer = buffer;
	path.MaximumLength = 512;

	status = NtOpenKey(&KeyHandle, access, &oa);  
	if(status > 0)
	{
		LogMessageA("NtOpenKey failed: 0x%1!x!\n", status);
		return 0;
	}

	LogMessageA("KeyHandle: 0x%1!x!\n", KeyHandle);

	
	nm_network_cards(KeyHandle, &path);


	LoadWinsock();

	WSADATA WSAData;
	int error;

	error = WSAStartup(0x0202, &WSAData);
	if(error)
	{
		LogMessageA("WSAStartup failed: %1!u!\n", error);	
		return 0;
	}

	// Create an Ipv4 TCP socket
	int socket = 0;
	socket = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0);
	if(~0 == socket)
	{
		LogMessageA("WSASocketW failed: 0x%1!x!\n", 0); 
		return 0;
	}


	char buf[512];
	nm_dns_t dns;


	dns.sendbuf.buf = buf;
	dns.sendbuf.len = 512;
	dns.qdcount = 0;


	dns.recvbuf.buf = buf;
	dns.recvbuf.len = 512;


	dns_connect(&dns);

	
	return 0;

}


