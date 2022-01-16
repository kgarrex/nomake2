
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


	wchar_t *pathEnd = (wchar_t*)((char*)path->buffer + path->length);	
	*pathEnd++ = L'\\';
	path->length++;

	valueName.buffer = L"ServiceName";
	valueName.length = 11 << 1;
	valueName.maximum_length = 0;

	
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

		path->length += nameLength;

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
		
		path->length -= nameLength; 
	}

}

#define WSADESCRIPTION_LEN 256
#define WSASYS_STATUS_LEN 128

typedef struct _WSADATA
{
	// The version of the Windows Sockets specification that the WS2_32.dll expects
	// the caller to use.
	WORD wVersion;

	WORD wHighVersion;
	char szDescription[WSADESCRIPTION_LEN+1];
	char szSystemStatus[WSASYS_STATUS_LEN+1];
	unsigned short iMaxSockets;
	unsigned short iMaxUdpDg;
	char *lpVendorInfo;
} WSADATA;


#define MAX_PROTOCOL_CHAIN 7

typedef struct _WSAPROTOCOLCHAIN {
/* the length of the chain:
	length = 0 means layered protocol
	length = 1 means base protocol
	length > 1 means protocol chain */
	int ChainLen;

/* a list of dwCatalogEntryIds */
	DWORD ChainEntries[MAX_PROTOCOL_CHAIN];
} WSAPROTOCOLCHAIN;


typedef struct _GUID {
	unsigned long Data1;
	unsigned short Data2;
	unsigned short Data3;
	unsigned char Data4[8];
} GUID;



typedef struct _WSAPROTOCOL_INFOW {
	DWORD dwServiceFlags1;
	DWORD dwServiceFlags2;
	DWORD dwServiceFlags3;
	DWORD dwServiceFlags4;
	DWORD dwServiceFlags;
	GUID ProviderId;
	DWORD dwCatalogEntryId;
	WSAPROTOCOLCHAIN ProtocolChain;
	int iVersion;
	int iAddressFamily;
	int iMaxSockAddr;
	int iMinSockAddr;
	int iSocketType;
	int iProtocol;
	int iProtocolMaxOffset;
	int iNetworkByteOrder;
	int iSecurityScheme;
	DWORD dwMessageSize;
	DWORD dwProviderReserved;
	wchar_t szProtocol[255+1];
} WSAPROTOCOL_INFOW, *LPWSAPROTOCOL_INFOW;



typedef struct _IN4ADDR {
	union {
		struct {
			unsigned char s_b1;
			unsigned char s_b2;
			unsigned char s_b3;
			unsigned char s_b4;
		} S_un_b;
		struct {
			unsigned short s_w1;
			unsigned short s_w2;
		} S_un_w;
		unsigned long S_addr;
	} S_un;
} IN4ADDR;

typedef struct _IN6ADDR {
	union {
		unsigned char byte[16];
		unsigned short word[8];
		uint32_t dword[4];
	} u;
} IN6ADDR;



typedef struct _SOCKADDR
{
	unsigned short Family;
	unsigned short Port;
	union {
		//IN4ADDR Ipv4Address;
		uint32_t Ipv4; 
		struct {
			uint32_t sin6_flowinfo;
			IN6ADDR Ipv6Address;
			uint32_t sin6_scope_id;
		} in6;
	};
	char Extra[4];
} SOCKADDR;



typedef struct _WSABUF {
	unsigned long len;
	char *buf;
} WSABUF, *LPWSABUF;


typedef struct _flowspec {
	unsigned long TokenRate;
	unsigned long TokenBucketSize;
	unsigned long PeakBandwidth;
	unsigned long Latency;
	unsigned long DelayVariation;
	unsigned long ServiceType;
	unsigned long MaxSduSize;
	unsigned long MinimumPolicedSize;
} FLOWSPEC, *PFLOWSPEC;


typedef struct _QualityOfService {
	FLOWSPEC SendingFlowspec;
	FLOWSPEC ReceivingFlowspec;
	WSABUF ProviderSpecific;
} QOS;


typedef struct _OVERLAPPED {
	unsigned long Internal;
	unsigned long InternalHigh;
	union {
		struct {
			DWORD Offset;
			DWORD OffsetHigh;
		} DUMMYSTRUCTNAME;
		void *Pointer;
	} DUMMYUNIONNAME;
	void *hEvent;
} OVERLAPPED;





int (__stdcall *WSAStartup)(WORD wVersionRequested, WSADATA *WSAData);


// Creates a socket that is bound to a specific transport-service provider
int (__stdcall *WSASocketW)(
	int AddressFamily, int SocketType, int Protocol,
	WSAPROTOCOL_INFOW *Info, int SocketGroupId, int Flags);


int (__stdcall *WSAConnect)(
	int Socket, const SOCKADDR *SockAddr, int SockAddrLength,
	WSABUF *CallerData, WSABUF *CalleeData, QOS *Sqos, QOS *Gqos);

int (__stdcall *WSAGetLastError)();


int (__stdcall *Connect)(int socket, SOCKADDR *address, int len);


/**
 * Sends data on a connected socket
 */
int (__stdcall *Send)(int socket, char *buf, int len, int flags);


/**
 * Creates a socket that is bound to a specific transport service provider
 */
int (__stdcall *Socket)(int family, int type, int protocol);



/**
 * Sends a single data message to a specific destination
 */
int (__stdcall *SendTo)(int socket, char *buf,
	int len, int flags, SOCKADDR *to, int tolen);


/**
 * Places a socket in a state that it can listen for incoming connections
 */
int (__stdcall *Listen)(int socket, int backlog);


int (__stdcall *Recv)(int socket, char *buf, int len, int flags);


int (__stdcall *Bind)(int socket, SOCKADDR *address, int len);


/**
 * Receives a datagram and store the source address
 */
int (__stdcall *RecvFrom)(int socket, char *buf,
	int len, int flags, SOCKADDR *from, int *fromlen);


typedef (__stdcall *OVERLAPPED_COMPLETION_ROUTINE)(
	DWORD Error, DWORD NumTransferred, OVERLAPPED *Overlapped, DWORD Flags);


int (__stdcall *WSAIoctl)(int socket,
	DWORD IoControlCode,
	void *InBuffer,
	DWORD InBufferLen,
	void *OutBuffer,
	DWORD OutBufferLen,
	DWORD *BytesReturned,
	OVERLAPPED *Overlapped,
	OVERLAPPED_COMPLETION_ROUTINE CompletionRoutine);


int (__stdcall *IoctlSocket)(
	int socket,
	long cmd,
	unsigned long *argp);


/**
 * socket: socket descriptor
 * how: A flag describing what types of operation will no longer be allowed
*/
int (__stdcall *shutdown)(int socket, int how);


void __stdcall LoadWinsock()
{
	unsigned long status;
	void *DllHandle;
	UNICODE_STRING FileName;
	ANSI_STRING ProcName = {0};

	wchar_t *searchPath = L"\\??\\C:\\Windows\\SysWOW64";
	FileName.buffer = L"ws2_32.dll";
	FileName.length = 10 << 1; //34 << 1;
	FileName.maximum_length = FileName.length;

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

	ProcName.length = 10;
	ProcName.buffer = "WSAStartup";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &WSAStartup);

	// Minimum support Windows 8.1
	ProcName.buffer = "WSASocketW";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &WSASocketW);

	ProcName.buffer = "WSAConnect";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &WSAConnect);

	ProcName.length = 15;
	ProcName.buffer = "WSAGetLastError";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &WSAGetLastError);

	ProcName.length = 7;
	ProcName.buffer= "connect";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &Connect);

	ProcName.length = 4;
	ProcName.buffer = "send";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &Send);

	ProcName.buffer = "recv";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &Recv);

	ProcName.buffer = "bind";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &Bind);

	ProcName.length = 6;
	ProcName.buffer = "sendto";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &SendTo);

	ProcName.buffer = "listen";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &Listen);

	ProcName.buffer = "socket";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &Socket);

	ProcName.length = 8;
	ProcName.buffer = "shutdown";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &shutdown);

	ProcName.buffer = "recvfrom";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &RecvFrom);

	ProcName.buffer = "WSAIoctl";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &WSAIoctl);

	ProcName.length = 11;
	ProcName.buffer = "ioctlsocket";
	LdrGetProcedureAddress(DllHandle, &ProcName, 0, &IoctlSocket);
}


/**
 * Invalid argument
 */
#define WSAEINVAL      10022
#define WSAEWOULDBLOCK 10035


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


	// buffer to hold the query/response message
	char *buf;
	
} nm_dns_t;


void dns_add_qname(nm_dns_t *dns, char *host, int len)
{
	char *ptr = dns->buf, *tmp = host;
	char _len;

	for(int i = 0; i < len; ++i)
	{
		if(host[i] != '.') continue;
		_len = &host[i] - tmp;

		tmp[0] = _len;
		//nm_memcpy(&tmp[1], 
	}
}


int dns_add_query_a(nm_dns_t *dns, char *host, int len)
{
	char *ptr = dns->buf;
	
	*((uint16_t*)ptr) =  1337;
	ptr += 2;


	*((uint16_t*)ptr) = 0x0100; // set flags
	ptr += 2;

	*((uint16_t*)ptr) = 0x0100; //++dns->qdcount;
	ptr += 2;

	*((uint16_t*)ptr) = 0;  // ancount
	ptr += 2;

	*((uint16_t*)ptr) = 0;  // nscount
	ptr += 2;
	
	*((uint16_t*)ptr) = 0;  // arcount
	ptr += 2;
	
	// Set the QNAME
	nm_memcpy(ptr, "\x6google" "\x3" "com\x0", 12);
	ptr += 12;

	// Set the QTYPE
	*((uint16_t*)ptr) = 0x0100; //QTYPE_A;
	ptr += 2;

	// Set the QCLASS for IN address
	*((uint16_t*)ptr) = 0x0100;
	ptr += 2;


	short tsts = QTYPE_A;
	char *tstc = (char*)&tsts;
	LogMessageA("NUMBER: 0x%1!x!\n", tstc[1]);

	return ptr - dns->buf;
}


#define INADDR_ANY  0x0

void dns_connect()
{
	SOCKADDR Addr;

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
	int socket = 0;
	socket = Socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(~0 == socket)
	{
		LogMessageA("WSASocketW failed: 0x%1!x!\n", 0); 
		return ;
	}

	
	LogMessageA("SockAddr_In6: %1!u!\n", sizeof(SOCKADDR));


	unsigned long isblocking = 1;
	error = IoctlSocket(socket, FIONBIO, &isblocking);
	if(error)
	{
		LogMessageA("IoctlSocket failed: 0x%1!x!\n", WSAGetLastError());
		return;
	}


	char buf[512];
	int len;
	int fromLen;

	nm_dns_t dns;

	dns.buf = buf;
	dns.qdcount = 0;
	
	Addr.Family = AF_INET;
	Addr.Port = 53;
	Addr.Ipv4 = dns_ipv4[0];

	/*
	error = Connect(socket, &Addr, sizeof(SOCKADDR));
	if(error)
	{
		LogMessageA("WSAConnect failed: %1!u!\n", error);	
		return;
	}
	*/

	len = dns_add_query_a(&dns, 0, 0);
	LogMessageA("Length: %1!u!\n", len);


	
	len = SendTo(socket, buf, len, 0, &Addr, sizeof(Addr));
	if(len == -1)
	{
		LogMessageA("SendTo failed: %1!u!\n", WSAGetLastError());
		return;	
	}


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


	len = RecvFrom(socket, buf, 512, 0, 0, 0);
	if(len == -1)
	{
		LogMessageA("RecvFrom failed: %1!u!\n", WSAGetLastError());	
		//return;
	}

	
	LARGE_INTEGER li = {0, -1000};
	//NtDelayExecution(0, &li);

	unsigned long status;
	status = NtWaitForSingleObject(socket, true, 0);
	if(status > 0)
	{
		LogMessageA("NtWaitForSingleObject failed: 0x%1!x!\n", status);
		return;	
	}


	LogMessageA("buf: %1!.*s!\n", len, buf);



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

	path.length = 75 << 1;
	nm_memcpy(
		buffer,
		L"\\Registry\\Machine\\Software\\Microsoft"
		"\\Windows NT\\CurrentVersion\\NetworkCards",
		path.length
	);

	path.buffer = buffer;
	path.maximum_length = 512;

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

	dns_connect();

	
	return 0;

}


