#define WSADESCRIPTION_LEN 256
#define WSASYS_STATUS_LEN 128


typedef void *RIO_RQ;

typedef struct _RIO_BUF
{
	void * BufferId; // RIO_BUFFERID
	unsigned long Offset;
	unsigned long Length;
} RIO_BUF;


typedef struct _RIO_EXTENSION_FUNCTION_TABLE
{
	DWORD cbSize;

	bool (__stdcall *RIOReceive)(void *SocketQueue,
		RIO_BUF *Data, unsigned long DataBufferCount, DWORD Flags, void *RequestContext);

	void *RIOReceiveEx;
	void *RIOSend;
	void *RIOSendEx;
	void *RIOCloseCompletionQueue;
	void *RIOCreateCompletionQueue;
	void *RIOCreateRequestQueue;
	void *RIODequeueCompletion;
	void *RIODeregisterBuffer;
	void *RIONotify;
	void *RIORegisterBuffer;
	void *RIOResizeCompletionQueue;
	void *RIOResizeRequestQueue;
} RIO_EXTENSION_FUNCTION_TABLE;

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
} WSABUF;


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



typedef void (__stdcall *OVERLAPPED_COMPLETION_ROUTINE)(
	DWORD Error, DWORD NumTransferred, OVERLAPPED *Overlapped, DWORD Flags);





int (__stdcall *WSAStartup)(WORD wVersionRequested, WSADATA *WSAData);


// Creates a socket that is bound to a specific transport-service provider
int (__stdcall *WSASocketW)(
	int AddressFamily, int SocketType, int Protocol,
	WSAPROTOCOL_INFOW *Info, int SocketGroupId, int Flags);


int (__stdcall *WSAConnect)(
	int Socket, const SOCKADDR *SockAddr, int SockAddrLength,
	WSABUF *CallerData, WSABUF *CalleeData, QOS *Sqos, QOS *Gqos);

int (__stdcall *WSAGetLastError)();


int (__stdcall *connect)(int socket, SOCKADDR *address, int len);


/**
 * Sends data on a connected socket
 */
int (__stdcall *send)(int socket, char *buf, int len, int flags);


int (__stdcall *WSASend)(
	int Socket,
	WSABUF *Buffers,
	DWORD BufferCount,
	DWORD *NumberOfBytesSent,
	DWORD Flags,
	OVERLAPPED *Ol,
	OVERLAPPED_COMPLETION_ROUTINE CompletionRoutine);


int (__stdcall *WSASendTo)(
	int Socket,
	WSABUF *Buffers,
	DWORD   BufferCount,
	DWORD  *NumBytesSent,
	DWORD   Flags,
	SOCKADDR *ToAddress,
	int     ToLength,
	OVERLAPPED *Overlapped,
	OVERLAPPED_COMPLETION_ROUTINE CompletionRoutine);




int (__stdcall *WSARecv)(
	int Socket,
	WSABUF *Buffers,
	DWORD BufferCount,
	DWORD *NumberOfBytesRecvd,
	DWORD *Flags,
	OVERLAPPED *Overlapped,
	OVERLAPPED_COMPLETION_ROUTINE CompletionRoutine);



int (__stdcall *WSARecvFrom)(
	int       Socket,
	WSABUF   *Buffers,
	DWORD     BufferCount,
	DWORD    *NumBytesRecv,
	DWORD    *Flags,
	SOCKADDR *FromAddress,
	int      *FromLength,
	OVERLAPPED *Overlapped,
	OVERLAPPED_COMPLETION_ROUTINE CompletionRoutine);


/**
 * Receives data from a connected socket or a bound connectionless socket
*/
int (__stdcall *WSARecvEx)(
	int socket,
	char *buf,
	int len,
	int *flags);



/**
 * Creates a socket that is bound to a specific transport service provider
 */
int (__stdcall *socket)(int family, int type, int protocol);



/**
 * Sends a single data message to a specific destination
 */
int (__stdcall *sendto)(int socket, char *buf,
	int len, int flags, SOCKADDR *to, int tolen);


int (__stdcall *WSASendTo)(
	int Socket,
	WSABUF *SendBuffer,
	DWORD BufferCount,
	DWORD *NumberOfBytesSent,
	DWORD Flags,
	SOCKADDR *ToAddress,
	int SizeOfToAddress,
	OVERLAPPED *lpOverlapped,
	OVERLAPPED_COMPLETION_ROUTINE CompletionRoutine);
	


/**
 * Places a socket in a state that it can listen for incoming connections
 */
int (__stdcall *listen)(int socket, int backlog);


int (__stdcall *recv)(int socket, char *buf, int len, int flags);


int (__stdcall *bind)(int socket, SOCKADDR *address, int len);


/**
 * Receives a datagram and store the source address
 */
int (__stdcall *recvfrom)(int socket, char *buf,
	int len, int flags, SOCKADDR *from, int *fromlen);


int (__stdcall *WSAIoctl)(
	int Socket,
	DWORD IoControlCode,
	void *InBuffer,
	DWORD InBufferLen,
	void *OutBuffer,
	DWORD OutBufferLen,
	DWORD *BytesReturned,
	OVERLAPPED *Overlapped,
	OVERLAPPED_COMPLETION_ROUTINE CompletionRoutine);


int (__stdcall *ioctlsocket)(
	int socket,
	long cmd,
	unsigned long *argp);


/**
 * socket: socket descriptor
 * how: A flag describing what types of operation will no longer be allowed
*/
int (__stdcall *shutdown)(int socket, int how);


