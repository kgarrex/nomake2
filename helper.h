
typedef signed char int8_t;
typedef signed short int16_t;
typedef signed int int32_t;
typedef signed long long int64_t;

typedef unsigned char bool;
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

typedef unsigned short wchar_t;
#if defined(_WIN64)
typedef unsigned __int64 size_t;
#else
typedef unsigned long size_t;
#endif

typedef float real32_t;
typedef double real64_t;


typedef char CHAR, *PCHAR, BYTE;
typedef __int64 QWORD, DWORD64, *PDWORD64;
typedef short WORD;
typedef unsigned int DWORD, UINT;





#define false 0
#define true  1

#define NULL 0
#define nullptr 0




size_t str8to16(wchar_t *dest, char *src, size_t length);


size_t str16to8(char *dest, wchar_t *src, size_t length);

