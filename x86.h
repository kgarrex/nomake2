
typedef signed char int8_t;
typedef signed short int16_t;
typedef signed int int32_t;
typedef signed long long int64_t;

typedef unsigned char bool;
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;


typedef char byte;
typedef short word;
typedef int dword;
typedef long long  qword;


// A 128 bit unsigned SIMD value
typedef struct uxmmword
{
	union
	{
		byte   b[0x10];
		word   w[0x08];
		dword dw[0x04];
		qword qw[0x02];
	};
} uxmmword_t;


// A 128 bit signed SIMD value
typedef struct sxmmword
{
	union
	{
		byte   b[0x10];
		word   w[0x08];
		dword dw[0x04];
		qword qw[0x02];
	};
} sxmmword_t;



// An 256 bit unsigned SIMD value
typedef struct uymmword
{
	union
	{
		byte   b[0x20];
		word   w[0x10];
		dword dw[0x08];
		qword qw[0x04];
	};
} uymmword_t;


// An 256 bit signed SIMD value
typedef struct symmword
{
	union
	{
		byte   b[0x20];
		word   w[0x10];
		dword dw[0x08];
		qword qw[0x04];
	};
} symmword_t;



// An 512 bit unsigned SIMD value
typedef struct uzmmword
{
	union
	{
		byte   b[0x40];
		word   w[0x20];
		dword dw[0x10];
		qword qw[0x08];
	};
} uzmmword_t;



// An 512 bit signed SIMD value
typedef struct szmmword
{
	union
	{
		byte   b[0x40];
		word   w[0x20];
		dword dw[0x10];
		qword qw[0x08];
	};
} szmmword_t;




