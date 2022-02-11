
#include <stdio.h>

typedef struct _jasm {char _[512];} jasm_t;


//typedef struct jasm_node {char _[32];} jasm_node_t;


typedef void *(__fastcall *jasm_alloc_t)(int size);
typedef void (__fastcall *jasm_free_t)(jasm_t *);
typedef void (__fastcall *jasm_recv_t)(jasm_t *);
typedef void (__fastcall *jasm_send_t)(jasm_t *);

typedef struct _jasm_atom
{
	int hash;
	int size;
	void *next;
	void *string;
} jasm_atom_t;


typedef struct _jasm512
{
	void *slots[0x4f];    // 79 slots
	char pad1[28];
	unsigned char *prslt; // the result pointer
	void *focus;
	void *root;           // +0
	int phase;            // +4
	char *string;         // +8
	int bufsize;             // +12
	int lineno;              // +16
	unsigned char stackidx;        // +20
	char pad2[1];
	char flags;
	unsigned char result;
	jasm_alloc_t alloc;   // +24
	jasm_free_t free;     // +28
	void *ns_stack[0x20]; // 32 levels
} _jasm512_t;


//Prime Numbers
//13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59,
//61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109,
//113, 127, 131, 137, 139, 149, 151, 157, 163, 

// 32bit 512: slots=79, levels=32, other=18
// 64bit 512: slots=29, levels=18, other=17





#define JASMCALL __fastcall


/*
 * Initialize the jasm library. Must be called before calling any other jasm procedure
 */
int JASMCALL jasm_init(void *jasm, long size);


/**
 * Set a jasm public variable
 */
void JASMCALL jasm_set_var(void *jasm, int id, void *value);


/**
 * Get a jasm public variable value
 */
void * JASMCALL jasm_get_var(void *jasm, int id);




int __fastcall jasm_load_buf(void *jasm, char *utf8, int length);

void __fastcall jasm_parse(void *jasm);


//char * JASMCALL jasm_:wa


//jasm_set_callbacks(


static char buffer[4096];
jasm_t jasm;

void * __fastcall alloc(int size)
{
	static char *ptr = buffer;
	
	ptr += size;
	return ptr-size;
}


void __fastcall free(void *ptr)
{
}



//jasm_set(jasm_t *, JASM_SET_CALLBACKS, t


//void __fastcall jasm_find_key(jasm_node_t *


int __cdecl main(int argc, char **argv)
{
	printf("Hello World\n");

	_jasm512_t *j;

	jasm_init(&jasm, sizeof(jasm));

	j = (_jasm512_t*)&jasm;

	printf("Phase: 0x%p\n", j->phase);
	printf("Length: 0x%p\n", j->bufsize);
	printf("Stack Index: %u\n", j->stackidx);
	printf("LineNo: %u\n", j->lineno);
	printf("Alloc: 0x%p | 0x%p\n", j->alloc, alloc);
	printf("prslt: 0x%p == 0x%p\n", j->prslt, &j->result);

	
	char *string = "\'$.\'u";
	for(int i = 0; i < 4; i++)
	{
		char c = string[i];
		printf("Char: %c\n", c);
	}

	printf("Long Multiplication: %u\n", (1 << 5));


	return 1;
}


int __stdcall mainCRTStartup()
{
	main(0, 0);
	return 1;
}

