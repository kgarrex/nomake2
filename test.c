
#include <stdio.h>

typedef struct jasm{char _[512];} jasm_t;

typedef struct jasm_node {char _[32];} jasm_node_t;


typedef void *(__fastcall *jasm_alloc_t)(int size);
typedef void (__fastcall *jasm_free_t)(void *);


typedef struct _jasm
{
	void *root;         // +0
	int phase;          // +4
	char *string;       // +8
	int length;         // +12
	int lineno;         // +16
	char stackidx;      // +20
	jasm_alloc_t alloc; // +24
	jasm_free_t free;   // +28
	void *ns_stack[80]; // +32
} _jasm_t;


int __fastcall jasm_init(
	jasm_t *jasm,
	jasm_alloc_t alloc,
	jasm_free_t free
);


int __fastcall jasm_load_buf(jasm_t *jasm, char *utf8, int length);

void __fastcall jasm_parse(jasm_t *jasm);

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

jasm_set(jasm_t *, JASM_SET_BUFFER, buf, buflen);
jasm_set(jasm_t *, JASM_SET_CALLBACKS, t


//void __fastcall jasm_find_key(jasm_node_t *


int __cdecl main(int argc, char **argv)
{
	printf("Hello World\n");

	_jasm_t *j;

	jasm_init(&jasm, alloc, 0);

	j = (_jasm_t*)&jasm;

	printf("Phase: 0x%p\n", j->phase);
	printf("Length: 0x%p\n", j->length);
	printf("Stack Index: %u\n", j->stackidx);
	printf("LineNo: %u\n", j->lineno);
	printf("Alloc: 0x%p | 0x%p\n", j->alloc, alloc);
	return 1;
}


int __stdcall mainCRTStartup()
{
	main(0, 0);
	return 1;
}

