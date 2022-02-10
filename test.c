
#include <stdio.h>

typedef struct _jasm32 {char _[512];} jasm32_t;

typedef struct _jasm64 {char _[2048];} jasm64_t;

//typedef struct jasm_node {char _[32];} jasm_node_t;


typedef void *(__fastcall *jasm_alloc_t)(int size);
typedef void (__fastcall *jasm_free_t)(void *);


typedef struct _jasm
{
	char pad1[152];
	int nbuckets;
	void *focus;
	void *root;         // +0
	int phase;          // +4
	char *string;       // +8
	int bufsize;        // +12
	int lineno;         // +16
	char stackidx;      // +20
	char pad2[3];
	jasm_alloc_t alloc; // +24
	jasm_free_t free;   // +28
	void *ns_stack[80]; // +32
} _jasm_t;




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
jasm32_t jasm;

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

	_jasm_t *j;

	jasm_init(&jasm, sizeof(jasm));

	j = (_jasm_t*)&jasm;

	printf("Phase: 0x%p\n", j->phase);
	printf("Length: 0x%p\n", j->bufsize);
	printf("Stack Index: %u\n", j->stackidx);
	printf("LineNo: %u\n", j->lineno);
	printf("Alloc: 0x%p | 0x%p\n", j->alloc, alloc);

	
	char *string = "\'$.\'u";
	for(int i = 0; i < 4; i++)
	{
		char c = string[i];
		printf("Char: %c\n", c);
	}
	return 1;
}


int __stdcall mainCRTStartup()
{
	main(0, 0);
	return 1;
}

