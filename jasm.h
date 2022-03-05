
#define JASM_ALIGN(n) __declspec(align(n))

typedef struct _jasm {char _[512];} jasm_t;


typedef struct _jasm_vtable {
    void* (*alloc)(long size);
    void (*free)(void* ptr);
} jasm_vtable;



#define MAX_JSON_BUFFER   0x400000



// Allow the storage of key names, use mainly to parse and write
// If this flag is set when write keys to a document, jasm will
// write attempt to write a unique value in place of a string
#define JASM_FLAG_PARSE_PRESERVE_KEYS  0x01


// Preserve the letter casing of keys
#define JASM_FLAG_PARSE_CASE_SENSITIVE 0x02


// Keys are only allow to contain alphanumeric characters and underscore
// Keys must begin with either an alpha or underscore
#define JASM_FLAG_PARSE_STRICT_KEYS   0x04


// Allow integers to be expressed in hexadecimal, octal and binary notations
#define JASM_FLAG_PARSE_NUM_NOTATIONS 0x08


// No duplicate keys are allowed in an object. This produeces an error.
// This will typically be less optimal for speed parsing
#define JASM_FLAG_NO_DUP_KEYS         0x10


// Parser does not check for valid uft8 string.
#define JASM_FLAG_BYPASS_STRING_CHECK 0x20


//typedef struct jasm_node {char _[32];} jasm_node_t;




// No available system memory
#define JASM_ERROR_NO_MEMORY        0x01
#define JASM_ERROR_BAD_PARAM1       
#define JASM_ERROR_CPU_UNSUPPORTED  0x03



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


JASM_ALIGN(1)
typedef struct _jasm512
{
	void *slots[0x4f];    // 79 slots
	char pad1[19];
        long nblock;
        char blockpos;
	long charmask;
	unsigned char *prslt; // the result pointer
	void *focus;
	void *root;           // +0
	int phase;            // +4
	char *string;         // +8
	int bufsize;             // +12
	int lineno;              // +16
	short flags;
	unsigned char stackidx;        // +20
	unsigned char result;
	jasm_alloc_t alloc;   // +24
	jasm_free_t free;     // +28
	void *ns_stack[0x20]; // 32 levels
} _jasm512_t;


#define JASMCALL_FASTCALL __fastcall
#define JASMCALL_CDECL __cdecl

int JASMCALL_FASTCALL jasm_strlen(char *str);


/*
 * Initialize the jasm library. Must be called before calling any other jasm procedure
 * If there is an error on initialization, jasm_init will return the error code
 * vt - vtable of custom function pointers
 * 
 */
int JASMCALL_CDECL jasm_init(jasm_t *jasm, jasm_vtable *vt, ...);


/**
 * Set a jasm public variable
 */
void JASMCALL_CDECL jasm_set(void *jasm, int id, ...);


/**
 * Get a jasm public variable value
 */
void * JASMCALL_FASTCALL jasm_get(void *jasm, int id);




int JASMCALL_FASTCALL jasm_load_buf(void *jasm, char *utf8, int length);


//void JASMCALL_FASTCALL jasm_parse(jasm_t * jasm);
void JASMCALL_FASTCALL jasm_parse(jasm_t * jasm);




