
#define JASM_ALIGN(n) __declspec(align(n))

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


JASM_ALIGN(1)
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
	short flags;
	unsigned char stackidx;        // +20
	unsigned char result;
	jasm_alloc_t alloc;   // +24
	jasm_free_t free;     // +28
	void *ns_stack[0x20]; // 32 levels
} _jasm512_t;


#define JASMCALL __fastcall

int __fastcall jasm_strlen(char *str);


/*
 * Initialize the jasm library. Must be called before calling any other jasm procedure
 */
int JASMCALL jasm_init(void *jasm);


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



