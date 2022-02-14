
#include <stdio.h>

#include "json\jasm.h"

//#include "test_json.h"

char *test_string =
"qndtefupsphjvnjtaxokkzdyhduoyxuvrpdymnqhnyntcgmffrvebuon"
"fsduapngoixgfcjxzdgoeutkecamkwhmswuykbqiqutcvitazrjhfedmu"
"fmtpoqpjxmhgqdvjedgviagsipbmysucfazikqdloceikrwuckpvaujne"
"zidmjtknjpyfvfeskryofdrlsyzxtgifdrtocusuctmmkafvqahcmdvuz"
"mcyrsgseywvujmdqlwawbczuhfejktrqiezzduaiqwflktgejuukjyjpy"
"rcehunjnnnnvycxdfpvgsuhlobvbcrxzqhtycmvknyeyqzolubzidqxur"
"puaszpgzydufyuslrtgiixmfjtdgpmpereqkyutuatzxovbbhiedakufu"
"dfsfiuuuuzkfheikynrwldjhbxpnwxkkspqnxgaqddbgrkmigcwyimzrn"
"gxvvtspdmwhtwkpvnqbmakrdoxtbpipllidpwvottkyufjjekozbyzfuu"
"nvwkitlzagshpobusmritsosreguoetouqnwkhijlrhegilmpmpspeogu"
"fbbwnjmolbliqeektlrjqqtdzdalpbqypuptilazpildsxpixtjhmrlym"
"gvjmfnrgnhswrpoketimoeaiyyupkwofjxspupnfqaaaskufqimiwztaw"
"xwimfoitdhjaekbybivnipeyuytgeowihhdkaqcszbyobtqsofjlwkahm"
"qastfvftpdxtiknfehpygtdqslrgzqlzzbxnwazjzyphkmdkphzenghru"
"cxtkcbsoetjyhgzqkyajayyzjxyogwducnftipuyaovjcvyiitxvffzep"
"vpsaeaalachkxfauzjujgiwqgqktgsokwamiajojbmvxmdseeqgridvoh"
"issqdoowjmdwwopvletwtlbwdirlneggxofrhwvwgbuuktmiyliasjokx"
"abjrzosxfrcpohlhyvphqehvddllmjyofvutvhxpltzjzfzmmrkbjkgu";



//Prime Numbers
//13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59,
//61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109,
//113, 127, 131, 137, 139, 149, 151, 157, 163, 

// 32bit 512: slots=79, levels=32, other=18
// 64bit 512: slots=29, levels=18, other=17



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

	jasm_init(&jasm);

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


	jasm_parse(&jasm);

	//printf("Long Multiplication: %u\n", (1 << 5));

	//printf("len %u\n", len);


	return 1;
}


int __stdcall mainCRTStartup()
{
	main(0, 0);
	return 1;
}

