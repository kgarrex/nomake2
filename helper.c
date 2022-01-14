
#include "helper.h"

size_t str8to16(wchar_t *dest, char *src, size_t length)
{
	char *tmp = (char*)dest;

	if(length == -1)
	{
		while(*src)
		{
			*tmp++ = *src++;
			*tmp++ = 0;
		}
	}
	else
	{
		while(length--)
		{
			*tmp++ = *src++;
			*tmp++ = 0;
		}
	}

	return tmp - (char*)dest; 
}


size_t str16to8(char *dest, wchar_t *src, size_t length)
{
	return 0;
}
