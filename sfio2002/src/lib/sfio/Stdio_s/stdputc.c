#include	"sfhdr.h"
#include	"stdio.h"
#undef putc

#if __STD_C
int putc(int c, FILE* f)
#else
int putc(c, f)
int	c;
FILE*	f;
#endif
{
	return f ? _std_putc(c,f) : -1;
}
