#include <stdio.h>

void
tatimestr(buf,dt)
char *buf;
int dt;
{
	int hours, mins, secs;

	secs  = dt % 60;
	dt    = dt / 60;
	mins  = dt % 60;
	hours = dt / 60;

	sprintf(buf,"%02d:%02d:%02d", hours, mins, secs);
}
