#include "hostenv.h"
#include "mailer.h"

static char *weekday[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

char *monthname[] = {	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
			"Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

extern char *rfc822date();

int main()
{
	static u_char buf[40];
	struct tm *ts;
	time_t tt;
	char *tzp;

	time(&tt);

	tzp = rfc822tz(&tt, &ts, 1);

	sprintf((char *)buf, "%s, %d %s %d %02d:%02d:%02d %s\n",
		weekday[ts->tm_wday], ts->tm_mday,
		monthname[ts->tm_mon], 1900 + ts->tm_year,
		ts->tm_hour, ts->tm_min, ts->tm_sec, tzp);
	printf("result: %s\n", buf);

	return 0;
}
