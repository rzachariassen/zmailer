#include "mailer.h"

#ifdef	HAVE_NDBM
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#include <ndbm.h>
#include <sys/file.h>

#else /* Not NDBM */

#error Tough, supports only NDBM for now

#endif




static DBM	*db = NULL;
static datum	key;


int
open_db ( file )
char	*file;
{
	if ((db = dbm_open(file, O_RDONLY, 0600)) == NULL)
		return (0);
	return (1);
}

datum
first_key ()
{
	return (dbm_firstkey(db));
}

datum
next_key ()
{
	return (dbm_nextkey(db));
}

void
close_db()
{
	dbm_close(db);
}
