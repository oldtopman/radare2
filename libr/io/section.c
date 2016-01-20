#include <r_io.h>
#include <sdb.h>
#include <r_types.h>

R_API void r_io_section_init (RIO *io)
{
	if (io && !io->sections) {
		if (io->sections = ls_new ())
			io->sections->free = free;
	}
}

R_API void r_io_section_fini (RIO *io)
{
	if (!io)
		return;
	if (io->sections)
		ls_free (io->sections);
	io->sections = NULL;
	if (io->freed_sec_ids)
		ls_free (io->freed_sec_ids);
	io->freed_sec_ids = NULL;
	io->sec_id = 0;
}

R_API int r_io_section_exists_for_id (RIO *io, ut32 id)
{
	SdbListIter *iter;
	RIOSection *sec;
	if (!io || !io->sections)
		return R_FALSE;
	ls_foreach (io->sections, iter, sec) {
		if (sec->id == id)
			return R_TRUE;
	}
	return R_FALSE;
}
