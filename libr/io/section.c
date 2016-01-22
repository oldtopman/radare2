#include <r_io.h>
#include <sdb.h>
#include <r_types.h>
#include <stdio.h>

void section_free (void *p)
{
	RIOSection *s = (RIOSection *)p;
	if (s)
		free (s->name);
	free (s);
}

R_API void r_io_section_init (RIO *io)
{
	if (io && !io->sections) {
		if (io->sections = ls_new ())
			io->sections->free = section_free;
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

R_API RIOSection *r_io_section_add (RIO *io, ut64 addr, ut64 vaddr, ut64 size, ut64 vsize, int rwx, const char *name, ut32 bin_id, int fd)
{
	RIOSection *sec;
	if (!io || !io->sections || !r_io_desc_get (io, fd) || !size || (UT64_MAX - size) < addr || (UT64_MAX - vsize) < vaddr)
		return NULL;
	if (!io->freed_sec_ids || io->sec_id == UT32_MAX)
		return NULL;
	sec = R_NEW0 (RIOSection);
	if (io->freed_sec_ids) {
		sec->id = (ut32)(size_t) ls_pop (io->freed_sec_ids);
		if (!io->freed_sec_ids->lenght) {
			ls_free (io->freed_sec_ids);
			io->freed_sec_ids = NULL;
		}
	} else {
		io->sec_id++;
		sec->id = io->sec_id;
	}
	sec->addr = addr;
	sec->vaddr = vaddr;
	sec->size = size;
	sec->vsize = vsize;
	sec->rwx = rwx;
	sec->bin_id = bin_id;
	sec->fd = fd;
	if (!name) {
		char buf[32];
		snprintf (buf, 31, "section.0x016%"PFMT64x"", vaddr);
		sec->name = strdup (buf);		//what should happen if that fails
	} else	sec->name = strdup (name);
	ls_append (io->sections, sec);
	return sec;
}
