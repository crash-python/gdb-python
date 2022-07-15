#include "config.h"
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <zlib.h>
#include <dlfcn.h>
#include <libiberty.h>
#include "bfd.h"
#include "libbfd.h"

/*
 * This is super hacky but it means that we don't force every consumer
 * of the library to link with libkdumpfile when it won't need it.
 */
#define KDUMPFILE_USE_DLOPEN 1

#if KDUMPFILE_USE_DLOPEN
#define kdump_new			indirect_kdump_new
#define kdump_free			indirect_kdump_free
#define kdump_read			indirect_kdump_read
#define kdump_get_err			indirect_kdump_get_err
#define kdump_get_attr			indirect_kdump_get_attr
#define kdump_get_typed_attr		indirect_kdump_get_typed_attr
#define kdump_set_attr			indirect_kdump_set_attr
#define kdump_attr_ref_get		indirect_kdump_attr_ref_get
#define kdump_get_addrxlat		indirect_kdump_get_addrxlat
#define kdump_attr_iter_start		indirect_kdump_attr_iter_start
#define kdump_attr_iter_next		indirect_kdump_attr_iter_next
#define kdump_attr_iter_end		indirect_kdump_attr_iter_end
#define addrxlat_sys_get_meth		indirect_addrxlat_sys_get_meth
#define addrxlat_sys_get_map		indirect_addrxlat_sys_get_map
#define addrxlat_map_ranges		indirect_addrxlat_map_ranges
#endif

#include "kdumpfile.h"

#if KDUMPFILE_USE_DLOPEN

kdump_ctx_t *(*kdump_new_p)(void);
void (*kdump_free_p)(kdump_ctx_t *);
kdump_status (*kdump_read_p)(kdump_ctx_t *, kdump_addrspace_t, kdump_addr_t, void *, size_t *);
const char * (*kdump_get_err_p)(kdump_ctx_t *);
kdump_status (*kdump_get_attr_p)(kdump_ctx_t *, const char *, kdump_attr_t *);
kdump_status (*kdump_get_typed_attr_p)(kdump_ctx_t *, const char *, kdump_attr_t *);
kdump_status (*kdump_set_attr_p)(kdump_ctx_t *, const char *, const kdump_attr_t *);
kdump_status (*kdump_attr_ref_get_p)(kdump_ctx_t *, const kdump_attr_ref_t *, kdump_attr_t *);
kdump_status (*kdump_get_addrxlat_p)(kdump_ctx_t *, addrxlat_ctx_t **, addrxlat_sys_t **);
kdump_status (*kdump_attr_iter_start_p)(kdump_ctx_t *, const char *, kdump_attr_iter_t *);
kdump_status (*kdump_attr_iter_next_p)(kdump_ctx_t *, kdump_attr_iter_t *);
void (*kdump_attr_iter_end_p)(kdump_ctx_t *, kdump_attr_iter_t *);
const addrxlat_meth_t *(*addrxlat_sys_get_meth_p)(const addrxlat_sys_t *, addrxlat_sys_meth_t);
addrxlat_map_t *(*addrxlat_sys_get_map_p)(const addrxlat_sys_t *, addrxlat_sys_map_t);
size_t (*addrxlat_map_len_p)(const addrxlat_map_t *map);
const addrxlat_range_t *(*addrxlat_map_ranges_p)(const addrxlat_map_t *map);

typedef void (*funcptr_t)(void);

struct required_fn {
  const char *name;
  funcptr_t *target;
} required_fns[] = {
  { "kdump_new",		(funcptr_t *)&kdump_new_p, },
  { "kdump_free",		(funcptr_t *)&kdump_free_p, },
  { "kdump_read",		(funcptr_t *)&kdump_read_p, },
  { "kdump_get_err",		(funcptr_t *)&kdump_get_err_p, },
  { "kdump_get_attr",		(funcptr_t *)&kdump_get_attr_p, },
  { "kdump_get_typed_attr",	(funcptr_t *)&kdump_get_typed_attr_p, },
  { "kdump_set_attr",		(funcptr_t *)&kdump_set_attr_p, },
  { "kdump_attr_ref_get",	(funcptr_t *)&kdump_attr_ref_get_p, },
  { "kdump_attr_iter_start",	(funcptr_t *)&kdump_attr_iter_start_p, },
  { "kdump_attr_iter_next",	(funcptr_t *)&kdump_attr_iter_next_p, },
  { "kdump_attr_iter_end",	(funcptr_t *)&kdump_attr_iter_end_p, },
  { "kdump_get_addrxlat",	(funcptr_t *)&kdump_get_addrxlat_p, },
  { "addrxlat_sys_get_meth",	(funcptr_t *)&addrxlat_sys_get_meth_p, },
  { "addrxlat_sys_get_map",	(funcptr_t *)&addrxlat_sys_get_map_p, },
  { "addrxlat_map_len",		(funcptr_t *)&addrxlat_map_len_p, },
  { "addrxlat_map_ranges",	(funcptr_t *)&addrxlat_map_ranges_p, },
};


extern kdump_ctx_t *
kdump_new(void);

kdump_ctx_t *
kdump_new(void)
{
  return kdump_new_p ();
}

void
kdump_free(kdump_ctx_t *ctx)
{
  return kdump_free_p(ctx);
}

kdump_status
kdump_read(kdump_ctx_t *ctx, kdump_addrspace_t as, kdump_addr_t addr,
		    void *buffer, size_t *plength)
{
  return kdump_read_p(ctx, as, addr, buffer, plength);
}

const char *
kdump_get_err(kdump_ctx_t *ctx)
{
  return kdump_get_err_p (ctx);
}

kdump_status
kdump_get_attr(kdump_ctx_t *ctx, const char *key, kdump_attr_t *valp)
{
  return kdump_get_attr_p (ctx, key, valp);
}

kdump_status
kdump_get_typed_attr(kdump_ctx_t *ctx, const char *key, kdump_attr_t *valp)
{
  return kdump_get_typed_attr_p (ctx, key, valp);
}

kdump_status
kdump_set_attr(kdump_ctx_t *ctx, const char *key, const kdump_attr_t *valp)
{
  return kdump_set_attr_p (ctx, key, valp);
}

kdump_status
kdump_attr_ref_get(kdump_ctx_t *ctx, const kdump_attr_ref_t *ref,
		   kdump_attr_t *valp)
{
  return kdump_attr_ref_get_p (ctx, ref, valp);
}


kdump_status
kdump_attr_iter_start(kdump_ctx_t *ctx, const char *path,
                      kdump_attr_iter_t *iter)
{
  return kdump_attr_iter_start_p(ctx, path, iter);
}

kdump_status
kdump_attr_iter_next(kdump_ctx_t *ctx, kdump_attr_iter_t *iter)
{
  return kdump_attr_iter_next_p(ctx, iter);
}

void
kdump_attr_iter_end(kdump_ctx_t *ctx, kdump_attr_iter_t *iter)
{
  return kdump_attr_iter_end_p(ctx, iter);
}

kdump_status
kdump_get_addrxlat(kdump_ctx_t *ctx,
			    addrxlat_ctx_t **axctx, addrxlat_sys_t **axsys)
{
  return kdump_get_addrxlat_p (ctx, axctx, axsys);
}

const addrxlat_meth_t *
addrxlat_sys_get_meth(const addrxlat_sys_t *sys, addrxlat_sys_meth_t idx)
{
  return addrxlat_sys_get_meth_p (sys, idx);
}

addrxlat_map_t *
addrxlat_sys_get_map(const addrxlat_sys_t *sys, addrxlat_sys_map_t idx)
{
  return addrxlat_sys_get_map_p (sys, idx);
}

const addrxlat_range_t *
addrxlat_map_ranges(const addrxlat_map_t *map)
{
  return addrxlat_map_ranges_p(map);
}


size_t
addrxlat_map_len (const addrxlat_map_t *map)
{
  return addrxlat_map_len_p(map);
}

static void *
locate_symbol(void *handle, const char *symname)
{
  char *error;
  void *fn;

  fn = dlsym(handle, symname);
  error = dlerror();
  if (error != NULL)
    {
      fprintf(stderr, "failed to locate required symbol %s\n", symname);
      return NULL;
    }

  return fn;
}

static bool
kdumpfile_init_libs(void)
{
  int i;
  void *libkdumpfile;
  int count = ARRAY_SIZE(required_fns);

  if (*required_fns[count - 1].target != NULL)
    return true;

  libkdumpfile = dlopen("libkdumpfile.so.9", RTLD_NOW);
  if (!libkdumpfile)
    return false;

  for (i = 0; i < count; i++) {
    void *fn = locate_symbol(libkdumpfile, required_fns[i].name);
    if (fn == NULL)
      return false;
    *(required_fns[i].target) = fn;
  }

  return true;
}
#else
static inline bool kdumpfile_init_libs(void) { return true; }
#endif

static const char *addrxlat_sys_meth_descr(addrxlat_sys_meth_t meth)
{
  static char buf[32];

  switch (meth)
    {
      case ADDRXLAT_SYS_METH_NONE:
	return "none";
      case ADDRXLAT_SYS_METH_PGT:
	return "pgt";
      case ADDRXLAT_SYS_METH_UPGT:
	return "upgt";
      case ADDRXLAT_SYS_METH_DIRECT:
	return "direct";
      case ADDRXLAT_SYS_METH_KTEXT:
	return "ktext";
      case ADDRXLAT_SYS_METH_VMEMMAP:
	return "vmemmap";
      case ADDRXLAT_SYS_METH_RDIRECT:
	return "direct";
      case ADDRXLAT_SYS_METH_MACHPHYS_KPHYS:
	return "machphys_kphys";
      case ADDRXLAT_SYS_METH_KPHYS_MACHPHYS:
	return "phys_machkphys";
      case ADDRXLAT_SYS_METH_CUSTOM:
	return "custom-meth-0";
    };

  snprintf(buf, sizeof(buf), "custom-meth-%d", meth - ADDRXLAT_SYS_METH_CUSTOM);

  return buf;
}

static int
check_kphys_direct_map(addrxlat_sys_t *sys, addrxlat_addr_t target_addr)
{
  addrxlat_map_t *map;
  size_t i, n;
  const addrxlat_range_t *range;
  addrxlat_addr_t addr;

  map = addrxlat_sys_get_map(sys, ADDRXLAT_SYS_MAP_KPHYS_DIRECT);
  if (!map)
  {
      fprintf(stderr, "Can't get MAP_KPHYS_DIRECT map\n");
      bfd_set_error (bfd_error_wrong_format);
      return -1;
    }

  n = addrxlat_map_len(map);
  addr = 0;
  range = addrxlat_map_ranges(map);

  for (i = 0; i < n; ++i)
    {
      if (addr == target_addr && range->meth == ADDRXLAT_SYS_METH_RDIRECT)
	{
	  return 1;
	}
	addr += range->endoff + 1;
	++range;
    }

  return 0;
}

/*
 * This should be as simple as requesting cpu.0.PRSTATUS and checking its size.
 * Unfortunately, there is padding in the elf_prstatus structure and the
 * blob ends up being unusable by gdb.
 */
static int
get_register_section(kdump_ctx_t *ctx, void *data, int datasize)
{
  const char *attrname = "cpu.0.reg";
  kdump_attr_iter_t iter;
  kdump_attr_t attr = { .type = KDUMP_NUMBER ,};
  kdump_status res;
  int count = 0;
  int regsize;

  res = kdump_get_typed_attr(ctx, "arch.ptr_size", &attr);
  if (res != KDUMP_OK)
    return -1;

  regsize = attr.val.number;

  res = kdump_attr_iter_start(ctx, attrname, &iter);
  if (res != KDUMP_OK)
    return -1;

  while (iter.key)
    {
      if (data)
	{
	  int offset;

	  res = kdump_attr_ref_get (ctx, &iter.pos, &attr);
	  if (res != KDUMP_OK)
	    break;

	  offset = count * regsize;

	  if (offset + regsize > datasize)
	    {
	      res = KDUMP_ERR_NODATA;
	      break;
	    }

	  memcpy(data + offset, &attr.val.number, regsize);
	}

      count += 1;
      res = kdump_attr_iter_next(ctx, &iter);
      if (res != KDUMP_OK)
	break;
    }

  kdump_attr_iter_end(ctx, &iter);
  if (res != KDUMP_OK)
    return -1;

  return count * regsize;
}

static bool
create_range_sections(bfd *abfd, struct bfd_kdumpfile_data_struct *tdata)
{
  kdump_ctx_t *ctx = tdata->kdump_ctx;
  kdump_status res;
  asection *asect;
  addrxlat_sys_t *sys;

  addrxlat_map_t *map;
  addrxlat_addr_t addr;
  const addrxlat_range_t *range;
  size_t i, n;
  const char *kaslr_offset_str;
  struct kdumpfile_section_data *secdata;
  kdump_addrspace_t as;
  int size;

  res = kdump_get_addrxlat (ctx, NULL, &sys);
  if (res != KDUMP_OK)
    {
      fprintf(stderr, "Can't get addrxlat\n");
      bfd_set_error (bfd_error_wrong_format);
      return false;
    }

  map = addrxlat_sys_get_map(sys, ADDRXLAT_SYS_MAP_KV_PHYS);
  if (!map)
  {
      fprintf(stderr, "Can't get MAP_KV_PHYS map\n");
      bfd_set_error (bfd_error_wrong_format);
      return false;
    }

  res = kdump_get_string_attr (ctx, "linux.vmcoreinfo.lines.KERNELOFFSET",
			       &kaslr_offset_str);
  if (res != KDUMP_OK && res != KDUMP_ERR_NOKEY)
    {
      fprintf(stderr, "Can't get kaslr offset\n");
      bfd_set_error (bfd_error_wrong_format);
      return false;

    }

  if (res == KDUMP_OK)
    {
      errno = 0;
      tdata->kaslr_offset = strtoul(kaslr_offset_str, NULL, 16);
      if (errno)
	{
	  fprintf(stderr, "Can't parse kaslr offset\n");
	  bfd_set_error (bfd_error_wrong_format);
	  return false;
	}
      abfd->start_address = tdata->kaslr_offset;
    }

  n = addrxlat_map_len(map);
  addr = 0;
  range = addrxlat_map_ranges(map);

  for (i = 0; i < n; ++i)
    {
      char *name;
      int ret;

      switch (range->meth)
	{
	  case ADDRXLAT_SYS_METH_PGT:
	  case ADDRXLAT_SYS_METH_VMEMMAP:
	  case ADDRXLAT_SYS_METH_DIRECT:
	  case ADDRXLAT_SYS_METH_KTEXT:
	    break;
	  case ADDRXLAT_SYS_METH_NONE:
	  case ADDRXLAT_SYS_METH_UPGT:
	  case ADDRXLAT_SYS_METH_RDIRECT:
	  case ADDRXLAT_SYS_METH_MACHPHYS_KPHYS:
	  case ADDRXLAT_SYS_METH_KPHYS_MACHPHYS:
	  default:
	    goto next_range;
	};

      ret = check_kphys_direct_map (sys, addr);
      if (ret < 0)
	return false;

      if (ret == 0)
	{
	  if (asprintf(&name, ".kv_phys.%s.%lx",
		       addrxlat_sys_meth_descr (range->meth), addr) < 0)
	    {
	      bfd_set_error (bfd_error_no_memory);
	      return false;
	    }
	  as = KDUMP_KVADDR;
	}
      else
	{
	  /* physical mapping */
	  if (asprintf(&name, ".kphys_direct.%lx", addr) < 0)
	    {
	      bfd_set_error (bfd_error_no_memory);
	      return false;
	    }
	  as = KDUMP_KPHYSADDR;
	}

      asect = bfd_make_section_with_flags (abfd, name,
				(SEC_ALLOC | SEC_HAS_CONTENTS | SEC_LOAD));
      if (asect == NULL)
	return false;

      secdata = bfd_alloc(abfd, sizeof(struct kdumpfile_section_data));
      if (secdata == NULL)
	return false;

      secdata->as = as;
      secdata->type = KDUMPFILE_SECTION_MEMORY;

      asect->vma = addr;
      asect->size = range->endoff;
      asect->used_by_bfd = secdata;

//      fprintf(stderr, "created %s section 0x%lx-0x%lx\n", asect->name, asect->vma, asect->size);

next_range:
	addr += range->endoff + 1;
	++range;
    }

  asect = bfd_make_section_with_flags (abfd, ".reg", SEC_HAS_CONTENTS);
  if (asect == NULL)
    return false;

  secdata = bfd_alloc(abfd, sizeof(struct kdumpfile_section_data));
  if (secdata == NULL)
    return false;

  size = get_register_section(ctx, NULL, 0);
  if (size < 0)
    return false;

  asect->size = size;
  asect->used_by_bfd = secdata;
  secdata->type = KDUMPFILE_SECTION_PRSTATUS;

  return true;
}

static const struct arch_map {
  const char *uts_machine;
  enum bfd_architecture arch;
  unsigned long mach;
} arch_map[] = {
  { "aarch64", bfd_arch_arm, bfd_mach_arm_8 },
  { "alpha", bfd_arch_alpha, 0 },
  { "arm", bfd_arch_arm, bfd_mach_arm_7 },
  { "ia32", bfd_arch_i386, bfd_mach_i386_i386 },
  { "ia64", bfd_arch_ia64, bfd_mach_ia64_elf64 },
  { "mips", bfd_arch_mips, 0 },
  { "ppc", bfd_arch_powerpc, bfd_mach_ppc },
  { "ppc64", bfd_arch_powerpc, bfd_mach_ppc64 },
  { "s390", bfd_arch_s390, bfd_mach_s390_31 },
  { "s390x", bfd_arch_s390, bfd_mach_s390_64 },
  { "x86_64", bfd_arch_i386, bfd_mach_x86_64 },
};

static bfd_cleanup
kdumpfile_core_file_p (bfd *abfd)
{
  struct bfd_kdumpfile_data_struct *tdata = NULL;
  kdump_status res;
  addrxlat_sys_t *xlatsys;
  kdump_attr_t archattr;
  const struct arch_map *map = NULL;
  unsigned int i;

  if (!kdumpfile_init_libs())
    {
      bfd_set_error (bfd_error_missing_dso);
      goto fail;
    }

  tdata = bfd_zalloc(abfd, sizeof(*tdata));
  if (!tdata)
    goto fail;

  tdata->kdump_ctx = kdump_new();
  if (!tdata->kdump_ctx)
    {
      bfd_set_error (bfd_error_no_memory);
      goto fail;
    }

  if (abfd->iostream == NULL || (abfd->flags & BFD_IN_MEMORY) == BFD_IN_MEMORY)
    {
      fprintf(stderr, "Can't get file descriptor %p %x\n",
	      abfd->iostream, abfd->flags & BFD_IN_MEMORY);
      bfd_set_error (bfd_error_invalid_target);
      goto fail;
    }

  res = kdump_set_number_attr(tdata->kdump_ctx, KDUMP_ATTR_FILE_FD,
			      fileno((FILE *)(abfd->iostream)));
  if (res != KDUMP_OK)
    {
      fprintf(stderr, "Can't set file descriptor\n");
      bfd_set_error (bfd_error_wrong_format);
      goto fail;
    }

  res = kdump_set_string_attr(tdata->kdump_ctx, "addrxlat.ostype", "linux");
  if (res != KDUMP_OK)
    {
      fprintf(stderr, "Can't set ostype: %s\n", kdump_get_err(tdata->kdump_ctx));
      bfd_set_error (bfd_error_wrong_format);
      goto fail;
    }

  res = kdump_get_attr (tdata->kdump_ctx, "addrxlat.ostype", &archattr);
  if (res != KDUMP_OK)
    {
      fprintf(stderr, "Can't get ostype: %s\n", kdump_get_err(tdata->kdump_ctx));
      bfd_set_error (bfd_error_wrong_format);
      goto fail;
    }


  res = kdump_get_addrxlat (tdata->kdump_ctx, NULL, &xlatsys);
  if (res != KDUMP_OK)
    {
      fprintf(stderr, "Can't get addrxlat\n");
      bfd_set_error (bfd_error_wrong_format);
      goto fail;
    }

  res = kdump_get_attr(tdata->kdump_ctx, "arch.name", &archattr);
  if (res != KDUMP_OK)
    {
      fprintf(stderr, "Can't resolve arch\n");
      bfd_set_error (bfd_error_invalid_target);
      goto fail;

    }

  for (i = 0; i < ARRAY_SIZE(arch_map); i++)
    {
      if (strcmp(arch_map[i].uts_machine, archattr.val.string) == 0) {
	map = &arch_map[i];
	break;
      }
    }

  if (!map)
    {
      fprintf(stderr, "Can't determine architecture\n");
      goto fail;
    }

  /* Select architecture */
  bfd_default_set_arch_mach(abfd, map->arch, map->mach);

  if (!create_range_sections(abfd, tdata))
    goto fail;

  abfd->tdata.kdumpfile_data = tdata;
  return _bfd_no_cleanup;

 fail:
  if (tdata)
    {
      if (tdata->kdump_ctx)
	kdump_free (tdata->kdump_ctx);
      bfd_release (abfd, tdata);
      abfd->tdata.kdumpfile_data = NULL;
    }
  bfd_section_list_clear (abfd);
  return NULL;
}

static char *
kdumpfile_core_file_failing_command (bfd *abfd)
{
  struct bfd_kdumpfile_data_struct *tdata = abfd->tdata.kdumpfile_data;

  if (!*tdata->failing_command)
    {
      kdump_attr_t sysname, release;
      kdump_status res;

      res = kdump_get_attr(tdata->kdump_ctx, "linux.uts.sysname", &sysname);
      if (res != KDUMP_OK)
	return "<unknown>";
      res = kdump_get_attr(tdata->kdump_ctx, "linux.uts.release", &release);
      if (res != KDUMP_OK)
	return "<unknown>";

      snprintf(tdata->failing_command, sizeof(tdata->failing_command), "%s %s",
	       sysname.val.string, release.val.string);
    }

  return tdata->failing_command;
}

static int
kdumpfile_core_file_failing_signal (bfd *abfd ATTRIBUTE_UNUSED)
{
  /*return core_signal (abfd);*/
  return 0;
}

static bool
kdumpfile_core_file_matches_executable_p (bfd *core_bfd ATTRIBUTE_UNUSED,
					  bfd *exec_bfd ATTRIBUTE_UNUSED)
{
  /*
   * We need a symbol table for exec_bfd to compare our release against
   * the kernel release.  This doesn't actually impact anything other than
   * whether a warning is printed.
   */
  return true;
}

static int
kdumpfile_core_file_pid (bfd *ignore_abfd ATTRIBUTE_UNUSED)
{
  return 0;
}

static bool
kdumpfile_get_section_contents (bfd *abfd ATTRIBUTE_UNUSED,
                                sec_ptr section ATTRIBUTE_UNUSED,
                                void *location ATTRIBUTE_UNUSED,
                                file_ptr offset ATTRIBUTE_UNUSED,
                                bfd_size_type count ATTRIBUTE_UNUSED)
{

  struct bfd_kdumpfile_data_struct *tdata = abfd->tdata.kdumpfile_data;
  kdump_status res;
  size_t len = count;
  uint64_t addr = section->vma + offset;
  const struct kdumpfile_section_data *secdata = section->used_by_bfd;

  if (secdata->type == KDUMPFILE_SECTION_MEMORY)
    {
      res = kdump_read(tdata->kdump_ctx, secdata->as, addr, location, &len);
      return (res == KDUMP_OK && len == count);
    }

  if (secdata->type == KDUMPFILE_SECTION_PRSTATUS)
    {
      res = get_register_section (tdata->kdump_ctx, location, count);
      return true;
    }

  printf("Couldn't read section %s\n", section->name);

  return false;
}

static bool
kdumpfile_get_section_contents_in_window(bfd *abfd ATTRIBUTE_UNUSED,
                                         sec_ptr section ATTRIBUTE_UNUSED,
                                         bfd_window *w ATTRIBUTE_UNUSED,
                                         file_ptr offset ATTRIBUTE_UNUSED,
                                         bfd_size_type count ATTRIBUTE_UNUSED)
{
  fprintf(stderr, "Reading window\n");
  return false;
}

/* If somebody calls any byte-swapping routines, shoot them.  */

static void
swap_abort (void)
{
 /* This way doesn't require any declaration for ANSI to fuck up.  */
  abort ();
}

#define	NO_GET ((bfd_vma (*) (const void *)) swap_abort)
#define	NO_PUT ((void (*) (bfd_vma, void *)) swap_abort)
#define	NO_GETS ((bfd_signed_vma (*) (const void *)) swap_abort)
#define	NO_GET64 ((bfd_uint64_t (*) (const void *)) swap_abort)
#define	NO_PUT64 ((void (*) (bfd_uint64_t, void *)) swap_abort)
#define	NO_GETS64 ((bfd_int64_t (*) (const void *)) swap_abort)

#define kdumpfile_close_and_cleanup    _bfd_generic_close_and_cleanup
#define kdumpfile_bfd_free_cached_info _bfd_generic_bfd_free_cached_info
#define kdumpfile_new_section_hook     _bfd_generic_new_section_hook

const bfd_target kdumpfile_vec =
  {
    "kdumpfile",
    bfd_target_kdumpfile_flavour,
    BFD_ENDIAN_UNKNOWN,         /* Target byte order.  */
    BFD_ENDIAN_UNKNOWN,         /* Target headers byte order.  */
    (HAS_RELOC | EXEC_P |      /* Object flags.  */
     HAS_LINENO | HAS_DEBUG |
     HAS_SYMS | HAS_LOCALS | WP_TEXT | D_PAGED),
    (SEC_HAS_CONTENTS |                /* Section flags.  */
     SEC_ALLOC | SEC_LOAD | SEC_RELOC),
    0,                         /* Symbol prefix.  */
    ' ',                       /* ar_pad_char.  */
    16,                                /* ar_max_namelen.  */
    0,                         /* Match priority.  */
    TARGET_KEEP_UNUSED_SECTION_SYMBOLS, /* keep unused section symbols.  */

    NO_GET64, NO_GETS64, NO_PUT64,	/* 64 bit data.  */
    NO_GET, NO_GETS, NO_PUT,		/* 32 bit data.  */
    NO_GET, NO_GETS, NO_PUT,		/* 16 bit data.  */
    NO_GET64, NO_GETS64, NO_PUT64,	/* 64 bit hdrs.  */
    NO_GET, NO_GETS, NO_PUT,		/* 32 bit hdrs.  */
    NO_GET, NO_GETS, NO_PUT,		/* 16 bit hdrs.  */

    {                                  /* bfd_check_format.  */
      _bfd_dummy_target,               /* Unknown format.  */
      _bfd_dummy_target,               /* Object file.  */
      _bfd_dummy_target,               /* Archive.  */
      kdumpfile_core_file_p            /* A core file.  */
    },
    {                                  /* bfd_set_format.  */
      _bfd_bool_bfd_false_error,
      _bfd_bool_bfd_false_error,
      _bfd_bool_bfd_false_error,
      _bfd_bool_bfd_false_error
    },
    {                                  /* bfd_write_contents.  */
      _bfd_bool_bfd_false_error,
      _bfd_bool_bfd_false_error,
      _bfd_bool_bfd_false_error,
      _bfd_bool_bfd_false_error
    },

    BFD_JUMP_TABLE_GENERIC (kdumpfile),
    BFD_JUMP_TABLE_COPY (_bfd_generic),
    BFD_JUMP_TABLE_CORE (kdumpfile),
    BFD_JUMP_TABLE_ARCHIVE (_bfd_noarchive),
    BFD_JUMP_TABLE_SYMBOLS (_bfd_nosymbols),
    BFD_JUMP_TABLE_RELOCS (_bfd_norelocs),
    BFD_JUMP_TABLE_WRITE (_bfd_generic),
    BFD_JUMP_TABLE_LINK (_bfd_nolink),
    BFD_JUMP_TABLE_DYNAMIC (_bfd_nodynamic),

    NULL,

    NULL                               /* Backend_data.  */
  };
