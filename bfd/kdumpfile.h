#ifndef _BFD_KDUMPFILE_H_
#define _BFD_KDUMPFILE_H_

#include "bfd.h"
#include <libkdumpfile/kdumpfile.h>
#include <libkdumpfile/addrxlat.h>

#ifdef __cplusplus
extern "C" {
#endif
struct bfd_kdumpfile_data_struct
{
  kdump_ctx_t *kdump_ctx;
  uint64_t kaslr_offset;
  char failing_command[132];
};

enum kdumpfile_section_type {
  KDUMPFILE_SECTION_MEMORY = 1,
  KDUMPFILE_SECTION_PRSTATUS = 2,
};

struct kdumpfile_section_data {
  kdump_addrspace_t as;
  enum kdumpfile_section_type type;
};

extern const bfd_target kdumpfile_vec;

#define bfd_kdumpfile_get_data(abfd) ((abfd)->tdata.kdumpfile_data)

#ifdef __cplusplus
}
#endif


#endif /* _BFD_KDUMPFILE_H_ */
