/* DWARF CU data structure

   Copyright (C) 2021 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "defs.h"
#include "dwarf2/cu.h"
#include "dwarf2/read.h"

/* Initialize dwarf2_cu to read PER_CU, in the context of PER_OBJFILE.  */

dwarf2_cu::dwarf2_cu (dwarf2_per_cu_data *per_cu,
		      dwarf2_per_objfile *per_objfile)
  : per_cu (per_cu),
    per_objfile (per_objfile),
    mark (false),
    has_loclist (false),
    checked_producer (false),
    producer_is_gxx_lt_4_6 (false),
    producer_is_gcc_lt_4_3 (false),
    producer_is_icc (false),
    producer_is_icc_lt_14 (false),
    producer_is_codewarrior (false),
    processing_has_namespace_info (false)
{
}

/* See cu.h.  */

struct type *
dwarf2_cu::addr_sized_int_type (bool unsigned_p) const
{
  int addr_size = this->per_cu->addr_size ();
  return this->per_objfile->int_type (addr_size, unsigned_p);
}

/* Start a symtab for DWARF.  NAME, COMP_DIR, LOW_PC are passed to the
   buildsym_compunit constructor.  */

struct compunit_symtab *
dwarf2_cu::start_symtab (const char *name, const char *comp_dir,
			 CORE_ADDR low_pc)
{
  gdb_assert (m_builder == nullptr);

  m_builder.reset (new struct buildsym_compunit
		   (this->per_objfile->objfile,
		    name, comp_dir, language, low_pc));

  list_in_scope = get_builder ()->get_file_symbols ();

  get_builder ()->record_debugformat ("DWARF 2");
  get_builder ()->record_producer (producer);

  processing_has_namespace_info = false;

  return get_builder ()->get_compunit_symtab ();
}

/* See read.h.  */

struct type *
dwarf2_cu::addr_type () const
{
  struct objfile *objfile = this->per_objfile->objfile;
  struct type *void_type = objfile_type (objfile)->builtin_void;
  struct type *addr_type = lookup_pointer_type (void_type);
  int addr_size = this->per_cu->addr_size ();

  if (TYPE_LENGTH (addr_type) == addr_size)
    return addr_type;

  addr_type = addr_sized_int_type (addr_type->is_unsigned ());
  return addr_type;
}
