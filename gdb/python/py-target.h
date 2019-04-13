/* Python interface to target operations.

   Copyright (C) 2016 Free Software Foundation, Inc.

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

#ifndef GDB_PY_TARGET_H
#define GDB_PY_TARGET_H

#include "target.h"

typedef struct
{
  PyObject_HEAD

  target_ops *ops;
  bool native_target;
  bool registered;
} pytarget_object;

extern PyTypeObject target_object_type
    CPYCHECKER_TYPE_OBJECT_FOR_TYPEDEF ("pytarget_object");

class python_target : public target_ops
{
public:
  python_target (PyObject *owner) : owner(owner), registered(false) {
	  _info.shortname = NULL;
	  _info.longname = NULL;
	  _info.doc = NULL;
  }
  virtual ~python_target () override {
	  if (registered)
	    unregister_target ();
	  xfree (const_cast<char *>(_info.shortname));
	  xfree (const_cast<char *>(_info.longname));
	  xfree (const_cast<char *>(_info.doc));
  }
  const target_info &info () const override {
    return _info;
  }
  strata stratum () const override { return thread_stratum; }

  virtual void open (const char *name, int from_tty);

  void close () override;

  enum target_xfer_status xfer_partial (enum target_object object,
					const char *annex,
					gdb_byte *gdb_readbuf,
					const gdb_byte *gdb_writebuf,
					ULONGEST offset, ULONGEST len,
					ULONGEST *xfered_len) override;
  const char *thread_name (struct thread_info *info) override;
  const char *extra_thread_info (struct thread_info *info) override;
  void update_thread_list (void) override;
  std::string pid_to_str (ptid_t ptid) override;
  bool thread_alive (ptid_t ptid) override;
  void fetch_registers (struct regcache *regcache, int reg) override;
  bool has_execution (inferior *inf) override;
  void store_registers (struct regcache *regcache, int reg) override;
  void prepare_to_store (struct regcache *regcache) override;

  int set_shortname (PyObject *name);
  int set_longname (PyObject *name);
  int set_docstring (PyObject *name);

  PyObject *get_owner(void);

  void register_target (void);
  void unregister_target (void);
  void prepare_open (int from_tty);
  void push_target (void);
private:
  target_info _info;
  PyObject *owner;
  bool registered;
};


#endif /* GDB_PY_TARGET_H */
