/* Python interface to inferior threads.

   Copyright (C) 2009-2018 Free Software Foundation, Inc.

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
#include "gdbthread.h"
#include "inferior.h"
#include "python-internal.h"

typedef struct
{
  PyObject_HEAD

  /* The thread we represent.  */
  struct thread_info *thread;

  /* Regcache */
  PyObject *regcache;

  /* The Inferior object to which this thread belongs.  */
  PyObject *inf_obj;

  /*
   * Registers associated with this thread.  Python code may hold outstanding
   * references and we need to be able to mark them invalid.
   */
  PyObject *register_objs;
} thread_object;

/*
 * This just a container so we get the destructor to
 * free the Python reference
 */
struct python_thread_info : public private_thread_info
{
  PyObject *obj;
  ~python_thread_info() {
    if (obj)
      Py_DECREF(obj);
  }
};

static inline python_thread_info *
get_python_thread_info (class thread_info *thread)
{
  return static_cast<python_thread_info *> (thread->priv.get ());
}

thread_object *create_thread_object (struct thread_info *tp);
thread_object *find_thread_object (ptid_t ptid)
    CPYCHECKER_RETURNS_BORROWED_REF;

PyObject *register_to_register_object (thread_object *thread_obj, int reg);
void del_thread_registers (thread_object *thread);
