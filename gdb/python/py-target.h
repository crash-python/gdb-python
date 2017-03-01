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

  /* The target operations we represent.  */
  struct target_ops *ops;

  struct target_ops python_ops;

} pytarget_object;

#endif /* GDB_PY_TARGET_H */
