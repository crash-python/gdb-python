/* Gdb/Python header for private use by Python module.

   Copyright (C) 2008-2019 Free Software Foundation, Inc.

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

#ifndef PYTHON_PYTHON_INFERIOR_H
#define PYTHON_PYTHON_INFERIOR_H

#include "python-internal.h"
#include "gdbthread.h"
struct infpy_thread_info : public private_thread_info
{
	PyObject *object;
	~infpy_thread_info() {
	      Py_DECREF (object);
	};
};

#endif /* PYTHON_PYTHON_INFERIOR_H */
