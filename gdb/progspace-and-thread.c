/* Copyright (C) 2009-2018 Free Software Foundation, Inc.

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
#include "progspace-and-thread.h"

/* See progspace-and-thread.h  */

void
switch_to_program_space_and_thread (program_space *pspace)
{
  inferior *inf = current_inferior ();

  if (inf->pspace != pspace)
    inf = find_inferior_for_program_space (pspace);

  if (inf != NULL && inf->pid != 0)
    {
      thread_info *tp = any_live_thread_of_process (inf->pid);
      thread_info *current_tp = NULL;

      if (ptid_get_pid (inferior_ptid) == inf->pid)
	current_tp = find_thread_ptid (inferior_ptid);

      if (tp != NULL)
	{
	  /* Prefer primarily thread not THREAD_EXITED and secondarily thread
	     not EXECUTING.  */
	  if (current_tp == NULL
	      || (tp->state != THREAD_EXITED
		  && current_tp->state == THREAD_EXITED)
	      || (!tp->executing && current_tp->executing))
	    switch_to_thread (tp->ptid);

	  /* Switching thread switches pspace implicitly.  We're
	     done.  */
	  return;
	}
    }

  switch_to_thread (null_ptid);
  set_current_program_space (pspace);
}
