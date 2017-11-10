/* This testcase is part of GDB, the GNU debugger.

   Copyright 2007 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

   Please email any bugs, comments, and/or additions to this file to:
   bug-gdb@prep.ai.mit.edu  */

int main()
{
  return 0;
}

char n[]="A";
signed char s[]="A";
unsigned char u[]="A";

typedef char char_n;
typedef signed char char_s;
typedef unsigned char char_u;

char_n n_typed[]="A";
char_s s_typed[]="A";
char_u u_typed[]="A";
