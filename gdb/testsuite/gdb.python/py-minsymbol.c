/* This testcase is part of GDB, the GNU debugger.

   Copyright 2018 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see  <http://www.gnu.org/licenses/>.  */

/* So we have a data section */
const char foo[] = "somestring";

asm("\
.section .text\n\
.global text_msym\n\
text_msym:\n\
	.byte 0\n\
.section .data\n\
.globl data_msym\n\
data_msym:\n\
	.asciz \"minsym text\"\n\
data_msym2:\n\
	.asciz \"minsym2 text\"\n\
");

int
main (void)
{
  return 0;
}
