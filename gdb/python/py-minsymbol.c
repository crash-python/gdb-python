/* Python interface to minsymbols.

   Copyright (C) 2008-2013 Free Software Foundation, Inc.

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
#include "block.h"
#include "exceptions.h"
#include "frame.h"
#include "symtab.h"
#include "python-internal.h"
#include "objfiles.h"
#include "value.h"

typedef struct msympy_symbol_object {
  PyObject_HEAD

  /* The GDB bound_minimal_symbol structure this object is wrapping.  */
  struct bound_minimal_symbol bound;

  /* A minsym object is associated with an objfile, so keep track with
     doubly-linked list, rooted in the objfile.  This lets us
     invalidate the underlying struct minimal_symbol when the objfile is
     deleted.  */
  struct msympy_symbol_object *prev;
  struct msympy_symbol_object *next;
} minsym_object;

/* Return the symbol that is wrapped by this symbol object.  */
static struct minimal_symbol *
minsym_object_to_minsym (PyObject *obj)
{
  if (! PyObject_TypeCheck (obj, &minsym_object_type))
    return NULL;
  return ((minsym_object *) obj)->bound.minsym;
}

static struct objfile *
minsym_object_to_objfile (PyObject *obj)
{
  if (! PyObject_TypeCheck (obj, &minsym_object_type))
    return NULL;
  return ((minsym_object *) obj)->bound.objfile;
}

/* Require a valid symbol.  All access to minsym_object->symbol should be
   gated by this call.  */
#define MSYMPY_REQUIRE_VALID(minsym_obj, minsym)	\
  do {							\
    minsym = minsym_object_to_minsym (minsym_obj);	\
    if (minsym == NULL)				\
      {							\
	PyErr_SetString (PyExc_RuntimeError,		\
			 _("MinSymbol is invalid."));	\
	return NULL;					\
      }							\
  } while (0)

#define MSYMPY_REQUIRE_VALID_BOUND(minsym_obj, minsym, objfile)	\
  do {								\
    minsym = minsym_object_to_minsym (minsym_obj);		\
    objfile = minsym_object_to_objfile (minsym_obj);		\
    if (minsym == NULL || objfile == NULL)			\
      {								\
	PyErr_SetString (PyExc_RuntimeError,			\
			 _("MinSymbol is invalid."));		\
	return NULL;						\
      }								\
  } while (0)

static const struct objfile_data *msympy_objfile_data_key;

static PyObject *
msympy_str (PyObject *self)
{
  PyObject *result;
  struct minimal_symbol *minsym = NULL;

  MSYMPY_REQUIRE_VALID (self, minsym);

  return PyString_FromString (MSYMBOL_PRINT_NAME (minsym));
}

static PyObject *
msympy_get_name (PyObject *self, void *closure)
{
  struct minimal_symbol *minsym = NULL;

  MSYMPY_REQUIRE_VALID (self, minsym);

  return PyString_FromString (MSYMBOL_NATURAL_NAME (minsym));
}

static PyObject *
msympy_get_file_name (PyObject *self, void *closure)
{
  struct minimal_symbol *minsym = NULL;

  MSYMPY_REQUIRE_VALID (self, minsym);

  return PyString_FromString (minsym->filename);
}

static PyObject *
msympy_get_linkage_name (PyObject *self, void *closure)
{
  struct minimal_symbol *minsym = NULL;

  MSYMPY_REQUIRE_VALID (self, minsym);

  return PyString_FromString (MSYMBOL_LINKAGE_NAME (minsym));
}

static PyObject *
msympy_get_print_name (PyObject *self, void *closure)
{
  struct minimal_symbol *minsym = NULL;

  MSYMPY_REQUIRE_VALID (self, minsym);

  return msympy_str (self);
}

static PyObject *
msympy_get_section (PyObject *self, void *closure)
{
  struct minimal_symbol *minsym = NULL;
  struct objfile *objfile = NULL;
  struct obj_section *section;
  const char *name;

  MSYMPY_REQUIRE_VALID_BOUND (self, minsym, objfile);

  section = MSYMBOL_OBJ_SECTION (objfile, minsym);
  if (section) {
    name = bfd_section_name (objfile->obfd, section->the_bfd_section);
    if (name)
      return PyString_FromString (name);
  }

  Py_RETURN_NONE;
}

static PyObject *
msympy_get_type (PyObject *self, void *closure)
{
  struct minimal_symbol *minsym = NULL;

  MSYMPY_REQUIRE_VALID (self, minsym);
  return PyInt_FromLong(MSYMBOL_TYPE(minsym));
}

static PyObject *
msympy_is_valid (PyObject *self, PyObject *args)
{
  struct minimal_symbol *minsym = NULL;

  minsym = minsym_object_to_minsym (self);
  if (minsym == NULL)
    Py_RETURN_FALSE;

  Py_RETURN_TRUE;
}

static struct type *
minsym_type(struct minimal_symbol *minsym)
{
  struct type *type;
  switch (minsym->type) {
  case mst_text:
  case mst_solib_trampoline:
  case mst_file_text:
  case mst_text_gnu_ifunc:
  case mst_slot_got_plt:
    type = builtin_type (python_gdbarch)->builtin_func_ptr;
    break;

  case mst_data:
  case mst_abs:
  case mst_bss:
  case mst_file_data:
  case mst_file_bss:
    type = builtin_type (python_gdbarch)->builtin_data_ptr;
    break;

  case mst_unknown:
  default:
    type = builtin_type (python_gdbarch)->builtin_void;
    break;
  }

  return type;
}

static PyObject *
msympy_is_code (PyObject *self, PyObject *args)
{
  struct minimal_symbol *minsym = NULL;
  struct type *type = builtin_type (python_gdbarch)->builtin_func_ptr;
  MSYMPY_REQUIRE_VALID (self, minsym);

  if (minsym_type(minsym) == type)
    Py_RETURN_TRUE;

  Py_RETURN_FALSE;
}

static PyObject *
msympy_is_data (PyObject *self, PyObject *args)
{
  struct minimal_symbol *minsym = NULL;
  struct type *type = builtin_type (python_gdbarch)->builtin_data_ptr;
  MSYMPY_REQUIRE_VALID (self, minsym);

  if (minsym_type(minsym) == type)
    Py_RETURN_TRUE;

  Py_RETURN_FALSE;
}

/* Implementation of gdb.MinSymbol.value (self) -> gdb.Value.  Returns
   the value of the symbol, or an error in various circumstances.  */

static PyObject *
msympy_value (PyObject *self, PyObject *args)
{
  minsym_object *minsym_obj = (minsym_object *)self;
  struct minimal_symbol *minsym = NULL;
  struct value *value = NULL;

  if (!PyArg_ParseTuple (args, ""))
    return NULL;

  MSYMPY_REQUIRE_VALID (self, minsym);
  TRY
    {
      value = value_from_ulongest (minsym_type (minsym),
				   MSYMBOL_VALUE_RAW_ADDRESS (minsym));
      if (value)
	set_value_address (value, MSYMBOL_VALUE_RAW_ADDRESS (minsym));
    }
  CATCH (except, RETURN_MASK_ALL)
    {
      GDB_PY_HANDLE_EXCEPTION (except);
    }
  END_CATCH

  return value_to_value_object (value);
}

static void
set_symbol (minsym_object *obj, struct bound_minimal_symbol *bound)
{
  obj->bound = *bound;
  obj->prev = NULL;
  if (bound->objfile)
    {
      obj->next = (minsym_object *) objfile_data (bound->objfile,
						  msympy_objfile_data_key);
      if (obj->next)
	obj->next->prev = obj;
      set_objfile_data (bound->objfile, msympy_objfile_data_key, obj);
    }
  else
    obj->next = NULL;
}

static PyObject *
bound_minsym_to_minsym_object (struct bound_minimal_symbol *bound)
{
  minsym_object *msym_obj;

  msym_obj = PyObject_New (minsym_object, &minsym_object_type);
  if (msym_obj)
    set_symbol (msym_obj, bound);

  return (PyObject *) msym_obj;
}

static void
msympy_dealloc (PyObject *obj)
{
  minsym_object *msym_obj = (minsym_object *) obj;

  if (msym_obj->prev)
    msym_obj->prev->next = msym_obj->next;
  else
    set_objfile_data (msym_obj->bound.objfile,
		      msympy_objfile_data_key, msym_obj->next);
  if (msym_obj->next)
    msym_obj->next->prev = msym_obj->prev;
  msym_obj->bound.minsym = NULL;
  msym_obj->bound.objfile = NULL;
}

/* Implementation of
   gdb.lookup_minimal_symbol (name, [sfile, [objfile]]) -> symbol or None.  */

PyObject *
gdbpy_lookup_minimal_symbol (PyObject *self, PyObject *args, PyObject *kw)
{
  int domain = VAR_DOMAIN;
  const char *name, *sfile = NULL;
  struct objfile *objfile = NULL;
  static char *keywords[] = { "name", "sfile", "objfile", NULL };
  struct bound_minimal_symbol bound_minsym = {};
  PyObject *msym_obj = NULL, *sfile_obj = NULL, *objfile_obj = NULL;
#if PY_MAJOR_VERSION >= 3
  PyObject *temp = NULL;
#endif

  if (!PyArg_ParseTupleAndKeywords (args, kw, "s|OO", keywords, &name,
				    &sfile_obj, &objfile_obj))
    return NULL;

  if (sfile_obj && sfile_obj != Py_None)
    {
#if PY_MAJOR_VERSION >= 3
	  temp = PyUnicode_AsASCIIString(sfile_obj);
	  if (!temp)
		  return NULL;

      sfile = PyBytes_AsString(temp); 
#else
	  sfile = PyString_AsString(sfile_obj);
#endif

      if (!sfile) {
#if PY_MAJOR_VERSION >= 3
		Py_DECREF(temp); 
#endif
		return NULL;
	  }
    }

  if (objfile_obj && objfile_obj != Py_None)
    {
      objfile = objfpy_object_to_objfile (objfile_obj);
      if (!objfile) {
#if PY_MAJOR_VERSION >= 3
		Py_DECREF(temp);
#endif
		return NULL;
	  }
    }

  TRY
    {
      bound_minsym = lookup_minimal_symbol (name, sfile, objfile);
    }
  CATCH (except, RETURN_MASK_ALL)
    {
      GDB_PY_HANDLE_EXCEPTION (except);
    }
  END_CATCH

#if PY_MAJOR_VERSION >= 3
  Py_XDECREF(temp);
#endif

  if (bound_minsym.minsym)
      msym_obj = bound_minsym_to_minsym_object (&bound_minsym);

  if (msym_obj)
    return msym_obj;

  Py_RETURN_NONE;
}

static void
del_objfile_msymbols (struct objfile *objfile, void *datum)
{
  minsym_object *obj = (minsym_object *) datum;
  while (obj)
    {
      minsym_object *next = obj->next;

      obj->bound.minsym = NULL;
      obj->bound.objfile = NULL;
      obj->next = NULL;
      obj->prev = NULL;

      obj = obj->next;
    }
}

int
gdbpy_initialize_minsymbols (void)
{
  if (PyType_Ready (&minsym_object_type) < 0)
    return -1;

  msympy_objfile_data_key
    = register_objfile_data_with_cleanup (NULL, del_objfile_msymbols);

  if (PyModule_AddIntConstant (gdb_module, "MINSYMBOL_TYPE_UNKNOWN",
			       mst_unknown) < 0
  || PyModule_AddIntConstant (gdb_module, "MINSYMBOL_TYPE_TEXT", mst_text) < 0
  || PyModule_AddIntConstant (gdb_module, "MINSYMBOL_TYPE_TEXT_GNU_IFUNC",
			      mst_text_gnu_ifunc) < 0
  || PyModule_AddIntConstant (gdb_module, "MINSYMBOL_TYPE_SLOT_GOT_PLT",
			      mst_slot_got_plt) < 0
  || PyModule_AddIntConstant (gdb_module, "MINSYMBOL_TYPE_DATA", mst_data) < 0
  || PyModule_AddIntConstant (gdb_module, "MINSYMBOL_TYPE_BSS", mst_bss) < 0
  || PyModule_AddIntConstant (gdb_module, "MINSYMBOL_TYPE_ABS", mst_abs) < 0
  || PyModule_AddIntConstant (gdb_module, "MINSYMBOL_TYPE_SOLIB_TRAMPOLINE",
			      mst_solib_trampoline) < 0
  || PyModule_AddIntConstant (gdb_module, "MINSYMBOL_TYPE_FILE_TEXT",
			      mst_file_text) < 0
  || PyModule_AddIntConstant (gdb_module, "MINSYMBOL_TYPE_FILE_DATA",
			      mst_file_data) < 0
  || PyModule_AddIntConstant (gdb_module, "MINSYMBOL_TYPE_FILE_BSS",
			      mst_file_bss) < 0)
    return -1;

  return gdb_pymodule_addobject (gdb_module, "MinSymbol",
				 (PyObject *) &minsym_object_type);
}



static PyGetSetDef minsym_object_getset[] = {
  { "name", msympy_get_name, NULL,
    "Name of the minimal symbol, as it appears in the source code.", NULL },
  { "linkage_name", msympy_get_linkage_name, NULL,
    "Name of the minimal symbol, as used by the linker (i.e., may be mangled).",
    NULL },
  { "filename", msympy_get_file_name, NULL,
    "Name of source file that contains this minimal symbol. Only applies for mst_file_*.",
    NULL },
  { "print_name", msympy_get_print_name, NULL,
    "Name of the minimal symbol in a form suitable for output.\n\
This is either name or linkage_name, depending on whether the user asked GDB\n\
to display demangled or mangled names.", NULL },
  { "section", msympy_get_section, NULL,
    "Section that contains this minimal symbol, if any", NULL, },
  { "type", msympy_get_type, NULL,
    "Type that this minimal symbol represents." },
  { NULL }  /* Sentinel */
};

static PyMethodDef minsym_object_methods[] = {
  { "is_valid", msympy_is_valid, METH_NOARGS,
    "is_valid () -> Boolean.\n\
Return true if this minimal symbol is valid, false if not." },
  { "is_code", msympy_is_code, METH_NOARGS,
    "is_code () -> Boolean.\n\
Return true if this minimal symbol represents code." },
  { "is_data", msympy_is_data, METH_NOARGS,
    "is_data () -> Boolean.\n\
Return true if this minimal symbol represents data." },
  { "value", msympy_value, METH_VARARGS,
    "value ([frame]) -> gdb.Value\n\
Return the value of the minimal symbol." },
  {NULL}  /* Sentinel */
};

PyTypeObject minsym_object_type = {
  PyVarObject_HEAD_INIT (NULL, 0)
  "gdb.MinSymbol",		  /*tp_name*/
  sizeof (minsym_object),	  /*tp_basicsize*/
  0,				  /*tp_itemsize*/
  msympy_dealloc,		  /*tp_dealloc*/
  0,				  /*tp_print*/
  0,				  /*tp_getattr*/
  0,				  /*tp_setattr*/
  0,				  /*tp_compare*/
  0,				  /*tp_repr*/
  0,				  /*tp_as_number*/
  0,				  /*tp_as_sequence*/
  0,				  /*tp_as_mapping*/
  0,				  /*tp_hash */
  0,				  /*tp_call*/
  msympy_str,			  /*tp_str*/
  0,				  /*tp_getattro*/
  0,				  /*tp_setattro*/
  0,				  /*tp_as_buffer*/
  Py_TPFLAGS_DEFAULT,		  /*tp_flags*/
  "GDB minimal symbol object",	  /*tp_doc */
  0,				  /*tp_traverse */
  0,				  /*tp_clear */
  0,				  /*tp_richcompare */
  0,				  /*tp_weaklistoffset */
  0,				  /*tp_iter */
  0,				  /*tp_iternext */
  minsym_object_methods,	  /*tp_methods */
  0,				  /*tp_members */
  minsym_object_getset		  /*tp_getset */
};
