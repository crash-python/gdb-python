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

#include "defs.h"
#include "gdbthread.h"
#include "inferior.h"
#include "python-internal.h"
#include "language.h"
#include "arch-utils.h"
#include "py-ref.h"

#include "py-target.h"

static PyObject *py_target_xfer_eof_error;
static PyObject *py_target_xfer_unavailable_error;

extern PyTypeObject pytarget_object_type
    CPYCHECKER_TYPE_OBJECT_FOR_TYPEDEF ("pytarget_object");

/* Require that Target operations are valid */
#define THPY_REQUIRE_VALID_RETURN(Target, ret)			\
  do {								\
    if (0)							\
      {								\
	PyErr_SetString (PyExc_RuntimeError,			\
			 _("Target not valid."));		\
	return ret;						\
      }								\
  } while (0)

#define THPY_REQUIRE_VALID(Target)				\
	THPY_REQUIRE_VALID_RETURN(Target, NULL)

#define THPY_REQUIRE_VALID_INT(Target)				\
	THPY_REQUIRE_VALID_RETURN(Target, 0)

#define THPY_REQUIRE_PYTHON_TARGET(target, ret)			\
  do {								\
    if (target->ops != &target->python_ops)			\
    {								\
      PyErr_SetString (PyExc_AttributeError,			\
		_("Property is read-only on native targets."));	\
      return ret;						\
    }								\
  } while (0)

/* Container of, courtesy of Linux Kernel for now */
#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &(((TYPE *) 0)->MEMBER))
#endif
#ifndef container_of
/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})
#endif

#define ENTRY() {} while(0)
#define EXIT() {} while(0)

/* Large spacing between sections during development for clear divisions */

/*****************************************************************************
 *
 * Target Operation Python Bindings
 *
 * These bindings map from the target_ops structure to the python object,
 * and call into any functions provided - or fall back to delegating to the
 * operations from beneath
 *
 *****************************************************************************/

/*
 * Our Target Ops structure will be stored inside our Target Object
 * This gives us the opportunity to find our Python Object when we are called
 * from C code
 */
static pytarget_object * target_ops_to_target_obj(struct target_ops *ops)
{
    pytarget_object *target_obj;

    if (ops->to_data == &pytarget_object_type) {
	target_obj = container_of(ops, pytarget_object, python_ops);
	return target_obj;
    }

    target_obj = PyObject_New (pytarget_object, &pytarget_object_type);
    if (target_obj)
      target_obj->ops = ops;

    return target_obj;
}



// Identify if our class (self) has a method to support this call
#define HasMethodOrReturnBeneath(py_ob, op, ops, args...)	\
	if (!gdb_PyObject_HasAttrString(py_ob, #op))		\
	{							\
	    ops = ops->beneath;					\
	    return ops->op(ops, ##args);			\
	}

static char *
xstrdup_realloc (const char *s, char *buf)
{
  size_t len = strlen (s) + 1;
  char *ret = XRESIZEVEC (char, buf, len);
  return (char *) memcpy (ret, s, len);
}

static const
char *py_target_to_thread_name (struct target_ops *ops,
				struct thread_info *info)
{
    pytarget_object *target_obj = target_ops_to_target_obj (ops);
    PyObject *self = (PyObject *) target_obj;
    static char *static_buf;
    char *ret = NULL;

    HasMethodOrReturnBeneath (self, to_thread_name, ops, info);

    gdbpy_ref<> thread(gdbpy_selected_thread (NULL, NULL));
    if (thread == NULL)
      return NULL;

    gdbpy_ref<> result(gdb_PyObject_CallMethod (self, "to_thread_name", "(O)",
					        thread.get(), NULL));
    if (result == NULL)
      return NULL;

    gdb::unique_xmalloc_ptr<char> name
       = python_string_to_host_string (result.get());
    if (name == NULL)
      return NULL;

    /* Do not remove this assignment */
    static_buf = xstrdup_realloc (name.get(), static_buf);
    return static_buf;
}

static const
char *py_target_to_thread_name_pyerr (struct target_ops *ops,
				      struct thread_info *info)
{
  gdbpy_enter enter_py (target_gdbarch (), current_language);

  PyErr_Clear ();

  const char *ret = py_target_to_thread_name (ops, info);

  if (PyErr_Occurred ())
    {
      gdbpy_print_stack();
      error (_("Error in Python while executing to_thread_name callback."));
    }
  return ret;
}

static enum target_xfer_status
py_target_to_xfer_partial (struct target_ops *ops,
			   enum target_object object, const char *annex,
			   gdb_byte *gdb_readbuf, const gdb_byte *gdb_writebuf,
			   ULONGEST offset, ULONGEST len, ULONGEST *xfered_len)
{
    pytarget_object *target_obj = target_ops_to_target_obj (ops);
    PyObject *self = (PyObject *) target_obj;
    enum target_xfer_status rt = TARGET_XFER_E_IO;
    unsigned long lret;

    HasMethodOrReturnBeneath (self, to_xfer_partial, ops, object, annex,
			      gdb_readbuf, gdb_writebuf, offset, len,
			      xfered_len);

    gdbpy_ref<> readbuf;
    if (gdb_readbuf)
      {
	readbuf.reset(PyByteArray_FromStringAndSize (
						  (char *) gdb_readbuf, len));
	if (readbuf == NULL)
	  return rt;
      }
    else
      {
	readbuf.reset(Py_None);
	Py_INCREF(readbuf.get());
      }

    gdbpy_ref<> writebuf;
    if (gdb_writebuf)
      {
	writebuf.reset(PyByteArray_FromStringAndSize (
						  (char *) gdb_writebuf, len));
	if (writebuf == NULL)
	  return rt;
      }
    else
      {
	writebuf.reset(Py_None);
	Py_INCREF(writebuf.get());
      }

    gdbpy_ref<> ret (gdb_PyObject_CallMethod (self, "to_xfer_partial",
					      "(isOOKK)", (int)object, annex,
					      readbuf.get(), writebuf.get(),
					      offset, len));

    if (ret == NULL)
      return rt;
    if (PyErr_Occurred())
      {
	if (PyErr_ExceptionMatches (py_target_xfer_eof_error))
	  {
	    PyErr_Clear();
	    rt = TARGET_XFER_EOF;
	    return rt;
	  }
	else if (PyErr_ExceptionMatches (PyExc_IOError))
	  {
	    PyErr_Clear();
	    rt = TARGET_XFER_E_IO;
	    return rt;
	  }
	else if (PyErr_ExceptionMatches (py_target_xfer_unavailable_error))
	  {
	    PyErr_Clear();
	    rt = TARGET_XFER_UNAVAILABLE;
	    *xfered_len = len;
	    return rt;
	  }
	else
	  return rt;
    }

    lret = PyLong_AsUnsignedLongLong (ret.get());
    if (PyErr_Occurred ())
      {
	PyErr_SetString(PyExc_RuntimeError,
			"to_xfer_partial callback must return long");
	return rt;
      }

    if (gdb_readbuf)
      {
	const char *str = PyByteArray_AsString (readbuf.get());
	int l = PyByteArray_Size (readbuf.get());
	memcpy (gdb_readbuf, str, l);
      }

    *xfered_len = lret;
    return TARGET_XFER_OK;
}

static enum target_xfer_status
py_target_to_xfer_partial_pyerr (struct target_ops *ops,
				 enum target_object object, const char *annex,
				 gdb_byte *gdb_readbuf,
				 const gdb_byte *gdb_writebuf,
				 ULONGEST offset, ULONGEST len,
				 ULONGEST *xfered_len)
{
  gdbpy_enter enter_py (target_gdbarch (), current_language);

  PyErr_Clear();

  enum target_xfer_status ret;
  ret = py_target_to_xfer_partial (ops, object, annex, gdb_readbuf,
				   gdb_writebuf, offset, len, xfered_len);

  if (PyErr_Occurred ())
    {
      gdb_assert(ret != TARGET_XFER_OK);
      gdbpy_print_stack();
      error (_("Error in Python while executing to_xfer_partial callback."));
    }

  return ret;
}

static const char *
py_target_to_extra_thread_info (struct target_ops *ops,
				struct thread_info *info)
{
    /* Note how we can obtain our Parent Python Object from the ops too */
    pytarget_object *target_obj = target_ops_to_target_obj(ops);
    PyObject * self = (PyObject *)target_obj;

    HasMethodOrReturnBeneath(self, to_extra_thread_info, ops, info);

    return "Linux task";
}

static const char *
py_target_to_extra_thread_info_pyerr (struct target_ops *ops,
				      struct thread_info *info)
{
  gdbpy_enter enter_py (target_gdbarch (), current_language);

  PyErr_Clear ();

  const char *ret = py_target_to_extra_thread_info (ops, info);

  if (PyErr_Occurred ())
    {
      gdbpy_print_stack();
      error (_("Error in Python while executing to_extra_thread_info callback."));
    }
  gdb_assert (ret != NULL);
  return ret;
}

static void
py_target_to_update_thread_list (struct target_ops *ops)
{
  pytarget_object *target_obj = target_ops_to_target_obj (ops);
  PyObject * self = (PyObject *) target_obj;

  HasMethodOrReturnBeneath (self, to_update_thread_list, ops);

  gdbpy_ref<> result (gdb_PyObject_CallMethod (self, "to_update_thread_list",
					       "()", NULL));
  if (result == NULL)
    return;
}

static void
py_target_to_update_thread_list_pyerr (struct target_ops *ops)
{
  gdbpy_enter enter_py (target_gdbarch (), current_language);

  PyErr_Clear ();
  py_target_to_update_thread_list (ops);

  if (PyErr_Occurred ())
    {
      gdbpy_print_stack();
      error (_("Error in Python while executing to_update_thread_list callback."));
    }
}

static int
py_target_to_thread_alive (struct target_ops *ops, ptid_t ptid)
{
  pytarget_object *target_obj = target_ops_to_target_obj (ops);
  PyObject *self = (PyObject *) target_obj;

  HasMethodOrReturnBeneath (self, to_thread_alive, ops, ptid);

  gdbpy_ref<> ptid_obj (gdbpy_create_ptid_object (ptid));
  if (ptid_obj == NULL)
    return 0;

  gdbpy_ref<> result (gdb_PyObject_CallMethod (self, "to_thread_alive", "(O)",
					       ptid_obj.get(), NULL));
  if (result == NULL)
    return 0;

  if (!PyBool_Check (result.get()))
    {
      PyErr_SetString (PyExc_RuntimeError,
		       "to_thread_alive callback must return True or False");
      return 0;
    }

  return result == Py_True;
}

static int
py_target_to_thread_alive_pyerr (struct target_ops *ops, ptid_t ptid)
{
  gdbpy_enter enter_py (get_current_arch (), current_language);

  PyErr_Clear ();

  int ret = py_target_to_thread_alive (ops, ptid);

  if (PyErr_Occurred ())
    {
      gdbpy_print_stack();
      error (_("Error in Python while executing to_thread_alive callback."));
    }

  return ret;
}

static const char *py_target_to_pid_to_str(struct target_ops *ops, ptid_t ptid)
{
  /* Note how we can obtain our Parent Python Object from the ops too */
  pytarget_object *target_obj = target_ops_to_target_obj (ops);
  PyObject *self = (PyObject *) target_obj;
  static char *static_buf;

  HasMethodOrReturnBeneath (self, to_pid_to_str, ops, ptid);

  gdbpy_ref<> ptid_obj (gdbpy_create_ptid_object (ptid));
  if (ptid_obj == NULL)
    return NULL;

  gdbpy_ref<> result (gdb_PyObject_CallMethod (self, "to_pid_to_str", "(O)",
					       ptid_obj.get(), NULL));
  if (result == NULL)
    return NULL;

  gdb::unique_xmalloc_ptr<char> ret
				= python_string_to_host_string (result.get());
  if (ret == NULL)
    return NULL;

  /* Do not remove this assignment */
  static_buf = xstrdup_realloc (ret.get(), static_buf);
  return static_buf;
}

static const char *py_target_to_pid_to_str_pyerr (struct target_ops *ops,
						  ptid_t ptid)
{
  gdbpy_enter enter_py (target_gdbarch (), current_language);

  PyErr_Clear ();

  const char *ret = py_target_to_pid_to_str (ops, ptid);

  if (PyErr_Occurred ())
    {
      gdbpy_print_stack();
      error (_("Error in Python while executing to_pid_to_str callback."));
    }

  return ret;
}


static void py_target_to_fetch_registers (struct target_ops *ops,
					  struct regcache *regcache, int reg)
{
  pytarget_object *target_obj = target_ops_to_target_obj (ops);
  PyObject * self = (PyObject *) target_obj;

  HasMethodOrReturnBeneath (self, to_fetch_registers, ops, regcache, reg);

  gdbpy_ref<> thread (gdbpy_selected_thread (NULL, NULL));
  if (thread == NULL)
    return;

  gdbpy_ref<> reg_obj (
	    register_to_register_object ((thread_object *) thread.get(), reg));
  if (reg_obj == NULL)
    return;

  gdbpy_ref<> arglist (Py_BuildValue ("(O)", reg_obj.get()));
  if (arglist == NULL)
    return;

  gdbpy_ref<> result (gdb_PyObject_CallMethod (self, "to_fetch_registers",
					       "(O)", reg_obj.get(), NULL));
}

static void py_target_to_fetch_registers_pyerr (struct target_ops *ops,
						struct regcache *regcache,
						int reg)
{
  gdbpy_enter enter_py (target_gdbarch (), current_language);

  PyErr_Clear ();

  py_target_to_fetch_registers (ops, regcache, reg);

  if (PyErr_Occurred ())
    {
      gdbpy_print_stack();
      error (_("Error in Python while executing to_fetch_registers callback."));
    }
}

static void py_target_to_prepare_to_store (struct target_ops *ops,
					   struct regcache *regcache)
{
  pytarget_object *target_obj = target_ops_to_target_obj (ops);
  PyObject * self = (PyObject *) target_obj;

  HasMethodOrReturnBeneath (self, to_prepare_to_store, ops, regcache);

  gdbpy_ref<> thread (gdbpy_selected_thread (NULL, NULL));
  if (thread == NULL)
    return;

  gdbpy_ref<> result (gdb_PyObject_CallMethod (self, "to_prepare_to_store",
					       "(O)", thread.get(), NULL));
  if (result == NULL)
    return;
}

static void py_target_to_prepare_to_store_pyerr (struct target_ops *ops,
						 struct regcache *regcache)
{
  gdbpy_enter enter_py (target_gdbarch (), current_language);

  PyErr_Clear();
  py_target_to_prepare_to_store (ops, regcache);

  if (PyErr_Occurred ())
    {
      gdbpy_print_stack();
      error (_("Error in Python while executing to_prepare_to_store callback."));
    }
}

static void py_target_to_store_registers (struct target_ops *ops,
					  struct regcache *regcache, int reg)
{
  pytarget_object *target_obj = target_ops_to_target_obj (ops);
  PyObject * self = (PyObject *) target_obj;

  HasMethodOrReturnBeneath (self, to_store_registers, ops, regcache, reg);

  gdbpy_ref<> thread (gdbpy_selected_thread (NULL, NULL));
  if (thread == NULL)
    return;

  gdbpy_ref<> reg_obj (register_to_register_object (
					(thread_object *) thread.get(), reg));
  if (reg_obj == NULL)
    return;

  gdbpy_ref<> result (gdb_PyObject_CallMethod (self, "to_store_registers",
					       "(O)", reg_obj.get(), NULL));
}

static void py_target_to_store_registers_pyerr (struct target_ops *ops,
						struct regcache *regcache,
						int reg)
{
  gdbpy_enter enter_py (target_gdbarch (), current_language);

  PyErr_Clear ();

  py_target_to_store_registers (ops, regcache, reg);

  if (PyErr_Occurred ())
    {
      gdbpy_print_stack ();
      error (_("Error in Python while executing to_store_registers callback."));
    }

}

static int
py_target_to_has_execution (struct target_ops *ops, ptid_t ptid)
{
  pytarget_object *target_obj = target_ops_to_target_obj (ops);
  PyObject * self = (PyObject *) target_obj;
  int ret = 0;

  HasMethodOrReturnBeneath (self, to_has_execution, ops, ptid);

  gdbpy_ref<> result (gdb_PyObject_CallMethod (self, "to_has_execution",
					       "((iii))", ptid.pid(),
					       ptid.lwp(), ptid.tid(), NULL));
  if (result == NULL)
    return 0;

  if (!PyBool_Check (result.get()))
    {
      PyErr_SetString (PyExc_RuntimeError,
		       "to_has_exception callback must return True or False");
      return 0;
    }

  return result == Py_True;
}

static int
py_target_to_has_execution_pyerr (struct target_ops *ops, ptid_t ptid)
{
  gdbpy_enter enter_py (target_gdbarch (), current_language);

  PyErr_Clear ();

  int ret = py_target_to_has_execution (ops, ptid);

  if (PyErr_Occurred ())
    {
      gdbpy_print_stack ();
      error (_("Error in Python while executing to_fetch_registers callback."));
    }

    return ret;
}

static int
default_true (struct target_ops *ops)
{
    return 1;
}

static void py_target_register_ops(struct target_ops * ops)
{
    if (!ops->to_shortname)
	ops->to_shortname = xstrdup (_("PythonTarget"));

    if (!ops->to_longname)
	ops->to_longname = xstrdup (_("A Python defined target layer"));

    /* Python Wrapper Calls */
    ops->to_xfer_partial = py_target_to_xfer_partial_pyerr;
    ops->to_thread_name = py_target_to_thread_name_pyerr;
    ops->to_extra_thread_info = py_target_to_extra_thread_info_pyerr;
    ops->to_update_thread_list = py_target_to_update_thread_list_pyerr;
    ops->to_thread_alive = py_target_to_thread_alive_pyerr;
    ops->to_pid_to_str = py_target_to_pid_to_str_pyerr;
    ops->to_fetch_registers = py_target_to_fetch_registers_pyerr;
    ops->to_has_execution = py_target_to_has_execution_pyerr;
    ops->to_store_registers = py_target_to_store_registers_pyerr;
    ops->to_prepare_to_store = py_target_to_prepare_to_store_pyerr;

    // This may be the only variable to specify as a parameter in __init__
    ops->to_stratum = thread_stratum;

    /* Initialise Defaults */
    ops->to_has_all_memory = default_child_has_all_memory;
    ops->to_has_memory = default_child_has_memory;
    ops->to_has_stack = default_child_has_stack;
    ops->to_has_registers = default_child_has_registers;
    default_true(ops);

    ops->to_magic = OPS_MAGIC;

    ops->to_data = &pytarget_object_type;

    /* Install any remaining operations as delegators */
    complete_target_initialization (ops);

    push_target(ops);
}




/*****************************************************************************/
/* Python Object Methods and Functionality */
/*****************************************************************************/

static void
target_dealloc (PyObject *self)
{
  ENTRY();

  // Py_DECREF (((pytarget_object *) self)->inf_obj);
  // Decremement any references taken....
  Py_TYPE (self)->tp_free (self);

  EXIT();
}

enum target_names {
    TGT_NAME,
    TGT_SHORTNAME,
    TGT_LONGNAME,
};

static PyObject *
tgt_py_get_name (PyObject *self, void * arg)
{
  enum target_names target_string = (enum target_names) (unsigned long)arg;
  pytarget_object *target_obj = (pytarget_object *) self;
  struct target_ops *ops = target_obj->ops;

  PyObject *name;

  const char *shortname;
  const char *longname;
  const char *noname = "None";

  THPY_REQUIRE_VALID (target_obj);

  shortname = ops->to_shortname;
  longname = ops->to_longname;

  if (shortname == NULL)
    shortname = noname;

  if (longname == NULL)
    longname = noname;

  switch (target_string)
    {
    default:
    case TGT_NAME:
	name = PyString_FromFormat ("%s (%s)", shortname, longname);
	break;
    case TGT_SHORTNAME:
	name = PyString_FromString (shortname);
	break;
    case TGT_LONGNAME:
	name = PyString_FromString (longname);
	break;
    }

  return name;
}

static int
tgt_py_set_name (PyObject *self, PyObject *newvalue, void * arg)
{
  enum target_names target_string = (enum target_names)(unsigned long) arg;
  pytarget_object *target_obj = (pytarget_object *) self;
  struct target_ops *ops = target_obj->ops;
  gdb::unique_xmalloc_ptr<char> name;

  THPY_REQUIRE_PYTHON_TARGET (target_obj, 0);

  THPY_REQUIRE_VALID_INT (target_obj);

  TRY
    {
      /*
       * GDB will raise an exception that we need to catch and raise as
       * a Python exception.
       * Python will raise an exception that we'll pass back to the caller.
       */
      name = python_string_to_host_string (newvalue);
    }
  CATCH (except, RETURN_MASK_ALL)
    {
      GDB_PY_SET_HANDLE_EXCEPTION (except);
    }
  END_CATCH

  /* Needs to be outside of the TRY/CATCH block */
  if (name == NULL)
    return -1;

  switch (target_string)
    {
    default:
    case TGT_NAME:
	/* No Op */
	break;
    case TGT_SHORTNAME:
	xfree ((void *)ops->to_shortname);
	ops->to_shortname = name.get();
	break;
    case TGT_LONGNAME:
	xfree ((void *)ops->to_longname);
	ops->to_longname = name.get();
	break;
    }

  return 0;
}

static PyObject *target_getconst(PyObject *_self, void *_value)
{
	return PyInt_FromLong((long)_value);
}


#define CONST_GET(x) {#x, target_getconst, NULL, #x, (void*)x}


static gdb_PyGetSetDef pytarget_object_getset[] =
{
  { "name", tgt_py_get_name, NULL,
    "The name of the target", (void*)TGT_NAME },
  { "shortname", tgt_py_get_name, tgt_py_set_name,
    "The shortname of the target", (void*)TGT_SHORTNAME },
  { "longname", tgt_py_get_name, tgt_py_set_name,
    "The longname of the target", (void*)TGT_LONGNAME },

  { "stratum", NULL, NULL, "ID of the thread, as assigned by GDB.", NULL },
CONST_GET(TARGET_OBJECT_AVR),
CONST_GET(TARGET_OBJECT_SPU),
CONST_GET(TARGET_OBJECT_MEMORY),
CONST_GET(TARGET_OBJECT_RAW_MEMORY),
CONST_GET(TARGET_OBJECT_STACK_MEMORY),
CONST_GET(TARGET_OBJECT_CODE_MEMORY),
CONST_GET(TARGET_OBJECT_UNWIND_TABLE),
CONST_GET(TARGET_OBJECT_AUXV),
CONST_GET(TARGET_OBJECT_WCOOKIE),
CONST_GET(TARGET_OBJECT_MEMORY_MAP),
CONST_GET(TARGET_OBJECT_FLASH),
CONST_GET(TARGET_OBJECT_AVAILABLE_FEATURES),
CONST_GET(TARGET_OBJECT_LIBRARIES),
CONST_GET(TARGET_OBJECT_LIBRARIES_SVR4),
CONST_GET(TARGET_OBJECT_LIBRARIES_AIX),
CONST_GET(TARGET_OBJECT_OSDATA),
CONST_GET(TARGET_OBJECT_SIGNAL_INFO),
CONST_GET(TARGET_OBJECT_THREADS),
CONST_GET(TARGET_OBJECT_STATIC_TRACE_DATA),
CONST_GET(TARGET_OBJECT_HPUX_UREGS),
CONST_GET(TARGET_OBJECT_HPUX_SOLIB_GOT),
CONST_GET(TARGET_OBJECT_TRACEFRAME_INFO),
CONST_GET(TARGET_OBJECT_FDPIC),
CONST_GET(TARGET_OBJECT_DARWIN_DYLD_INFO),
CONST_GET(TARGET_OBJECT_OPENVMS_UIB),
CONST_GET(TARGET_OBJECT_BTRACE),
CONST_GET(TARGET_OBJECT_BTRACE_CONF),
CONST_GET(TARGET_OBJECT_EXEC_FILE),
  { NULL }
};













/* Base Delegate Implementation of gdb.Target.to_thread_name */


/* We will potentially need one of these for each of the Target API's ...
 * The target-delegate.c module is autogenerated, and I suspect we
 * could do the same here!
 */

static PyObject *
tgtpy_default_to_thread_name (PyObject *self, PyObject *args)
{
  pytarget_object *target_obj = (pytarget_object *) self;
  PyObject * ThreadName;

  ENTRY();

  ThreadName = PyString_FromString ("NoThreadName");

  EXIT();

  return ThreadName;
}

static PyMethodDef pytarget_object_methods[] =
{
  { "to_thread_name_int", tgtpy_default_to_thread_name, METH_VARARGS | METH_KEYWORDS,
    "to_thread_name (thread_info) -> String.\n\
Return string name representation of the given thread." },



  { NULL }
};


static int
target_init (PyObject *self, PyObject *args, PyObject *kw)
{
    pytarget_object *target_obj = (pytarget_object *) self;

    ENTRY();

    TRY
      {
	target_obj->ops = &target_obj->python_ops;
	py_target_register_ops (&target_obj->python_ops);
	init_thread_list ();
      }
    CATCH (except, RETURN_MASK_ALL)
      {
	GDB_PY_SET_HANDLE_EXCEPTION (except);
      }
    END_CATCH

    /* We have registered our structure on the target stack
     * Our object needs to persist while it is registered
     */
    Py_INCREF (self);

    EXIT();

    return 0;
}



int
gdbpy_initialize_target (void)
{

  ENTRY();

  /* Allow us to create instantiations of this class ... */
  pytarget_object_type.tp_new = PyType_GenericNew;

  if (PyType_Ready (&pytarget_object_type) < 0)
    return -1;

  py_target_xfer_eof_error = PyErr_NewException ("gdb.TargetXferEOF",
						 PyExc_EOFError, NULL);
  if (!py_target_xfer_eof_error)
    goto fail;

  if (gdb_pymodule_addobject (gdb_module, "TargetXferEOF",
			      py_target_xfer_eof_error) < 0)
    goto fail;

  py_target_xfer_unavailable_error = PyErr_NewException (
						    "gdb.TargetXferUnavailable",
						    PyExc_LookupError, NULL);
  if (!py_target_xfer_unavailable_error)
    goto fail;

  if (gdb_pymodule_addobject (gdb_module, "TargetXferUnavailable",
			      py_target_xfer_unavailable_error) < 0)
    goto fail;

  EXIT ();

  return gdb_pymodule_addobject (gdb_module, "Target",
				 (PyObject *) &pytarget_object_type);
fail:
  gdbpy_print_stack();
  EXIT ();
  return -1;
}






PyTypeObject pytarget_object_type =
{
  PyVarObject_HEAD_INIT (NULL, 0)
  "gdb.Target",			  /*tp_name*/
  sizeof (pytarget_object),	  /*tp_basicsize*/
  0,				  /*tp_itemsize*/
  target_dealloc,		  /*tp_dealloc*/
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
  0,				  /*tp_str*/
  0,				  /*tp_getattro*/
  0,				  /*tp_setattro*/
  0,				  /*tp_as_buffer*/
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,  /*tp_flags*/
  "GDB target object",		  /* tp_doc */
  0,				  /* tp_traverse */
  0,				  /* tp_clear */
  0,				  /* tp_richcompare */
  0,				  /* tp_weaklistoffset */
  0,				  /* tp_iter */
  0,				  /* tp_iternext */
  pytarget_object_methods,	  /* tp_methods */
  0,				  /* tp_members */
  pytarget_object_getset,		  /* tp_getset */
  0,				  /* tp_base */
  0,				  /* tp_dict */
  0,				  /* tp_descr_get */
  0,				  /* tp_descr_set */
  0,				  /* tp_dictoffset */
  target_init,			  /* tp_init */
  0				  /* tp_alloc */
};

PyObject *
gdbpy_current_target (PyObject *self, PyObject *args)
{
  struct target_ops *ops = current_target.beneath;
  pytarget_object *obj = target_ops_to_target_obj(ops);

  if (obj->ops->to_data == &pytarget_object_type)
	  Py_INCREF(obj);

  return (PyObject *)obj;
}
