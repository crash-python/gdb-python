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
#include "process-stratum-target.h"

static PyObject *py_target_xfer_eof_error;
static PyObject *py_target_xfer_unavailable_error;

extern PyTypeObject target_object_type
    CPYCHECKER_TYPE_OBJECT_FOR_TYPEDEF ("target_object");

class python_target final : public process_stratum_target
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

  void open (const char *name, int from_tty);

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
  bool has_execution (ptid_t ptid) override;
  void store_registers (struct regcache *regcache, int reg) override;
  void prepare_to_store (struct regcache *regcache) override;

  int set_shortname (PyObject *name);
  int set_longname (PyObject *name);
  int set_docstring (PyObject *name);

  PyObject *get_owner(void);

  void register_target (void);
  void unregister_target (void);
private:
  target_info _info;
  PyObject *owner;
  bool registered;
};

typedef struct
{
  PyObject_HEAD

  target_ops *ops;
  bool native_target;
  bool registered;
} pytarget_object;

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

static char scratch_buf[4096];

#define pytarget_has_op(op)					\
	PyObject_HasAttrString (owner, #op)


static python_target *
get_writable_python_target (pytarget_object *target_obj)
{
  if (target_obj->native_target)
    {
      PyErr_SetString (PyExc_AttributeError,
                       _("Property is read-only on native targets."));
      return NULL;
    }

  if (target_obj->registered)
    {
      PyErr_SetString (PyExc_AttributeError,
                       _("Property is read-only on registered targets."));
      return NULL;
    }

  return dynamic_cast<python_target *>(target_obj->ops);
}

void
python_target::open (const char *argstring, int from_tty)
{
  target_ops *ops;
  PyObject *callback = NULL;
  PyObject *arglist = NULL;
  PyObject *ret = NULL;
  bool stacked = false;

  gdbpy_enter enter_py (target_gdbarch (), current_language);

  if (!pytarget_has_op (open))
    error (_("Python target has no open callback"));

  ops = find_target_at (thread_stratum);
  if (ops && !have_inferiors ())
    {
      if (from_tty && !query (_("Another target is open.  Close it?")))
	error (_("Refusing to replace other target."));
    }

  if (pytarget_has_op(stacked_target))
    {
      callback = PyObject_GetAttrString (owner, "stacked_target");
      if (!callback)
	goto error;

      ret = gdb_PyObject_CallFunction (callback, "()", NULL);
      if (!ret)
	goto error;

      if (!PyBool_Check (ret))
	{
	  PyErr_SetString (PyExc_RuntimeError,
			   "stacked_target callback must return True or False");
	  goto error;
	}
	stacked = ret == Py_True;
	Py_XDECREF (ret);
	ret = NULL;
    }

  if (!stacked)
    {
      target_preopen (from_tty);
      reopen_exec_file ();
    }
  registers_changed ();

  callback = PyObject_GetAttrString (owner, "open");
  if (!callback)
    goto error;

  if (!argstring)
    argstring = "";

  arglist = Py_BuildValue ("(si)", argstring, from_tty);
  if (!arglist)
    goto error;

  ret = PyObject_Call(callback, arglist, NULL);
  if (!ret)
    {
      gdbpy_handle_exception();
      PyErr_Clear();
    }
  else
    {
      Py_INCREF (owner);
      target_ops_up target_holder (this);
      push_target (std::move (target_holder));
      reread_symbols ();
      init_thread_list ();
    }

error:
  Py_XDECREF (callback);
  Py_XDECREF (arglist);
  Py_XDECREF (ret);

  if (PyErr_Occurred ())
    {
      gdbpy_print_stack ();
      error (_("Error in Python while executing open callback."));
    }
}

void
python_target::close (void)
{
  PyObject *callback = NULL;
  PyObject *ret = NULL;

  gdbpy_enter enter_py (target_gdbarch (), current_language);

  pop_all_targets_at_and_above (thread_stratum);

  if (!pytarget_has_op (close))
    error (_("Python target has no close callback"));

  inferior_ptid = null_ptid;
  discard_all_inferiors ();

  trace_reset_local_state ();

  callback = PyObject_GetAttrString (owner, "close");
  if (!callback)
    goto error;

  ret = gdb_PyObject_CallFunction (callback, "()", NULL);
  if (!ret)
    goto error;

error:
  Py_XDECREF (callback);
  Py_XDECREF (ret);

  if (PyErr_Occurred ())
    {
      gdbpy_print_stack ();
      error (_("Error in Python while executing close callback."));
    }
}

const char *
python_target::thread_name (struct thread_info *info)
{
    PyObject *arglist  = NULL;
    PyObject *result   = NULL;
    PyObject *callback = NULL;
    PyObject *thread   = NULL;

    gdb::unique_xmalloc_ptr<char> host_string_holder;
    char *host_string = NULL;

    gdbpy_enter enter_py (target_gdbarch (), current_language);
    if (!pytarget_has_op (info))
      return process_stratum_target::thread_name (info);

    callback = PyObject_GetAttrString (owner, "thread_name");
    if (!callback)
      goto error;

    /* (re-)initialise the static string before use in case of error */
    scratch_buf[0] = '\0';

    thread = gdbpy_selected_thread (NULL, NULL);
    if (!thread)
      goto error;

    /* Time to call the callback */
    arglist = Py_BuildValue ("(O)", thread);
    if (!arglist)
      goto error;

    result = PyObject_Call (callback, arglist, NULL);
    if (!result)
      goto error;

    /*
     * GDB will raise an exception that the caller will catch.
     * Python will raise an exception and return NULL.
     */
    host_string_holder = python_string_to_host_string (result);
    if (!host_string_holder)
      goto error;

    host_string = host_string_holder.get ();

    strncpy (scratch_buf, host_string, sizeof (scratch_buf) - 1);
    scratch_buf[sizeof (scratch_buf) - 1] = '\0';

error:
    Py_XDECREF (result);
    Py_XDECREF (arglist);
    Py_XDECREF (thread);
    Py_XDECREF (callback);

    if (PyErr_Occurred ())
      {
	gdbpy_print_stack ();
	error (_("Error in Python while executing thread_name callback."));
      }

    return scratch_buf;
}

enum target_xfer_status
python_target::xfer_partial (enum target_object object, const char *annex,
			   gdb_byte *gdb_readbuf, const gdb_byte *gdb_writebuf,
			   ULONGEST offset, ULONGEST len, ULONGEST *xfered_len)
{
    PyObject *callback  = NULL;
    PyObject *readbuf   = NULL;
    PyObject *writebuf  = NULL;
    PyObject *arglist   = NULL;
    PyObject *ret       = NULL;

    enum target_xfer_status rt = TARGET_XFER_E_IO;
    unsigned long lret;

    gdbpy_enter enter_py (target_gdbarch (), current_language);

    if (!pytarget_has_op (xfer_partial))
      return process_stratum_target::xfer_partial (object, annex, gdb_readbuf,
						   gdb_writebuf, offset,
						   len, xfered_len);

    callback = PyObject_GetAttrString (owner, "xfer_partial");
    if (!callback)
      goto error;

    if (gdb_readbuf)
      {
	readbuf = PyByteArray_FromStringAndSize ((char *) gdb_readbuf, len);
	if (!readbuf)
	  goto error;
      }
    else
      {
	readbuf = Py_None;
	Py_INCREF (Py_None);
      }

    if (gdb_writebuf)
      {
	writebuf = PyByteArray_FromStringAndSize ((char *) gdb_writebuf, len);
	if (!writebuf)
	  goto error;
      }
    else
      {
	writebuf = Py_None;
	Py_INCREF (Py_None);
      }

    arglist = Py_BuildValue ("(isOOKK)", (int)object, annex, readbuf,
                             writebuf, offset, len);
    if (!arglist)
      goto error;

    ret = PyObject_Call(callback, arglist, NULL);
    if (PyErr_Occurred ())
      {
	if (PyErr_ExceptionMatches (py_target_xfer_eof_error))
	  {
	    PyErr_Clear ();
	    rt = TARGET_XFER_EOF;
	    goto error;
	  }
	else if (PyErr_ExceptionMatches (PyExc_IOError))
	  {
	    PyErr_Clear ();
	    rt = TARGET_XFER_E_IO;
	    goto error;
	  }
	else if (PyErr_ExceptionMatches (py_target_xfer_unavailable_error))
	  {
	    PyErr_Clear ();
	    rt = TARGET_XFER_UNAVAILABLE;
	    *xfered_len = len;
	    goto error;
	  }
	else
	  goto error;
    }

    lret = PyLong_AsUnsignedLongLong (ret);
    if (gdb_readbuf)
      {
	const char *str = PyByteArray_AsString (readbuf);
	int l = PyByteArray_Size (readbuf);
	memcpy (gdb_readbuf, str, l);
      }

    rt = TARGET_XFER_OK;
    *xfered_len = lret;

error:
    Py_XDECREF (ret);
    Py_XDECREF (writebuf);
    Py_XDECREF (readbuf);
    Py_XDECREF (callback);
    Py_XDECREF (arglist);

    if (PyErr_Occurred ())
      {
	gdbpy_print_stack ();
	error (_("Error in Python while executing xfer_partial callback."));
      }

    return rt;
}

const char *
python_target::extra_thread_info (struct thread_info *info)
{
  PyObject *callback = NULL;
  PyObject *arglist  = NULL;
  PyObject *result   = NULL;

  gdb::unique_xmalloc_ptr<char> host_string_holder;
  char *host_string = NULL;

  scratch_buf[0] = '\0';

  gdbpy_enter enter_py (target_gdbarch (), current_language);

  if (!pytarget_has_op (extra_thread_info))
    return NULL;

  callback = PyObject_GetAttrString (owner, "extra_thread_info");
  if (!callback)
    goto error;

  arglist = Py_BuildValue ("()");
  if (!arglist)
    goto error;

  result = PyObject_Call (callback, arglist, NULL);
  if (!result)
    goto error;

  host_string_holder = python_string_to_host_string (result);
  if (!host_string_holder)
    goto error;

  host_string = host_string_holder.get ();
  strncpy (scratch_buf, host_string, sizeof (scratch_buf) - 1);
  scratch_buf[sizeof (scratch_buf) - 1] = '\0';

error:
  Py_XDECREF (result);
  Py_XDECREF (arglist);
  Py_XDECREF (callback);

  if (PyErr_Occurred ())
    {
      gdbpy_print_stack ();
      error (_("Error in Python while executing update_thread_list callback."));
    }

    return scratch_buf;
}

void
python_target::update_thread_list (void)
{
  PyObject *callback = NULL;
  PyObject *arglist  = NULL;
  PyObject *result   = NULL;

  gdbpy_enter enter_py (target_gdbarch (), current_language);

  if (!pytarget_has_op (update_thread_list))
    return;

  callback = PyObject_GetAttrString (owner, "update_thread_list");
  if (!callback)
    goto error;

  arglist = Py_BuildValue ("()");
  if (!arglist)
    goto error;

  result = PyObject_Call (callback, arglist, NULL);
  if (!result)
    goto error;

error:
  Py_XDECREF (result);
  Py_XDECREF (arglist);
  Py_XDECREF (callback);

  if (PyErr_Occurred ())
    {
      gdbpy_print_stack ();
      error (_("Error in Python while executing update_thread_list callback."));
    }

}

bool
python_target::thread_alive (ptid_t ptid)
{
  PyObject *ptid_obj = NULL;
  PyObject *arglist  = NULL;
  PyObject *result   = NULL;
  PyObject *callback = NULL;

  long ret = 0;

  gdbpy_enter enter_py (target_gdbarch (), current_language);

  if (!pytarget_has_op (thread_alive)) {
    printf("target doesn't have thread_alive\n");
    return false;
  }

  callback = PyObject_GetAttrString (owner, "thread_alive");
  if (!callback)
    goto error;

  ptid_obj = gdbpy_create_ptid_object (ptid);
  if (!ptid_obj)
    goto error;

  arglist = Py_BuildValue ("(O)", ptid_obj);
  if (!arglist)
    goto error;

  result = PyObject_Call (callback, arglist, NULL);
  if (!result)
    goto error;

  ret = PyInt_AsLong (result);

error:
  Py_XDECREF (result);
  Py_XDECREF (arglist);
  Py_XDECREF (ptid_obj);
  Py_XDECREF (callback);

  if (PyErr_Occurred ())
    {
      gdbpy_print_stack ();
      error (_("Error in Python while executing thread_alive callback."));
    }

  return ret;
}

std::string
python_target::pid_to_str (ptid_t ptid)
{
  PyObject *ptid_obj = NULL;
  PyObject *arglist  = NULL;
  PyObject *result   = NULL;
  PyObject *callback = NULL;

  gdb::unique_xmalloc_ptr<char> host_string_holder;
  char *host_string = NULL;

  scratch_buf[0] = '\0';

  gdbpy_enter enter_py (target_gdbarch (), current_language);

  if (!pytarget_has_op (pid_to_str))
    return process_stratum_target::pid_to_str (ptid);

  callback = PyObject_GetAttrString (owner, "pid_to_str");
  if (!callback)
    goto error;

  ptid_obj = gdbpy_create_ptid_object (ptid);
  if (!ptid_obj)
    goto error;

  arglist = Py_BuildValue ("(O)", ptid_obj);
  if (!arglist)
    goto error;

  result = PyObject_Call (callback, arglist, NULL);

  if (!result)
    goto error;

  host_string_holder = python_string_to_host_string (result);
  if (!host_string_holder)
    goto error;

  host_string = host_string_holder.get ();

  strncpy (scratch_buf, host_string, sizeof (scratch_buf) - 1);
  scratch_buf[sizeof (scratch_buf) - 1] = '\0';

error:
  Py_XDECREF (arglist);
  Py_XDECREF (ptid_obj);
  Py_XDECREF (callback);
  Py_XDECREF (result);

  if (PyErr_Occurred ())
    {
      gdbpy_print_stack ();
      error (_("Error in Python while executing pid_to_str callback."));
    }

  return scratch_buf;
}

void
python_target::fetch_registers (struct regcache *regcache, int reg)
{
  PyObject *arglist  = NULL;
  PyObject *result   = NULL;
  PyObject *callback = NULL;
  PyObject *reg_obj  = NULL;
  PyObject *thread = NULL;

  gdbpy_enter enter_py (target_gdbarch (), current_language);

  if (!pytarget_has_op (fetch_registers)) {
    printf("target has no fetch_registers\n");
    return;
  }

  callback = PyObject_GetAttrString (owner, "fetch_registers");
  if (!callback)
    goto error;

  thread = gdbpy_selected_thread (NULL, NULL);
  if (!thread)
    goto error;

  reg_obj = register_to_register_object ((thread_object *) thread, reg);
  if (!reg_obj)
    goto error;

  arglist = Py_BuildValue ("(O)", reg_obj);
  if (!arglist)
    goto error;

  result = PyObject_Call (callback, arglist, NULL);
  if (!result)
    goto error;

error:
  Py_XDECREF (result);
  Py_XDECREF (arglist);
  Py_XDECREF (reg_obj);
  Py_XDECREF (thread);
  Py_XDECREF (callback);

  if (PyErr_Occurred ())
    {
      gdbpy_print_stack ();
      error (_("Error in Python while executing fetch_registers callback."));
    }

}

void
python_target::prepare_to_store (struct regcache *regcache)
{
  PyObject *arglist  = NULL;
  PyObject *result   = NULL;
  PyObject *callback = NULL;
  PyObject *thread = NULL;

  gdbpy_enter enter_py (target_gdbarch (), current_language);
  if (!pytarget_has_op (prepare_to_store))
    return;

  callback = PyObject_GetAttrString (owner, "prepare_to_store");
  if (!callback)
    goto error;

  thread = gdbpy_selected_thread (NULL, NULL);
  if (!thread)
    goto error;

  arglist = Py_BuildValue ("(O)", thread);
  if (!arglist)
    goto error;

  result = PyObject_Call (callback, arglist, NULL);
  if (!result)
    goto error;

error:
  Py_XDECREF (result);
  Py_XDECREF (arglist);
  Py_XDECREF (thread);
  Py_XDECREF (callback);

  if (PyErr_Occurred ())
    {
      gdbpy_print_stack ();
      error (_("Error in Python while executing prepare_to_store callback."));
    }
}

void
python_target::store_registers (struct regcache *regcache, int reg)
{
  PyObject *arglist  = NULL;
  PyObject *result   = NULL;
  PyObject *callback = NULL;
  PyObject *reg_obj  = NULL;
  PyObject *thread = NULL;

  gdbpy_enter enter_py (target_gdbarch (), current_language);

  if (!pytarget_has_op (store_registers))
    return;

  callback = PyObject_GetAttrString (owner, "store_registers");
  if (!callback)
    goto error;

  thread = gdbpy_selected_thread (NULL, NULL);
  if (!thread)
    goto error;

  reg_obj = register_to_register_object ((thread_object *) thread, reg);
  if (!reg_obj)
    goto error;

  arglist = Py_BuildValue ("(O)", reg_obj);
  if (!arglist)
    goto error;

  result = PyObject_Call (callback, arglist, NULL);
  if (!result)
    goto error;

error:
  Py_XDECREF (result);
  Py_XDECREF (arglist);
  Py_XDECREF (reg_obj);
  Py_XDECREF (thread);
  Py_XDECREF (callback);

  if (PyErr_Occurred ())
    {
      gdbpy_print_stack ();
      error (_("Error in Python while executing store_registers callback."));
    }
}

bool
python_target::has_execution (ptid_t ptid)
{
  PyObject *arglist  = NULL;
  PyObject *result   = NULL;
  PyObject *callback = NULL;

  int ret = 0;

  gdbpy_enter enter_py (target_gdbarch (), current_language);
  if (!pytarget_has_op (has_execution))
    return process_stratum_target::has_execution (ptid);

  callback = PyObject_GetAttrString (owner, "has_execution");
  if (!callback)
    goto error;

  arglist = Py_BuildValue ("((iii))", ptid.pid (), ptid.lwp (), ptid.tid ());
  if (!arglist)
    goto error;

  result = PyObject_Call (callback, arglist, NULL);
  if (!result)
    goto error;

  if (!PyBool_Check (result))
    {
      PyErr_SetString (PyExc_RuntimeError,
		       "has_exception callback must return True or False");
      goto error;
    }

  ret = (result == Py_True);

error:
  Py_XDECREF (result);
  Py_XDECREF (arglist);
  Py_XDECREF (callback);

  if (PyErr_Occurred ())
    {
      gdbpy_print_stack ();
      error (_("Error in Python while executing has_execution callback."));
    }

  return ret;
}

int
python_target::set_shortname (PyObject *name)
{
  gdb::unique_xmalloc_ptr<char> name_holder;

  if (registered) {
    PyErr_SetString (PyExc_RuntimeError,
		     _("Cannot set name on registered Target."));
    return -1;
  }

  name_holder = python_string_to_host_string (name);
  if (!name_holder)
    return -1;

  _info.shortname = xstrdup (name_holder.get ());

  return 0;
}

int
python_target::set_longname (PyObject *name)
{
  gdb::unique_xmalloc_ptr<char> name_holder;

  if (registered) {
    PyErr_SetString (PyExc_RuntimeError,
		     _("Cannot set name on registered Target."));
    return -1;
  }

  name_holder = python_string_to_host_string (name);
  if (!name_holder)
    return -1;

  _info.longname = xstrdup (name_holder.get ());

  return 0;
}

int
python_target::set_docstring (PyObject *name)
{
  gdb::unique_xmalloc_ptr<char> name_holder;

  if (registered) {
    PyErr_SetString (PyExc_RuntimeError,
		     _("Cannot set docstring on registered Target."));
    return -1;
  }

  name_holder = python_string_to_host_string (name);
  if (!name_holder)
    return -1;

  _info.doc = xstrdup (name_holder.get ());

  return 0;
}

python_target *registered_target;

void
pytarget_open (const char *args, int from_tty)
{
  registered_target->open (args, from_tty);
}

void
python_target::register_target (void)
{
  if (!_info.shortname)
    {
      PyErr_SetString (PyExc_RuntimeError,
		       "Cannot register nameless target.");
      return;
    }

  if (registered_target) {
      PyErr_SetString (PyExc_RuntimeError,
		       "This implementation only supports one python target at a time");
      return;
  }

  if (!_info.longname)
    {
      _info.longname = xstrdup (_info.shortname);
    }

  if (!_info.doc)
    {
      _info.doc = xstrdup (_info.longname);
    }

  registered_target = this;
  registered = true;

  add_target (info (), pytarget_open, NULL);
}

void
python_target::unregister_target (void)
{
  if (!registered)
    error (_("Target is not registered."));
  delete_target (info (), pytarget_open);
  registered_target = NULL;

  registered = false;
}

PyObject *
python_target::get_owner (void)
{
  Py_INCREF(owner);
  return owner;
}

/*****************************************************************************/
/* Python Object Methods and Functionality */
/*****************************************************************************/

static void
target_dealloc (PyObject *owner)
{
  pytarget_object *obj = (pytarget_object *)owner;
  ENTRY ();

  if (!obj->native_target)
    delete obj->ops;
  obj->ops = NULL;

  // Py_DECREF (((pytarget_object *) owner)->inf_obj);
  // Decremement any references taken....
  Py_TYPE (owner)->tp_free (owner);

  EXIT ();
}

static int
tgt_py_set_shortname (PyObject *owner, PyObject *name, void * arg)
{
  pytarget_object *target_obj = (pytarget_object *) owner;
  python_target *target = get_writable_python_target (target_obj);

  if (!target)
    return -1;

  return target->set_shortname (name);
}

static int
tgt_py_set_longname (PyObject *owner, PyObject *name, void * arg)
{
  pytarget_object *target_obj = (pytarget_object *) owner;
  python_target *target = get_writable_python_target (target_obj);

  if (!target)
    return -1;

  return target->set_longname (name);
}

static int
tgt_py_set_docstring (PyObject *owner, PyObject *name, void * arg)
{
  pytarget_object *target_obj = (pytarget_object *) owner;
  python_target *target = get_writable_python_target (target_obj);

  if (!target)
    return -1;

  return target->set_docstring (name);
}

static PyObject *
tgt_py_get_name (PyObject *owner, void * arg)
{
  pytarget_object *target_obj = (pytarget_object *) owner;
  return PyString_FromFormat ("%s (%s)",
			      target_obj->ops->shortname (),
			      target_obj->ops->longname ());
}

static PyObject *
tgt_py_get_shortname (PyObject *owner, void * arg)
{
  pytarget_object *target_obj = (pytarget_object *) owner;
  return PyString_FromString (target_obj->ops->shortname ());
}

static PyObject *
tgt_py_get_longname (PyObject *owner, void * arg)
{
  pytarget_object *target_obj = (pytarget_object *) owner;
  return PyString_FromString (target_obj->ops->longname ());
}

static PyObject *
tgt_py_get_docstring (PyObject *owner, void * arg)
{
  pytarget_object *target_obj = (pytarget_object *) owner;
  return PyString_FromString (target_obj->ops->info ().doc);
}

static PyObject *
tgt_py_get_stratum (PyObject *owner, void * arg)
{
  pytarget_object *target_obj = (pytarget_object *) owner;
  return PyInt_FromLong (target_obj->ops->stratum());
}

static PyObject *
tgt_py_get_arch (PyObject *owner, void *arg)
{
  return gdbarch_to_arch_object (target_gdbarch ());
}

static PyObject *target_getconst (PyObject *_owner, void *_value)
{
	return PyInt_FromLong ((long)_value);
}

#define CONST_GET(x) {#x, target_getconst, NULL, #x, (void*)x}

static gdb_PyGetSetDef pytarget_object_getset[] =
{
  { "name", tgt_py_get_name, NULL, "The name of the target", NULL },
  { "shortname", tgt_py_get_shortname, tgt_py_set_shortname,
    "The shortname of the target", NULL },
  { "longname", tgt_py_get_longname, tgt_py_set_longname,
    "The longname of the target", NULL },
  { "docstring", tgt_py_get_docstring, tgt_py_set_docstring,
    "The docstring of the target", NULL },
  { "stratum", tgt_py_get_stratum, NULL, "The stratum of the target.", NULL },
  { "arch", tgt_py_get_arch, NULL, "The architecture of the target.", NULL },
  CONST_GET(TARGET_OBJECT_AVR),
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
  CONST_GET(TARGET_OBJECT_TRACEFRAME_INFO),
  CONST_GET(TARGET_OBJECT_FDPIC),
  CONST_GET(TARGET_OBJECT_DARWIN_DYLD_INFO),
  CONST_GET(TARGET_OBJECT_OPENVMS_UIB),
  CONST_GET(TARGET_OBJECT_BTRACE),
  CONST_GET(TARGET_OBJECT_BTRACE_CONF),
  CONST_GET(TARGET_OBJECT_EXEC_FILE),
  CONST_GET(TARGET_OBJECT_FREEBSD_VMMAP),
  CONST_GET(TARGET_OBJECT_FREEBSD_PS_STRINGS),

  { NULL }
};

static PyObject *
pytarget_register_target(PyObject *object, PyObject *unused)
{
  pytarget_object *owner = (pytarget_object *) object;

  if (owner->native_target)
    {
      PyErr_SetString (PyExc_AttributeError,
                             _("Native targets cannot be registered."));
      return NULL;
    }

  python_target *target = dynamic_cast<python_target *>(owner->ops);

  PyErr_Clear();
  target->register_target();

  if (PyErr_Occurred ())
    return NULL;

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
pytarget_unregister_target (PyObject *object, PyObject *unused)
{
  pytarget_object *owner = (pytarget_object *) object;

  if (owner->native_target)
    {
      PyErr_SetString (PyExc_AttributeError,
                             _("Native targets cannot be unregistered."));
      return NULL;
    }

  python_target *target = dynamic_cast<python_target *>(owner->ops);
  try
    {
      target->unregister_target ();
    }
  catch (const gdb_exception &except)
    {
      GDB_PY_HANDLE_EXCEPTION (except);
    }

  Py_INCREF (Py_None);
  return Py_None;
}


static PyMethodDef pytarget_object_methods[] =
{
  { "register", pytarget_register_target, METH_NOARGS,
    "register ()\nRegister this target for use with GDB." },
  { "unregister", pytarget_unregister_target, METH_NOARGS,
    "unregister ()\nUnregister this target for use with GDB." },
  { NULL }
};


static PyObject *
pytarget_new (PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  ENTRY ();

  PyObject *self = type->tp_alloc (type, 0);

  if (self)
    {
      try
	{
	  pytarget_object *target_obj = (pytarget_object *)self;
	  target_obj->ops = new python_target (self);
	  target_obj->native_target = false;
	  target_obj->registered = false;
	}
      catch (const gdb_exception &except)
	{
	  Py_DECREF (self);
	  GDB_PY_HANDLE_EXCEPTION (except);
	}
    }

  EXIT ();

  return self;
}

static PyObject *
pytarget_from_native (struct target_ops *target)
{
  PyObject *self = target_object_type.tp_alloc (&target_object_type, 0);

  if (self)
    {
      try
        {
          pytarget_object *target_obj = (pytarget_object *)self;
          target_obj->ops = target;
          target_obj->native_target = true;
          target_obj->registered = true;
        }
      catch (const gdb_exception &except)
        {
          Py_DECREF (self);
          GDB_PY_HANDLE_EXCEPTION (except);
        }
    }

    return self;
}

int
gdbpy_initialize_target (void)
{

  ENTRY ();

  /* Allow us to create instantiations of this class ... */
  target_object_type.tp_new = pytarget_new;

  if (PyType_Ready (&target_object_type) < 0)
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
				 (PyObject *) &target_object_type);
fail:
  gdbpy_print_stack ();
  EXIT ();
  return -1;
}

PyTypeObject target_object_type =
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
  0,				  /* tp_init */
  0,				  /* tp_alloc */
  pytarget_new,			  /* tp_new */
};

PyObject *
gdbpy_current_target (PyObject *self, PyObject *args)
{
  PyObject *target_obj = NULL;
  target_ops *target = current_top_target ();

  python_target *pytarget = dynamic_cast<python_target *>(target);
  if (pytarget)
    {
      target_obj = pytarget->get_owner();
    }
  else
    {
      target_obj = pytarget_from_native (target);
    }

  return target_obj;
}
