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
#include "user-regs.h"
#include "py-target.h"

static PyObject *py_target_xfer_eof_error;
static PyObject *py_target_xfer_unavailable_error;

struct pytarget_thread_info : public private_thread_info
{
  char *thread_name;
  PyObject *thread_info;
};

static pytarget_thread_info *
get_pytarget_thread_info (thread_info *thread)
{
  return static_cast<pytarget_thread_info *> (thread->priv.get ());
}

/*****************************************************************************
 *
 * Target Operation Python Bindings
 *
 * These bindings map from the target_ops structure to the python object,
 * and call into any functions provided - or fall back to delegating to the
 * operations from beneath
 *
 *****************************************************************************/

#define pytarget_has_op_name(name)      PyObject_HasAttrString (owner, (name))
#define pytarget_has_op()               pytarget_has_op_name(__FUNCTION__)

#define pytarget_get_op_name(name)      PyObject_GetAttrString (owner, (name))
#define pytarget_get_op()               pytarget_get_op_name(__FUNCTION__)

#define PYTARGET_REQUIRE_CALLBACK()                                     \
do {                                                                    \
  if (!pytarget_has_op())                                               \
    {                                                                   \
      error (_("Python target has no %s callback"), __FUNCTION__);      \
      return;                                                           \
    }                                                                   \
} while (0)

#define PYTARGET_REQUIRE_CALLBACK_RET(retval)                           \
do {                                                                    \
  if (!pytarget_has_op())                                               \
    {                                                                   \
      error (_("Python target has no %s callback"), __FUNCTION__);      \
      return (retval);                                                  \
    }                                                                   \
} while (0)

static void
gdbpy_ignore_result_name(const char *function, gdbpy_ref<> &result)
{
  if (result.get () != Py_None)
    {
      PyErr_Format(PyExc_ValueError, "`%s' callback must return None.",
		   function);
      gdbpy_handle_exception ();
    }
}

#define gdbpy_ignore_result(result)                                     \
        gdbpy_ignore_result_name(__FUNCTION__, (result))

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
  gdbpy_enter enter_py (target_gdbarch (), current_language);

  PyObject *py_from_tty = from_tty ? Py_True : Py_False;

  gdbpy_ref<> ret (PyObject_CallMethod (owner, "open", "sO", argstring, py_from_tty));
  if (ret == NULL)
    gdbpy_handle_exception ();
}

void
python_target::close (void)
{
  gdbpy_enter enter_py (target_gdbarch (), current_language);

  pop_all_targets_at_and_above (thread_stratum);

  PYTARGET_REQUIRE_CALLBACK();

  inferior_ptid = null_ptid;
  exit_inferior_silent (current_inferior ());

  trace_reset_local_state ();

  gdbpy_ref<> callback (pytarget_get_op());
  if (callback == NULL)
    gdbpy_handle_exception ();

  gdbpy_ref<> ret (gdb_PyObject_CallFunction (callback.get (), "()", NULL));
  if (ret == NULL)
    gdbpy_handle_exception ();
}

const char *
python_target::thread_name (struct thread_info *info)
{
  gdb::unique_xmalloc_ptr<char> host_string;

  gdbpy_enter enter_py (target_gdbarch (), current_language);

  if (!pytarget_has_op ())
    return beneath ()->thread_name (info);

  struct pytarget_thread_info *th = get_pytarget_thread_info (info);

  gdbpy_ref<> callback (pytarget_get_op ());
  if (callback == NULL)
    gdbpy_handle_exception ();

  gdbpy_ref<> thread (gdbpy_selected_thread (NULL, NULL));
  if (thread == NULL)
    gdbpy_handle_exception ();

  gdbpy_ref<> arglist (Py_BuildValue ("(O)", thread.get ()));
  if (arglist == NULL)
    gdbpy_handle_exception ();

  gdbpy_ref<> result(PyObject_Call (callback.get (), arglist.get (), NULL));
  if (result == NULL)
    gdbpy_handle_exception ();

  if (!PyUnicode_Check (result.get ()))
    {
      PyErr_Format(PyExc_TypeError, "`%s' callback must return `str'",
                   __FUNCTION__);
      gdbpy_handle_exception ();
    }

  host_string = python_string_to_host_string (result.get ());
  if (host_string == NULL)
    gdbpy_handle_exception ();

  if (th->thread_name)
    xfree (th->thread_name);

  th->thread_name = xstrdup (host_string.get ());
  return th->thread_name;
}

enum target_xfer_status
python_target::xfer_partial (enum target_object object, const char *annex,
                             gdb_byte *gdb_readbuf,
                             const gdb_byte *gdb_writebuf,
			     ULONGEST offset,
                             ULONGEST len, ULONGEST *xfered_len)
{
    PyObject *obj;
    unsigned long lret;

    gdbpy_enter enter_py (target_gdbarch (), current_language);

    if (!pytarget_has_op ())
      return beneath ()->xfer_partial (object, annex, gdb_readbuf,
                                       gdb_writebuf, offset, len, xfered_len);

    gdbpy_ref<> callback(PyObject_GetAttrString (owner, "xfer_partial"));
    if (callback == NULL)
      gdbpy_handle_exception ();

    gdbpy_ref<> readbuf;
    if (gdb_readbuf)
      {
	char *buf = reinterpret_cast<char *>(gdb_readbuf);
	obj = PyMemoryView_FromMemory(buf, len, PyBUF_WRITE);
        if (!obj)
          gdbpy_handle_exception ();
        readbuf.reset(obj);
      }
    else
      {
	Py_INCREF (Py_None);
	readbuf.reset(Py_None);
      }

    gdbpy_ref<> writebuf;
    if (gdb_writebuf)
      {
	/* Messy but the PyBUF_READ flag enforces the constness */
	char *buf = const_cast<char *>(reinterpret_cast<const char *>(gdb_writebuf));
	obj = PyMemoryView_FromMemory(buf, len, PyBUF_READ);
        if (!obj)
          gdbpy_handle_exception ();
        writebuf.reset(obj);
      }
    else
      {
	Py_INCREF (Py_None);
	writebuf.reset(Py_None);
      }

    gdbpy_ref<> arglist (Py_BuildValue ("(isOOKK)", (int)object, annex,
                                        readbuf, writebuf, offset, len));
    if (arglist == NULL)
      gdbpy_handle_exception ();

    gdbpy_ref<> ret(PyObject_Call(callback.get (), arglist.get (), NULL));
    if (PyErr_Occurred ())
      {
	if (PyErr_ExceptionMatches (py_target_xfer_eof_error))
	  {
	    PyErr_Clear ();
	    return TARGET_XFER_EOF;
	  }
	else if (PyErr_ExceptionMatches (PyExc_IOError))
	  {
	    PyErr_Clear ();
	    return TARGET_XFER_E_IO;
	  }
	else if (PyErr_ExceptionMatches (py_target_xfer_unavailable_error))
	  {
	    PyErr_Clear ();
	    *xfered_len = len;
	    return TARGET_XFER_UNAVAILABLE;
	  }

        gdbpy_handle_exception ();
    }

    lret = PyLong_AsUnsignedLongLong (ret.get ());
    if (gdb_readbuf)
      {
	const char *str = PyByteArray_AsString (readbuf.get ());
	int l = PyByteArray_Size (readbuf.get ());
        if (l > len)
          l = len;
	memcpy (gdb_readbuf, str, l);
      }

    *xfered_len = lret;
    return TARGET_XFER_OK;
}

const char *
python_target::extra_thread_info (struct thread_info *info)
{
  gdb::unique_xmalloc_ptr<char> host_string;

  gdbpy_enter enter_py (target_gdbarch (), current_language);

  if (!pytarget_has_op ())
    return beneath ()->extra_thread_info (info);

  gdbpy_ref<> callback (pytarget_get_op ());
  if (callback == NULL)
    gdbpy_handle_exception ();

  gdbpy_ref<> arglist (Py_BuildValue ("()"));
  if (arglist == NULL)
    gdbpy_handle_exception ();

  gdbpy_ref<> result (PyObject_Call (callback.get (), arglist.get (), NULL));
  if (result == NULL)
    gdbpy_handle_exception ();

  host_string = python_string_to_host_string (result.get ());
  if (host_string != NULL)
    gdbpy_handle_exception ();

  /* XXX FIXME */
  return "<unimplemented>";
}

void
python_target::update_thread_list (void)
{
  gdbpy_enter enter_py (target_gdbarch (), current_language);

  if (!pytarget_has_op ())
    {
      beneath ()->update_thread_list();
      return;
    }

  gdbpy_ref<> callback (pytarget_get_op());
  if (callback == NULL)
    gdbpy_handle_exception ();

  gdbpy_ref<> arglist (Py_BuildValue ("()"));
  if (arglist == NULL)
    gdbpy_handle_exception ();

  gdbpy_ref<> result (PyObject_Call (callback.get (), arglist.get (), NULL));
  if (result == NULL)
    gdbpy_handle_exception ();

  gdbpy_ignore_result (result);
}

bool
python_target::thread_alive (ptid_t ptid)
{
  gdbpy_enter enter_py (target_gdbarch (), current_language);

  if (!pytarget_has_op ()) {
    printf("target doesn't have thread_alive\n");
    return false;
  }

  gdbpy_ref<> callback (pytarget_get_op ());
  if (callback == NULL)
    gdbpy_handle_exception ();

  gdbpy_ref<> ptid_obj (gdbpy_create_ptid_object (ptid));
  if (ptid_obj == NULL)
    gdbpy_handle_exception ();

  gdbpy_ref<> arglist (Py_BuildValue ("(O)", ptid_obj.get ()));
  if (arglist == NULL)
    gdbpy_handle_exception ();

  gdbpy_ref<> result (PyObject_Call (callback.get (), arglist.get (), NULL));
  if (result == NULL)
    gdbpy_handle_exception ();

  if (!PyBool_Check (result.get ()))
    {
      PyErr_Format(PyExc_TypeError,
                   "`%s' callback must return True or False.", __FUNCTION__);
      gdbpy_handle_exception ();
    }

  return result.get () == Py_True;
}

std::string
python_target::pid_to_str (ptid_t ptid)
{
  gdb::unique_xmalloc_ptr<char> host_string;

  gdbpy_enter enter_py (target_gdbarch (), current_language);

  if (!pytarget_has_op ())
    return beneath ()->pid_to_str (ptid);

  gdbpy_ref<> callback (pytarget_get_op ());
  if (callback == NULL)
    gdbpy_handle_exception ();

  gdbpy_ref<> ptid_obj (gdbpy_create_ptid_object (ptid));
  if (ptid_obj == NULL)
    gdbpy_handle_exception ();

  gdbpy_ref<> arglist (Py_BuildValue ("(O)", ptid_obj.get ()));
  if (arglist == NULL)
    gdbpy_handle_exception ();

  gdbpy_ref<> result (PyObject_Call (callback.get (), arglist.get (), NULL));
  if (result == NULL)
    gdbpy_handle_exception ();

  if (!PyUnicode_Check (result.get ()))
    {
      PyErr_Format(PyExc_TypeError, "`%s' callback must return `str'",
                      __FUNCTION__);
      gdbpy_handle_exception ();
    }

  host_string = python_string_to_host_string (result.get ());
  if (host_string == NULL)
    gdbpy_handle_exception ();

  return std::string (host_string.get ());
}

static void
write_register (struct thread_info *ti, struct regcache *regcache,
		int reg, const void *data)
{
  struct gdbarch *gdbarch = target_gdbarch ();

  if (target_has_execution (ti->inf) &&
      reg == gdbarch_pc_regnum (gdbarch) && data)
    {
      CORE_ADDR pc = *(CORE_ADDR *)data;
      regcache_write_pc (regcache, pc);
    }
  else
    regcache->raw_supply (reg, data);
}

static const char *
type_prefix (struct type *type)
{
  switch (type->code ())
    {
      case TYPE_CODE_UNION:
        return "union ";
      case TYPE_CODE_STRUCT:
        return "struct ";
      case TYPE_CODE_ENUM:
        return "enum ";
      }

    return "";
}

static void
check_size (size_t len, size_t size)
{
  if (len < size)
    {
      PyErr_Format (PyExc_TypeError,
		    "Value must be at least %zd bytes in size.", size);
      gdbpy_handle_exception ();
    }
}

static void
decode_and_write_register (struct thread_info *ti, struct regcache *regcache,
			   int regnum, PyObject *value_obj)
{
  struct gdbarch *gdbarch = ti->inf->gdbarch;
  struct type *type = register_type (gdbarch, regnum);
  int size = register_size (gdbarch, regnum);
  struct value *value;

  if (value_obj == Py_None)
    {
      write_register (ti, regcache, regnum, NULL);
      return;
    }

  if (PyByteArray_Check (value_obj))
    {
      Py_ssize_t len = PyByteArray_Size (value_obj);
      char *buf;

      check_size (len, size);

      buf = PyByteArray_AsString (value_obj);
      write_register (ti, regcache, regnum, buf);
      return;
    }

  if (PyLong_Check (value_obj))
    {
      unsigned long value_ul;

      check_size (sizeof (value_ul), size);

      value_ul = PyLong_AsUnsignedLong (value_obj);
      if (value_ul == (unsigned long)-1 && PyErr_Occurred ())
        gdbpy_handle_exception ();

      write_register (ti, regcache, regnum, &value_ul);
      return;
    }

  value = value_object_to_value (value_obj);
  if (value)
    {
      try
	{
	  check_size (type->length, value_type (value)->length);
	  value = value_cast (type, value);
	}
      catch (const gdb_exception &except)
	{
	  const char *name
	    = gdbarch_register_name (gdbarch, regnum);
	  PyErr_Format (PyExc_ValueError,
			"Cannot convert gdb.Value of type %s%s to type %s%s for register %s: %s",
			type_prefix (type), type->name (),
			type_prefix (value_type(value)),
                        value_type(value)->name (),
			name, except.message);
	  gdbpy_handle_exception ();
	}

      write_register (ti, regcache, regnum, value_contents (value).data ());
      return;
    }

  PyErr_Format (PyExc_TypeError,
	  "Value must be long, bytearray, or gdb.Value and convertible to `%s%s'",
	  type_prefix (type), type->name ());
  gdbpy_handle_exception ();
}

void
python_target::fetch_registers (struct regcache *regcache, int reg)
{
  thread_info *info;
  Py_ssize_t pos = 0;

  gdbpy_enter enter_py (target_gdbarch (), current_language);

  if (!pytarget_has_op()) {
    error ("target has no `fetch_registers' method implemented\n");
    return;
  }

  gdbpy_ref<> callback (pytarget_get_op ());
  if (callback == NULL)
    gdbpy_handle_exception ();

  info = find_thread_ptid (regcache->target (), regcache->ptid ());

  if (!info)
    {
      PyErr_SetString (PyExc_RuntimeError, "No such ptid for registers.");
      gdbpy_handle_exception ();
    }

  gdbpy_ref<> thread = thread_to_thread_object (info);
  if (thread == NULL)
    gdbpy_handle_exception ();

  gdbpy_ref<> reg_obj;
  if (reg != -1)
    {
      reg_obj = gdbpy_get_register_descriptor (target_gdbarch (), reg);
    }
  else
    {
      Py_INCREF (Py_None);
      reg_obj.reset (Py_None);
    }

  if (reg_obj == NULL)
    gdbpy_handle_exception ();

  gdbpy_ref<> arglist (Py_BuildValue ("(OO)", thread.get (), reg_obj.release ()));
  if (arglist == NULL)
    gdbpy_handle_exception ();

  gdbpy_ref<> result (PyObject_Call (callback.get (), arglist.get (), NULL));
  if (result == NULL)
    gdbpy_handle_exception ();

  if (!PyDict_Check (result.get ()))
    {
      if (result.get () != Py_None)
        {
          PyErr_SetString (PyExc_TypeError,
                   _("fetch_registers is expected to return a dictionary."));
          gdbpy_handle_exception ();
        }
      return;
    }

  /* The callback can return any number of registers */
  PyObject *key = NULL;
  PyObject *value = NULL;
  while (PyDict_Next(result.get (), &pos, &key, &value))
    {
      int regnum = 0;

      if (PyObject_IsInstance (key,
                               (PyObject *) &register_descriptor_object_type))
        {
          struct register_descriptor_object *reg_decr
            = (struct register_descriptor_object *) key;
          if (reg_decr->gdbarch != target_gdbarch ())
            {
              PyErr_SetString(PyExc_ValueError,
                              _("Architecture mismatch in register"));
              gdbpy_handle_exception ();
            }
        }
      else if (PyString_Check (key))
        {
          gdb::unique_xmalloc_ptr<char> regname;

          regname = python_string_to_host_string (key);
          if (!regname)
            gdbpy_handle_exception ();

          if (*regname == '\0')
            {
              PyErr_SetString(PyExc_ValueError,
                              _("Register name cannot be empty."));
              gdbpy_handle_exception ();
            }

          regnum = user_reg_map_name_to_regnum (target_gdbarch (),
                                                regname.get (), -1);
          if (regnum < 0)
            {
              PyErr_Format(PyExc_ValueError,
                              _("Architecture has no register named `%s'"),
			      regname.get ());
              gdbpy_handle_exception ();
            }
        }

        gdb_assert (regnum >= 0);

        decode_and_write_register (info, regcache, regnum, value);
    }
}

void
python_target::prepare_to_store (struct regcache *regcache)
{
  gdbpy_enter enter_py (target_gdbarch (), current_language);

  if (!pytarget_has_op ())
    {
      beneath ()->prepare_to_store (regcache);
      return;
    }

  gdbpy_ref<> callback (pytarget_get_op());
  if (callback == NULL)
    gdbpy_handle_exception ();

  gdbpy_ref<> thread (gdbpy_selected_thread (NULL, NULL));
  if (thread == NULL)
    gdbpy_handle_exception ();

  gdbpy_ref<> arglist (Py_BuildValue ("(O)", thread.get ()));
  if (arglist == NULL)
    gdbpy_handle_exception ();

  gdbpy_ref<> result (PyObject_Call (callback.get (), arglist.get (), NULL));
  if (result == NULL)
    gdbpy_handle_exception ();
}

void
python_target::store_registers (struct regcache *regcache, int reg)
{
  struct gdbarch *gdbarch = target_gdbarch ();
  int min_reg, max_reg;

  gdbpy_enter enter_py (target_gdbarch (), current_language);

  if (!pytarget_has_op ())
    {
      beneath ()->store_registers (regcache, reg);
      return;
    }

  gdbpy_ref<> callback (pytarget_get_op());
  if (callback == NULL)
    gdbpy_handle_exception ();

  PyObject *thread (gdbpy_selected_thread (NULL, NULL));
  if (thread == NULL)
    gdbpy_handle_exception ();

  gdbpy_ref<> reg_dict (PyDict_New ());
  if (reg_dict == NULL)
    gdbpy_handle_exception ();

  if (reg >= 0)
    {
      min_reg = reg;
      max_reg = reg + 1;
    }
  else
    {
      min_reg = 0;
      max_reg = gdbarch_num_regs (target_gdbarch ());
    }

  for (int i = min_reg; i < max_reg; i++)
    {
        int size = register_size (target_gdbarch (), i);
        char bytes[size];

	if (regcache->get_register_status (i) != REG_VALID)
	  continue;

        regcache->raw_collect(i, bytes);

        gdbpy_ref<> key = gdbpy_get_register_descriptor (gdbarch, i);
        PyObject *value = PyByteArray_FromStringAndSize (bytes, size);

        if (PyDict_SetItem (reg_dict.get (), key.release (), value))
          gdbpy_handle_exception ();
    }

  gdbpy_ref<> arglist (Py_BuildValue ("(OO)", thread, reg_dict.get ()));
  if (arglist == NULL)
    gdbpy_handle_exception ();

  gdbpy_ref<> result (PyObject_Call (callback.get (), arglist.get (), NULL));
  if (result == NULL)
    gdbpy_handle_exception ();

  gdbpy_ignore_result (result);
}

bool
python_target::has_execution (inferior *inf)
{
  gdbpy_enter enter_py (target_gdbarch (), current_language);

  if (!pytarget_has_op ())
    return beneath ()->has_execution (inf);

  gdbpy_ref<> callback (pytarget_get_op());
  if (callback == NULL)
    gdbpy_handle_exception ();

  gdbpy_ref<inferior_object> inf_obj = inferior_to_inferior_object (inf);
  if (inf_obj == NULL)
    gdbpy_handle_exception ();

  gdbpy_ref<> arglist (Py_BuildValue ("(O)", (PyObject *)inf_obj.get ()));
  if (arglist == NULL)
    gdbpy_handle_exception ();

  gdbpy_ref<> result (PyObject_Call (callback.get (), arglist.get (), NULL));
  if (result == NULL)
    gdbpy_handle_exception ();

  if (!PyBool_Check (result.get ()))
    {
      PyErr_SetString (PyExc_RuntimeError,
		       "has_exception callback must return True or False");
      gdbpy_handle_exception ();
    }

  return result == Py_True;
}

int
python_target::set_shortname (PyObject *pyname)
{
  gdb::unique_xmalloc_ptr<char> name;

  if (registered) {
    PyErr_SetString (PyExc_RuntimeError,
		     _("Cannot set name on registered Target."));
    return -1;
  }

  name = python_string_to_host_string (pyname);
  if (!name)
    return -1;

  _info.shortname = xstrdup (name.get ());

  return 0;
}

int
python_target::set_longname (PyObject *pyname)
{
  gdb::unique_xmalloc_ptr<char> name;

  if (registered) {
    PyErr_SetString (PyExc_RuntimeError,
		     _("Cannot set name on registered Target."));
    return -1;
  }

  name = python_string_to_host_string (pyname);
  if (!name)
    return -1;

  _info.longname = xstrdup (name.get ());

  return 0;
}

int
python_target::set_docstring (PyObject *pyname)
{
  gdb::unique_xmalloc_ptr<char> name;

  if (registered) {
    PyErr_SetString (PyExc_RuntimeError,
		     _("Cannot set docstring on registered Target."));
    return -1;
  }

  name = python_string_to_host_string (pyname);
  if (!name)
    return -1;

  _info.doc = xstrdup (name.get ());

  return 0;
}

static python_target *registered_target = NULL;
static bool target_cmd_added = false;

static void
pytarget_open (const char *args, int from_tty)
{

  struct target_ops *ops = find_target_at (thread_stratum);
  if (ops && !have_inferiors ())
    {
      if (from_tty && !query (_("Another target is open.  Close it?")))
	error (_("Refusing to replace other target."));
    }

  /*
   * This happens when we've used a python target and have unregistered it.
   * It'd be nice to just remove the command as well, but it gets messy
   * fast.
   */
  if (!registered_target)
    error("No python target implementation registered.");

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

  /* We could have an array of openers and targets based on stratum */
  if (registered_target) {
      PyErr_SetString (PyExc_RuntimeError,
		       "This implementation only supports one python target at a time");
      return;
  }

  if (!_info.longname)
    _info.longname = xstrdup (_info.shortname);

  if (!_info.doc)
    _info.doc = xstrdup (_info.longname);

  Py_INCREF(owner);

  registered_target = this;
  registered = true;

  if (!target_cmd_added)
    {
      add_target (info (), pytarget_open, NULL);
      target_cmd_added = true;
    }
}

void
python_target::unregister_target (void)
{
  if (!registered)
    error (_("Target is not registered."));

  registered_target = NULL;
  registered = false;

  Py_DECREF (owner);
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

  if (!obj->native_target)
    delete obj->ops;
  obj->ops = NULL;

  // Py_DECREF (((pytarget_object *) owner)->inf_obj);
  // Decremement any references taken....
  Py_TYPE (owner)->tp_free (owner);
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
  return PyLong_FromLong (target_obj->ops->stratum());
}

static PyObject *
tgt_py_get_arch (PyObject *owner, void *arg)
{
  return gdbarch_to_arch_object (target_gdbarch ());
}

static PyObject *target_getconst (PyObject *_owner, void *_value)
{
	return PyLong_FromLong ((long)_value);
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

static PyObject *
pytarget_prepare_open (PyObject *object, PyObject *args, PyObject *kwargs)
{
  pytarget_object *self = (pytarget_object *) object;
  static const char *keywords[] = { "prompt_to_replace", NULL };

  int from_tty = 1;

  if (self->native_target)
    {
      PyErr_SetString (PyExc_ValueError,
                             _("Native targets are read-only."));
      return NULL;
    }

  if (!gdb_PyArg_ParseTupleAndKeywords (args, kwargs, "|p", keywords, &from_tty))
    return NULL;

  try
    {
      target_ops *old = find_target_at (self->ops->stratum ());
      if (old && !have_inferiors ())
        {
          if (from_tty && !query (_("Another target is open.  Close it?")))
           error (_("Refusing to replace other target."));
        }
      if (self->ops->stratum () <= process_stratum)
	{
	  target_preopen (from_tty);
	  reopen_exec_file ();
	}
      registers_changed ();
    }
  catch (const gdb_exception &except)
    {
      GDB_PY_HANDLE_EXCEPTION (except);
    }

  Py_RETURN_NONE;
}

static PyObject *
pytarget_push_target (PyObject *object, PyObject *unused)
{
  pytarget_object *target = (pytarget_object *)object;
  Py_INCREF (object);
  target_ops_up target_holder (target->ops);
  current_inferior ()->push_target (std::move (target_holder));
  reread_symbols (0);
  init_thread_list ();

  Py_RETURN_NONE;
}

static PyObject *
pytarget_close_target (PyObject *object, PyObject *unused)
{
  pytarget_object *owner = (pytarget_object *) object;

  if (owner->native_target)
    {
      PyErr_SetString (PyExc_AttributeError,
                             _("Native targets are read-only."));
      return NULL;
    }

  try
    {
      current_inferior ()->unpush_target (owner->ops);
      Py_DECREF (owner);
    }
  catch (const gdb_exception &except)
    {
      GDB_PY_HANDLE_EXCEPTION (except);
    }

  Py_RETURN_NONE;
}

static PyObject *
pytarget_update_thread_list (PyObject *object, PyObject *unused)
{
  pytarget_object *owner = (pytarget_object *) object;

  if (owner->native_target)
    {
      PyErr_SetString (PyExc_AttributeError,
                             _("Native targets are read-only."));
      return NULL;
    }

  try
    {
      owner->ops->update_thread_list ();
    }
  catch (const gdb_exception &except)
    {
      GDB_PY_HANDLE_EXCEPTION (except);
    }

  Py_RETURN_NONE;
}

static PyMethodDef pytarget_object_methods[] =
{
  { "register", pytarget_register_target, METH_NOARGS,
    "register ()\nRegister this target for use with GDB as a target command." },
  { "unregister", pytarget_unregister_target, METH_NOARGS,
    "unregister ()\nUnregister this target for use with GDB as a target command." },
  { "prepare_open", (PyCFunction)pytarget_prepare_open, METH_VARARGS | METH_KEYWORDS,
    "prepare_open ([PROMPT])\nPrepare this target for opening, optionally replacing an existing target." },
  { "push_target", pytarget_push_target, METH_NOARGS,
    "push_target ()\nPush this target on to the target stack for immediate use." },
  { "close", pytarget_close_target, METH_NOARGS,
    "close ()\nClose this target and remove it from the target stack." },
  { "update_thread_list", pytarget_update_thread_list, METH_NOARGS,
    "update_thread_list ()\nUpdate the target's thread list" },
  { NULL }
};

static int
pytarget_init (PyObject *obj, PyObject *args, PyObject *kwds)
{
    pytarget_object *self = (pytarget_object *)obj;

    try
      {
	self->ops = new python_target (obj);
      }
    catch (const gdb_exception &except)
      {
	Py_DECREF (self);
	GDB_PY_SET_HANDLE_EXCEPTION (except);
      }
    return 0;
}


static PyObject *
pytarget_new (PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  PyObject *self = type->tp_alloc (type, 0);

  if (self)
    {
    	  pytarget_object *target_obj = (pytarget_object *)self;
	  target_obj->ops = NULL;
	  target_obj->native_target = false;
	  target_obj->registered = false;
    }

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

  return gdb_pymodule_addobject (gdb_module, "Target",
				 (PyObject *) &target_object_type);
fail:
  gdbpy_print_stack ();
  return -1;
}

PyTypeObject target_object_type =
{
  PyVarObject_HEAD_INIT (NULL, 0)
  "gdb._Target",		  /*tp_name*/
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
  pytarget_init,		  /* tp_init */
  0,				  /* tp_alloc */
  pytarget_new,			  /* tp_new */
};

PyObject *
gdbpy_current_target (PyObject *self, PyObject *args)
{
  PyObject *target_obj = NULL;
  target_ops *target = current_inferior ()->top_target ();

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
