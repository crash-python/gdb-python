#include "defs.h"
#include "python-internal.h"
#include "gdbthread.h"
#include "regcache.h"

extern PyTypeObject register_object_type;

typedef struct register_object {
  PyObject_HEAD
  thread_object *thread;
  int regnum;
  struct register_object *next;
  struct register_object *prev;
} register_object;

#define REGPY_REQUIRE_VALID(register_obj, reg, ret)		\
  do {								\
    reg = register_object_to_register(register_obj);		\
    if (reg == NULL)						\
      {								\
	PyErr_SetString (PyExc_RuntimeError,			\
			 _("Register is invalid."));		\
	return ret;						\
      }								\
  } while(0)

static void
set_register(register_object *obj, thread_object *thread_obj, int regnum)
{
  obj->thread = thread_obj;
  obj->regnum = regnum;
  obj->prev = NULL;
  obj->next = (register_object *)thread_obj->register_objs;
  if (obj->next)
    obj->next->prev = obj;
  thread_obj->register_objs = (PyObject *)obj;
}

PyObject *
register_to_register_object (thread_object *thread_obj, int reg)
{
  register_object *register_obj;

  register_obj = PyObject_New (register_object, &register_object_type);
  if (register_obj)
    set_register (register_obj, thread_obj, reg);
  return (PyObject *) register_obj;

}

static register_object *
register_object_to_register (PyObject *obj)
{
  register_object *reg;
  if (! PyObject_TypeCheck (obj, &register_object_type))
    return NULL;
  reg = (register_object *) obj;
  if (!reg->thread)
    return NULL;
  return reg;
}

static PyObject *
register_get_name(PyObject *self, void *closure)
{
  register_object *obj;
  const char *name = NULL;

  REGPY_REQUIRE_VALID(self, obj, NULL);
  TRY
    {
      struct gdbarch *gdbarch = target_gdbarch();
      name = gdbarch_register_name (gdbarch, obj->regnum);
    }
  CATCH (except, RETURN_MASK_ALL)
    {
      GDB_PY_HANDLE_EXCEPTION (except);
    }
  END_CATCH

  return PyString_FromString(name);
}

static PyObject *
register_get_value(PyObject *self, void *closure)
{
  register_object *obj;
  struct value *value = NULL;

  REGPY_REQUIRE_VALID(self, obj, NULL);

  TRY
    {
      struct gdbarch *gdbarch = target_gdbarch ();
      struct thread_info *ti = obj->thread->thread;
      struct regcache *regcache = get_thread_regcache (ti->ptid);
      if (obj->regnum == gdbarch_pc_regnum (gdbarch))
	{
	  CORE_ADDR pc = regcache_read_pc (regcache);
	  value = allocate_value (register_type (gdbarch, obj->regnum));

	  VALUE_LVAL (value) = lval_register;
	  VALUE_REGNUM (value) = obj->regnum;
	  memcpy (value_contents_raw (value), &pc, sizeof (pc));
	}
      else
	{
	  /*
	   * We don't want raw read since that expects to
	   * read it from the core file
	   */
	  value = regcache_cooked_read_value (regcache, obj->regnum);
	}
    }
  CATCH (ex, RETURN_MASK_ERROR)
    {
      GDB_PY_HANDLE_EXCEPTION (ex);
    }
  END_CATCH

  return value_to_value_object(value);
}

static const char *
type_prefix (struct type *type)
{
  switch (TYPE_CODE(type))
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

static int
check_size (size_t len, size_t size)
{
  if (len < size)
    {
      PyErr_Format (PyExc_TypeError,
		    "Value must be at least %zd bytes in size.", size);
      return -1;
    }
  return 0;
}

static int
write_register (struct regcache *regcache, int reg, const void *data)
{
  struct gdbarch *gdbarch = target_gdbarch ();
  if (reg == gdbarch_pc_regnum (gdbarch))
    {
      CORE_ADDR pc = *(CORE_ADDR *)data;
      regcache_write_pc (regcache, pc);
    }
  else
    regcache_raw_supply (regcache, reg, data);

  return 0;
}

static int
register_set_value(PyObject *self, PyObject *value_obj, void *closure)
{
  struct type *type = NULL;
  register_object *obj;
  int ret = -1;
  size_t size = 0;

  REGPY_REQUIRE_VALID(self, obj, -1);

  TRY
    {
      struct gdbarch *gdbarch = target_gdbarch ();
      size_t size = register_size (gdbarch, obj->regnum);
      struct thread_info *ti = obj->thread->thread;
      struct regcache *regcache = get_thread_regcache_for_ptid(ti->ptid);
      struct value *value;
      unsigned long ul_value;

      type = register_type (gdbarch, obj->regnum);

      if (value_obj == Py_None)
	ret = write_register (regcache, obj->regnum, NULL);
      else if (PyByteArray_Check (value_obj))
        {
	  Py_ssize_t len = PyByteArray_Size (value_obj);
	  char *buf = PyByteArray_AsString (value_obj);
	  if (!check_size (len, size))
	    ret = write_register (regcache, obj->regnum, buf);
	}
      else if (PyLong_Check (value_obj))
	{
	  ul_value = PyLong_AsUnsignedLong (value_obj);

	  if (!check_size (sizeof (ul_value), size))
	    {
	      /* Let the value code do the type checking */
	      value = value_from_ulongest (type, ul_value);
	      ret = write_register (regcache, obj->regnum, &ul_value);
	    }
	}
#ifndef IS_PY3K
      else if (PyInt_Check (value_obj))
	{
	  ul_value = PyInt_AsUnsignedLongMask (value_obj);

	  if (!check_size (sizeof (ul_value), size))
	    {
	      /* Let the value code do the type checking */
	      value = value_from_ulongest (type, ul_value);
	      ret = write_register (regcache, obj->regnum, &ul_value);
	    }
	}
#endif
      else
	{
	  value = value_object_to_value(value_obj);
	  if (value)
	    {
	      value = value_cast (type, value);
	      ret = write_register (regcache, obj->regnum,
				    value_contents (value));
	    }
	  else
	    PyErr_Format (PyExc_TypeError,
		      "Value must be int, long, bytearray, or gdb.Value and convertible to `%s%s'",
		      type_prefix (type), type_name_no_tag (type));
	}
    }
  CATCH (except, RETURN_MASK_ALL)
    {
      GDB_PY_SET_HANDLE_EXCEPTION (except);
    }
  END_CATCH

  return ret;
}

static PyObject *
register_get_size(PyObject *self, void *closure)
{
  register_object *obj;
  int size = 0;

  REGPY_REQUIRE_VALID(self, obj, NULL);

  TRY
    {
      struct gdbarch *gdbarch = target_gdbarch();
      size = register_size (gdbarch, obj->regnum);
    }
  CATCH (except, RETURN_MASK_ALL)
    {
      GDB_PY_HANDLE_EXCEPTION (except);
    }
  END_CATCH

  return PyInt_FromLong(size);
}

static PyObject *
register_get_regnum(PyObject *self, void *closure)
{
  register_object *obj;
  REGPY_REQUIRE_VALID(self, obj, NULL);

  return PyInt_FromLong(obj->regnum);
}

static PyObject *
register_get_regtype(PyObject *self, void *closure)
{
  register_object *obj;
  struct type *type = NULL;

  REGPY_REQUIRE_VALID(self, obj, NULL);

  TRY
    {
      struct gdbarch *gdbarch = target_gdbarch ();
      type = register_type (gdbarch, obj->regnum);
    }
  CATCH (except, RETURN_MASK_ALL)
    {
      GDB_PY_HANDLE_EXCEPTION (except);
    }
  END_CATCH

  return type_to_type_object(type);
}

static void
register_object_dealloc (PyObject *self)
{
  register_object *reg = (register_object *) self;

  if (reg->prev)
	  reg->prev->next = reg->next;
  else if (reg->thread)
    reg->thread->register_objs = (PyObject *)reg->next;

  if (reg->next)
	  reg->next->prev = reg->prev;
}

void
del_thread_registers (thread_object *thread)
{
  register_object *obj = (register_object *) thread->register_objs;

  while (obj)
    {
      register_object *next = obj->next;

      obj->thread = NULL;
      obj->prev = NULL;
      obj->next = NULL;

      obj = next;
    }
}

static gdb_PyGetSetDef register_object_getset[] = {
  { "name", register_get_name, NULL, "Register name.", NULL },
  { "value", register_get_value, register_set_value, "Register value.", NULL },
  { "size", register_get_size, NULL, "Register size.", NULL },
  { "regnum", register_get_regnum, NULL, "Register number.", NULL },
  { "type", register_get_regtype, NULL, "Register type.", NULL },
  { NULL }  /* Sentinal */
};

PyTypeObject register_object_type = {
  PyVarObject_HEAD_INIT (NULL, 0)
  "gdb.Register",		  /*tp_name*/
  sizeof(register_object),	  /*tp_basicsize*/
  0,				  /*tp_itemsize*/
  register_object_dealloc,	  /*tp_delalloc*/
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
  Py_TPFLAGS_DEFAULT,		  /*tp_flags*/
  "GDB Register object",	  /* tp_doc */
  0,				  /* tp_traverse */
  0,				  /* tp_clear */
  0,				  /* tp_richcompare */
  0,				  /* tp_weaklistoffset */
  0,				  /* tp_iter */
  0,				  /* tp_iternext */
  0,	  			  /* tp_methods */
  0,				  /* tp_members */
  register_object_getset,	  /* tp_getset */
};

int gdbpy_initialize_register (void)
{
    if (PyType_Ready (&register_object_type) < 0)
      return -1;

    return (gdb_pymodule_addobject(gdb_module, "register",
			       (PyObject *)&register_object_type));
}
