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

#include "py-target.h"

extern PyTypeObject target_object_type
    CPYCHECKER_TYPE_OBJECT_FOR_TYPEDEF ("target_object");

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
static target_object * target_ops_to_target_obj(struct target_ops *ops)
{
    return container_of(ops, target_object, ops);
}



// Identify if our class (self) has a method to support this call
#define HasMethodOrReturnBeneath(py_ob, op, ops, args...)	\
	if (!PyObject_HasAttrString(py_ob, #op))		\
	{							\
	    ops = ops->beneath;					\
	    return ops->op(ops, ##args);			\
	}


static const
char *py_target_to_thread_name (struct target_ops *ops , struct thread_info * info)
{
    /* Note how we can obtain our Parent Python Object from the ops too */
    target_object *target_obj = target_ops_to_target_obj(ops);
    PyObject * self = (PyObject *)target_obj;

    PyObject *arglist;
    PyObject *argobj;
    PyObject *result;
    PyObject *to_thread_name;

    int arg;
    char * args = "";
    struct cleanup *cleanup;

    /* Linux defines TASK_COMM_LEN as 16 in the kernel's sched.h.
     * But other targets may have different sizes...  */
#define TASK_COMM_LEN 16  /* As defined in the kernel's sched.h.  */
    /* static array required to pass the string back to the calling function */
    static char name[TASK_COMM_LEN] = "";

    HasMethodOrReturnBeneath(self, to_thread_name, ops, info);

    /* (re-)initialise the static string before use in case of error */
    name[0] = '\0';

    /*
     * Don't try to enter the python environment until we know we will try to execute.
     * The call to HasAttr should be safe to call.
     */
    cleanup = ensure_python_env (get_current_arch (), current_language);

    // Call into Python Method

    to_thread_name = PyObject_GetAttrString (self, "to_thread_name");
    if (! to_thread_name)
	{
	  error (_("Failed to get 'to_thread_name' object. Can't continue..."));
	}


    TRY
    {
	//result = PyObject_CallMethod(self, "to_thread_name", "");
	arg = 123;

	/* Time to call the callback */
	arglist = Py_BuildValue("(i)", arg);

	result = PyObject_Call (to_thread_name, arglist, NULL);
	Py_DECREF(arglist);

	if (result)
	{
	    char * host_string = python_string_to_host_string (result);
	    if (host_string == NULL)
	      {
	        PyErr_SetString (PyExc_RuntimeError, _("Cannot allocate new name string."));
	        return "err";
	      }

	    strncpy(name, host_string, TASK_COMM_LEN-1);
	    name[TASK_COMM_LEN-1] = '\0';
	}


    }
    CATCH (except, RETURN_MASK_ALL)
    {
	printf_filtered("Failed to call to_thread_name successfully!\n");
	/* We *MUST* handle any exceptions before calling do_cleanups()
	 * which exits the python environment
	 */
	 // Handle any exceptions
    }
    END_CATCH

    Py_DECREF(result);

    do_cleanups(cleanup);

    return name;
}

static char *
py_target_to_extra_thread_info (struct target_ops *ops, struct thread_info *info)
{
    /* Note how we can obtain our Parent Python Object from the ops too */
    target_object *target_obj = target_ops_to_target_obj(ops);
    PyObject * self = (PyObject *)target_obj;

    struct cleanup *cleanup;
    cleanup = ensure_python_env (get_current_arch (), current_language);

    HasMethodOrReturnBeneath(self, to_extra_thread_info, ops, info);

    do_cleanups(cleanup);

    return "Linux task";
}

static void
py_target_to_update_thread_list (struct target_ops *ops)
{
    /* Note how we can obtain our Parent Python Object from the ops too */
    target_object *target_obj = target_ops_to_target_obj(ops);
    PyObject * self = (PyObject *)target_obj;

    struct cleanup *cleanup;
    cleanup = ensure_python_env (get_current_arch (), current_language);

    HasMethodOrReturnBeneath(self, to_update_thread_list, ops);

    do_cleanups(cleanup);
}


static void py_target_register_ops(struct target_ops * ops)
{
    if (!ops->to_shortname)
	ops->to_shortname = xstrdup (_("PythonTarget"));

    if (!ops->to_longname)
	ops->to_longname = xstrdup (_("A Python defined target layer"));

    /* Python Wrapper Calls */
    ops->to_thread_name = py_target_to_thread_name;
    ops->to_extra_thread_info = py_target_to_extra_thread_info;
    ops->to_update_thread_list = py_target_to_update_thread_list;

    // This may be the only variable to specify as a parameter in __init__
    ops->to_stratum = thread_stratum;

    /* Initialise Defaults */
    ops->to_has_all_memory = default_child_has_all_memory;
    ops->to_has_memory = default_child_has_memory;
    ops->to_has_stack = default_child_has_stack;
    ops->to_has_registers = default_child_has_registers;
    ops->to_has_execution = default_child_has_execution;

    ops->to_magic = OPS_MAGIC;

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

  // Py_DECREF (((target_object *) self)->inf_obj);
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
  enum target_names target_string = (enum target_names) arg;
  target_object *target_obj = (target_object *) self;
  struct target_ops *ops = &target_obj->ops;

  PyObject * name;

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
	    name = PyString_FromFormat("%s (%s)", shortname, longname);
	    break;
	case TGT_SHORTNAME:
	    name = PyString_FromString(shortname);
	    break;
	case TGT_LONGNAME:
	    name = PyString_FromString(longname);
	    break;
  }

  return name;
}

static int
tgt_py_set_name (PyObject *self, PyObject *newvalue, void * arg)
{
  enum target_names target_string = (enum target_names) arg;
  target_object *target_obj = (target_object *) self;
  struct target_ops *ops = &target_obj->ops;
  char * name;

  THPY_REQUIRE_VALID_INT (target_obj);

  name = python_string_to_host_string (newvalue);
  if (name == NULL)
    {
      PyErr_SetString (PyExc_RuntimeError, _("Cannot allocate new name string."));
      return -1;
    }

  switch (target_string)
  {
	default:
	case TGT_NAME:
	    /* No Op */
	    break;
	case TGT_SHORTNAME:
	    xfree((void *)ops->to_shortname);
	    ops->to_shortname = name;
	    break;
	case TGT_LONGNAME:
	    xfree((void *)ops->to_longname);
	    ops->to_longname = name;
	    break;
  }

  return 0;
}

static PyGetSetDef target_object_getset[] =
{
  { "name", tgt_py_get_name, NULL,
    "The name of the target", (void*)TGT_NAME },
  { "shortname", tgt_py_get_name, tgt_py_set_name,
    "The shortname of the target", (void*)TGT_SHORTNAME },
  { "longname", tgt_py_get_name, tgt_py_set_name,
    "The longname of the target", (void*)TGT_LONGNAME },

  { "stratum", NULL, NULL, "ID of the thread, as assigned by GDB.", NULL },

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
  target_object *target_obj = (target_object *) self;
  PyObject * ThreadName;

  ENTRY();

  ThreadName = PyString_FromString ("NoThreadName");

  EXIT();

  return ThreadName;
}

static PyMethodDef target_object_methods[] =
{
  { "to_thread_name_int", tgtpy_default_to_thread_name, METH_VARARGS | METH_KEYWORDS,
    "to_thread_name (thread_info) -> String.\n\
Return string name representation of the given thread." },



  { NULL }
};


static int
target_init (PyObject *self, PyObject *args, PyObject *kw)
{
    target_object *target_obj = (target_object *) self;
    struct target_ops *ops = &target_obj->ops;

    ENTRY();

    py_target_register_ops(ops);

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
  target_object_type.tp_new = PyType_GenericNew;

  if (PyType_Ready (&target_object_type) < 0)
    return -1;

  EXIT();

  return gdb_pymodule_addobject (gdb_module, "Target",
				 (PyObject *) &target_object_type);
}






PyTypeObject target_object_type =
{
  PyVarObject_HEAD_INIT (NULL, 0)
  "gdb.Target",			  /*tp_name*/
  sizeof (target_object),	  /*tp_basicsize*/
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
  target_object_methods,	  /* tp_methods */
  0,				  /* tp_members */
  target_object_getset,		  /* tp_getset */
  0,				  /* tp_base */
  0,				  /* tp_dict */
  0,				  /* tp_descr_get */
  0,				  /* tp_descr_set */
  0,				  /* tp_dictoffset */
  target_init,			  /* tp_init */
  0				  /* tp_alloc */
};
