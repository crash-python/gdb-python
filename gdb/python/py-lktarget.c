#include "defs.h"

#include <dlfcn.h>
#include <libkdumpfile/kdumpfile.h>

#include "bfd/kdumpfile.h"
#include "gdbcore.h"
#include "inferior.h"
#include "objfiles.h"
#include "python-internal.h"
#include "py-target.h"

typedef struct
{
  pytarget_object super;
} lktarget_object;

class lktarget : public python_target
{
public:
  lktarget (PyObject *owner) : python_target(owner) {}
  strata stratum() const override { return thread_stratum; }

  void update_thread_list (void) override;
  bool has_all_memory () override { return false; }
  bool has_stack () override { return (core_bfd != NULL); }
  bool has_registers () override { return (core_bfd != NULL); }
  const char *thread_name (struct thread_info *info) override;
  const char *extra_thread_info (struct thread_info *info) override;
  std::string pid_to_str (ptid_t ptid) override;
  void setup_task_struct (void);
  void finish_initial_setup (void);
  void relocate_kernel (void);
private:
  struct value *m_init_task;
  struct type *m_ulong_ptr_type;
  CORE_ADDR m_thread_return_addr;
  int m_task_mm_offset;
  int m_task_comm_offset;
};

static struct symbol *
lookup_kernel_symbol(const char *name)
{
  return lookup_symbol(name, NULL, VAR_DOMAIN, NULL).symbol;
}

static struct value *
lookup_kernel_value(const char *name)
{
  struct symbol *sym = lookup_kernel_symbol(name);
  struct value *val = NULL;

  if (sym)
    val = value_of_variable(sym, NULL);
  return val;
}

struct list_iterator {
  CORE_ADDR head;
  struct value *cur;
  struct type *ulong_ptr_type;
};

static void
list_iterator_init(struct list_iterator *iter, struct value *head)
{
  iter->head = value_address(head);
  iter->cur = value_struct_elt (&head, {}, "next", NULL, "list_head.next");
}

static struct value *
list_iterator_next(struct list_iterator *iter)
{
  struct value *next;

  next = value_struct_elt (&iter->cur, {}, "next", NULL, "list_head.next");

  iter->cur = next;
  if (value_address(iter->cur) == iter->head)
    return NULL;

  return iter->cur;
}

void
lktarget::setup_task_struct(void)
{
  struct_elt tmp_elt;

  m_init_task = lookup_kernel_value("init_task");
  if (!m_init_task)
    error(_("Failed to update thread list: Couldn't locate init_task.\n"));

  tmp_elt = lookup_struct_elt (value_type(m_init_task), "mm", 0);
  m_task_mm_offset = tmp_elt.offset / 8;

  tmp_elt = lookup_struct_elt (value_type(m_init_task), "comm", 0);
  m_task_comm_offset = tmp_elt.offset / 8;
}

void
lktarget::finish_initial_setup ()
{
  struct gdbarch *arch = current_inferior ()->gdbarch;
  m_ulong_ptr_type = lookup_pointer_type (builtin_type(arch)->builtin_unsigned_long);

  setup_task_struct ();
}

static PyObject *
lktarget_check_underlying_target (PyObject *object, PyObject *unused)
{
  bfd *exec_bfd = current_program_space->exec_bfd ();

  if (!core_bfd)
    {
      PyErr_SetString(PyExc_ValueError, "Target requires core file.");
      return NULL;
    }

  if (!exec_bfd)
    {
      PyErr_SetString (PyExc_ValueError, "Target requires executable file.");
      return NULL;
    }


  if (bfd_get_flavour (core_bfd) != bfd_target_kdumpfile_flavour &&
      bfd_get_flavour (core_bfd) != bfd_target_elf_flavour)
    {
      PyErr_Format (PyExc_ValueError, "Core file is unknown flavor %s.",
		    bfd_flavour_name (bfd_get_flavour (core_bfd)));
      return NULL;
    }

  if (bfd_get_flavour (core_bfd) == bfd_target_elf_flavour)
    {
      PyErr_SetString (PyExc_ValueError, "/proc/kcore support is not yet implemented.");
      return NULL;
    }

  Py_RETURN_NONE;
}

static PyObject *
lktarget_relocate_kernel (PyObject *object, PyObject *unused)
{
  lktarget_object *self = (lktarget_object *)object;

  try
    {
      lktarget *target = dynamic_cast<lktarget *>(self->super.ops);
      target->relocate_kernel ();
    }
  catch (const gdb_exception &except)
    {
      GDB_PY_HANDLE_EXCEPTION (except);
    }

  Py_RETURN_NONE;
}

static PyObject *
lktarget_finish_initial_setup (PyObject *object, PyObject *unused)
{
  lktarget_object *self = (lktarget_object *)object;

  try
    {
      lktarget *target = dynamic_cast<lktarget *>(self->super.ops);
      target->finish_initial_setup();
    }
  catch (const gdb_exception &except)
    {
      GDB_PY_HANDLE_EXCEPTION (except);
    }

  Py_RETURN_NONE;
}

static PyMethodDef lktarget_object_methods[] =
{
  { "_check_underlying_target", lktarget_check_underlying_target, METH_NOARGS,
    "_check_underlying_target () -> None\nEnsure this target has the prerequisites met." },
  { "_relocate_kernel", lktarget_relocate_kernel, METH_NOARGS,
    "_relocate_kernel () -> None\nRelocate the kernel to match the target." },
  { "_finish_initial_setup", lktarget_finish_initial_setup, METH_NOARGS,
    "_finish_initial_setup () -> None\nFinish initialization." },
  { NULL }
};

struct lk_thread_info : public private_thread_info
{
  bool kernel_thread;
  char comm[16 + 2];
  std::string extra_thread_info;
  std::string thread_name;

  PyObject *info;
};

static lk_thread_info *
get_lk_thread_info (thread_info *thread)
{
  return static_cast<lk_thread_info *> (thread->priv.get ());
}

void
lktarget::update_thread_list ()
{
  struct value *list_head = NULL;
  struct value *cur = NULL;
  struct list_iterator iter;
  struct_elt task_pid_elt;
  CORE_ADDR task_tasks_offset;
  static bool init;
  struct thread_info *th;

  if (init)
    return;

  th = find_thread_ptid (current_inferior(), ptid_t (1));
  if (th)
      delete_thread (th);

  init = true;

  process_stratum_target *beneath
    = as_process_stratum_target (this->beneath ());

  list_head = value_struct_elt (&m_init_task, {}, "tasks", NULL, "init_task.tasks");
  task_pid_elt = lookup_struct_elt (value_type(m_init_task), "pid", 0);

  task_tasks_offset = value_address(list_head) - value_address(m_init_task);

  /* Just populate the thread list and associate each with the task struct */
  list_iterator_init(&iter, list_head);
  while ((cur = list_iterator_next(&iter)) != NULL)
    {
      CORE_ADDR task_addr = value_address(cur) - task_tasks_offset;
      struct value *pid, *mm;
      struct lk_thread_info *priv;
      gdb_byte comm[16];

      pid = value_at(task_pid_elt.field->type(), task_addr + task_pid_elt.offset /8);
      ptid_t ptid (1, value_as_long(pid), task_addr);

      th = add_thread_silent(beneath, ptid);

      priv = new lk_thread_info;

      mm = value_at(m_ulong_ptr_type, th->ptid.tid() + m_task_mm_offset);
      priv->kernel_thread = value_as_address(mm) == 0;
      if (target_read_memory (th->ptid.tid() + m_task_comm_offset,
			      comm, sizeof(comm)) < 0)
	  error("couldn't read task->comm");
      if (priv->kernel_thread)
	priv->thread_name = string_printf("[%s]", comm);
      else
	priv->thread_name = string_printf("%s", comm);
      priv->extra_thread_info = string_printf("task %lx", task_addr);
      th->priv.reset(priv);
    }
}

std::string
lktarget::pid_to_str (ptid_t ptid)
{
  return string_printf("PID %ld", ptid.lwp());
}

const char *
lktarget::extra_thread_info (thread_info *th)
{
  struct lk_thread_info *ti = get_lk_thread_info (th);
  if (!ti)
    return "";
  if (ti->extra_thread_info.empty())
    return "";
  return ti->extra_thread_info.c_str();
}

const char *
lktarget::thread_name (thread_info *th)
{
  struct lk_thread_info *ti = get_lk_thread_info (th);
  if (!ti)
    return "";
  if (ti->thread_name.empty())
    return "";
  return ti->thread_name.c_str();
}

static void
apply_offsets (const section_offsets &section_offsets)
{
  for (objfile *objfile : current_program_space->objfiles ())
    {
      if (objfile->per_bfd->get_bfd() == core_bfd)
	continue;

      objfile_relocate(objfile, section_offsets);
    }
}

void
lktarget::relocate_kernel (void)
{
  asection *tsect;
  CORE_ADDR start, end;
  bfd *exec_bfd = current_program_space->exec_bfd ();
  section_offsets section_offsets;
  struct value *percpu_offsets_val;
  struct value *cpu0_offset_val;
  int percpu_index = -1;
  int i = 0;

  tsect = bfd_get_section_by_name (exec_bfd, ".text");
  if (!tsect)
    error(_("Couldn't locate required section `.text' in executable."));

  start = tsect->vma;
  end = tsect->vma + tsect->size;

  for (asection *asect : gdb_bfd_sections (core_bfd))
    {
      if (tsect->vma == asect->vma - core_bfd->start_address)
	{
	  start = asect->vma - core_bfd->start_address;
	  end = start + asect->size;
	}
    }

  for (asection *asect : gdb_bfd_sections (exec_bfd))
    {
      if (percpu_index == -1 && strcmp(asect->name, ".data..percpu") == 0)
	percpu_index = i;

      if (asect->vma >= start && asect->vma + asect->size <= end)
	section_offsets.emplace_back(core_bfd->start_address);
      else
	section_offsets.emplace_back(0);
      i++;
    }

  apply_offsets (section_offsets);

  if (percpu_index == -1)
    {
      warning (_("Couldn't locate percpu section."));
      return;
    }

  /*
   * We relocate the percpu section to the offset for CPU0 for two reasons:
   * 1) So that using the variable actually gives something back that makes sense
   * 2) To avoid the percpu symbol names colliding with e.g. NULL at offset 0.
   *
   * It needs to be done separately because we don't have access to the percpu
   * offsets until after we've relocated the data section.
   */
  percpu_offsets_val = lookup_kernel_value ("__per_cpu_offset");
  cpu0_offset_val = value_subscript (percpu_offsets_val, 0);
  section_offsets[percpu_index] = value_as_long (cpu0_offset_val);
  apply_offsets (section_offsets);
}

/* Iterators */

static int
lktarget_object_init (PyObject *obj, PyObject *args, PyObject *kwds)
{
  lktarget_object *self = (lktarget_object *)obj;

  try
    {
      lktarget *target = new lktarget (obj);
      if (self->super.ops)
	delete self->super.ops;
      self->super.ops = target;
    }
  catch (const gdb_exception &except)
    {
      Py_DECREF (obj);
      GDB_PY_SET_HANDLE_EXCEPTION (except);
    }
  return 0;
}

static PyObject *
lktarget_object_new (PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  PyObject *self = type->tp_alloc (type, 0);

  if (self)
    {
      try
	{
	  lktarget_object *target_obj = (lktarget_object *)self;
	  target_obj->super.ops = new lktarget (self);
	  target_obj->super.native_target = false;
	  target_obj->super.registered = false;
	}
      catch (const gdb_exception &except)
	{
	  Py_DECREF (self);
	  GDB_PY_HANDLE_EXCEPTION (except);
	}
    }

  return self;
}

static void
lktarget_object_dealloc (PyObject *owner)
{
  lktarget_object *obj = (lktarget_object *)owner;

  if (!obj->super.native_target)
    delete obj->super.ops;
  obj->super.ops = NULL;

  // Py_DECREF (((pytarget_object *) owner)->inf_obj);
  // Decremement any references taken....
  Py_TYPE (owner)->tp_free (owner);
}

static PyObject *
lktarget_get_kdumpfile (PyObject *owner, void * arg)
{
  kdump_ctx_t *ctx;
  PyObject *self = NULL;
  PyObject *mod = NULL;
  PyObject *kdumpfile_type_obj = NULL;

  if (bfd_get_flavour (core_bfd) != bfd_target_kdumpfile_flavour)
    {
      PyErr_SetString (PyExc_ValueError, "Target is not using kdumpfile");
      return NULL;
    }

  ctx = bfd_kdumpfile_get_data (core_bfd)->kdump_ctx;

  if (ctx == NULL)
    Py_RETURN_NONE;

  mod = PyImport_ImportModule ("_kdumpfile");
  if (!mod)
    return NULL;

  kdumpfile_type_obj = PyObject_GetAttrString (mod, "kdumpfile");
  if (!kdumpfile_type_obj)
    goto fail;

  self = PyObject_CallMethod (kdumpfile_type_obj, "from_pointer", "k",
			      (unsigned long)ctx);
fail:
  Py_XDECREF (mod);
  Py_XDECREF (kdumpfile_type_obj);

  return self;
}

static gdb_PyGetSetDef lktarget_object_getset[] =
{
  { "kdumpfile", lktarget_get_kdumpfile, NULL, "The kdumpfile for this target", NULL, },
  { NULL }
};

PyTypeObject lktarget_object_type =
{
  PyVarObject_HEAD_INIT (NULL, 0)
  "gdb._LinuxKernelTarget",	  /*tp_name*/
  sizeof (lktarget_object),	  /*tp_basicsize*/
  0,				  /*tp_itemsize*/
  lktarget_object_dealloc,		  /*tp_dealloc*/
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
  "GDB Linux Kernel target object",	  /* tp_doc */
  0,				  /* tp_traverse */
  0,				  /* tp_clear */
  0,				  /* tp_richcompare */
  0,				  /* tp_weaklistoffset */
  0,				  /* tp_iter */
  0,				  /* tp_iternext */
  lktarget_object_methods,	  /* tp_methods */
  0,				  /* tp_members */
  lktarget_object_getset,	  /* tp_getset */
  &target_object_type,		  /* tp_base */
  0,				  /* tp_dict */
  0,				  /* tp_descr_get */
  0,				  /* tp_descr_set */
  0,				  /* tp_dictoffset */
  lktarget_object_init,		  /* tp_init */
  0,				  /* tp_alloc */
  lktarget_object_new,		  /* tp_new */
};

int
gdbpy_initialize_lktarget (void)
{
  if (PyType_Ready (&lktarget_object_type) < 0)
    return -1;

  return gdb_pymodule_addobject (gdb_module, "LinuxKernelTarget",
				 (PyObject *)&lktarget_object_type);
}
