# Unwinder for libjit.

# FIXME
# * x86-64 only for now
# * should make a cache of all functions for further unwinding
#   and then invalidate on gdb.events.cont
# * Extract function names

import gdb
import gdb.types
import gdb.unwinder
from gdb.FrameDecorator import FrameDecorator

# Python 3 compat.
try:
    long
except NameError:
    long = int

# Python 3 compat.
try:
    from itertools import imap
except ImportError:
    imap = map

info_cache = {}

def find_by_sp(sp):
    if sp in info_cache:
        return info_cache[sp]
    return None

def add_function_range(sp, start, end):
    info_cache[sp] = [start, end]

def clear_cache(*args, **kwargs):
    global info_cache
    info_cache = {}

gdb.events.cont.connect(clear_cache)

class FrameId(object):
    def __init__(self, sp, pc):
        self.sp = sp
        self.pc = pc

class LibjitFrameDecorator(FrameDecorator):
    def __init__(self, base, start, end):
        super(LibjitFrameDecorator, self).__init__(base)
        self.start = start
        self.end = end

    def function(self):
        return "JIT[0x%x, 0x%x]" % (self.start, self.end)

class LibjitFrameFilter(object):
    def __init__(self):
        self.name = "Libjit"
        self.enabled = True
        self.priority = 100

    def maybe_wrap(self, frame):
        rbp = long(frame.inferior_frame().read_register("rbp"))
        vals = find_by_sp(rbp)
        if vals is None:
            return frame
        return LibjitFrameDecorator(frame, vals[0], vals[1])

    def filter(self, frame_iter):
        return imap(self.maybe_wrap, frame_iter)

class LibjitUnwinder(gdb.unwinder.Unwinder):
    def __init__(self):
        super(LibjitUnwinder, self).__init__("Libjit")
        self.enabled = True

    def our_frame(self, pc, rbp):
        pc = long(pc)
        # FIXME - there's no way to get this generally,
        # so this is Emacs-specific.
        context = gdb.lookup_global_symbol("emacs_jit_context").value()
        if long(context) == 0:
            return False
        func = context['functions']
        while long(func) != 0:
            if pc >= long(func["entry_point"]) and pc < long(func["code_end"]):
                add_function_range(long(rbp), long(func["entry_point"]),
                                   long(func["code_end"]))
                return True
            func = func["next"]
        return False

    def __call__(self, pending_frame):
        # Just x86-64 for now.
        pc = pending_frame.read_register("rip")
        rbp = pending_frame.read_register("rbp")
        if not self.our_frame(pc, rbp):
            return None

        # Convenient type to work with.
        ptr = gdb.lookup_type("void").pointer().pointer()

        # Previous frame pointer is at 0(%rbp).
        as_ptr = rbp.cast(ptr)
        prev_rbp = as_ptr.dereference()
        # Previous PC is at 8(%rbp)
        prev_pc = (as_ptr + 1).dereference()

        frame_id = FrameId(prev_rbp, prev_pc)
        unwind_info = pending_frame.create_unwind_info(frame_id)
        unwind_info.add_saved_register("rip", prev_pc)
        unwind_info.add_saved_register("rbp", prev_rbp)

        return unwind_info

def register_unwinder(objf):
    # Register the unwinder.
    unwinder = LibjitUnwinder()
    gdb.unwinder.register_unwinder(objf, unwinder, replace=True)
    # Register the frame filter.
    filt = LibjitFrameFilter()
    if objf is None:
        objf = gdb
    objf.frame_filters[filt.name] = filt

register_unwinder(None)
