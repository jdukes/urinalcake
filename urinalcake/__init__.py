#!/usr/bin/env python
#This is going to need to be broken up in to a bunch of different files
# move all class definitions to a sub file classes
# move all ctypes stuff to a dir containing
#    wrappers, type defs, and static variable defs
"""A simple ctypes python wrapper designed to be simple, geneirc,
clear, and pythonic.

I was going to name this project pytrace or ptracepy, but there are so
damn many projects with names similar already that I decided to name
it something totally different. Since one of my ideas was ptracepy
(pronounced "pee trace pie") I figured urinalcake was close enough.

"""
import os

import inspect
import functools

from native import Regs, FPRegs, Siginfo, ptrace, syscall_info



###############################################################################
# Meta
###############################################################################

class Live(object):
    """This descriptor allows attributes to determine if they have been
modified.

    This is useful for things like registers or file descriptors. On
    set it adds

    """
    def __init__(self, name=None):
        self.name = name
        self.val = None
    
    def __get__(self, instance, objtype):
        if self.name in instance._get_update:
            instance._update_attr(self.name)
        return self.val

    def __set__(self, instance, val):
        self.val = val
        instance._set_update.add(self.name)


def advance(fn):
    #watch that video again and fix this
    argspec = inspect.getargspec(fn)
    @functools.wraps(fn)
    def update_and_invalidate(cls, *args, **kwargs):
        for attr in cls._invalidate_on_advance:
            cls._invalidate_attr(attr)
        return fn(cls, *args, **kwargs)
    return update_and_invalidate


###############################################################################
# Classes
###############################################################################

#Create class of SeizedProcess, AttachedProcess, and NewProcess
#(traceme) that operate differently and inherit from Process
# debug(pid) should default to returning a SeizedProcess

class Permissions:

    def __init__(self, perms_string):
        self.perms_string = perms_string
        perms = list(perms_string)
        for (perm,symbol) in (('private','p'),
                              ('exec','x'),
                              ('write','w'),
                              ('read','r')):
            self.__setattr__(perm, perms.pop() == symbol)
        self.shared = not self.private

    def __repr__(self):
        return "<Permission %s>" % self.perms_string


class MemMap(list):

    def __init__(self, process):
        super().__init__(self)
        self.process = process
        maps = open('/proc/%s/maps' % process.pid)
        self.extend(Memory(self.process, line) for line in maps)
        maps.close()

    def get_stack(self):
        return next(m for m in self if m.name == '[stack]')

    def get_addr_in_maps(self, addr):
        return [m for m in self if m.contains_addr(addr)]


class Memory:

    def __init__(self, process, mapsline):
        mapsline = mapsline.split()
        memrange, perms, offset, dev, inode = mapsline[:5]
        if len(mapsline) > 5:
            name = mapsline[-1]
        else:
            name = None
        start, end = memrange.split('-')
        self.start = int(start, 16)
        self.end = int(end, 16)
        self.size = self.end - self.start
        self.perms = Permissions(perms)
        self.name = name
        self.process = process

    def contains_addr(self, addr):
        return self.end > addr > self.start

    def __repr__(self):
        descrip = "start=%s " % hex(self.start)
        descrip += "end=%s " % hex(self.end)
        descrip += "perms=%(perms)s" % self.__dict__
        if self.name:
            descrip += " name=%s" % self.name
        return "<Memory %s>" % descrip

    def read(self, num_bytes=None):
        if not num_bytes:
            num_bytes = self.size
        return _dump_mem(self.process.pid, self.start, num_bytes)

    def read_from_frame(self, num_bytes=None):
        if not num_bytes:
            num_bytes = self.size
        regs = self.process.get_regs()
        return _dump_mem(self.process.pid, self.process.regs.get_agnostic("sp"), num_bytes)


class Process:
    regs = Live("regs")
    fpregs = Live("fpregs")
    # mmap = Live("mmap")
    _invalidate_on_advance = set(("regs", "fpregs")) 
    #this could be done in a
    #metaclass where all Live objects
    #are added to the invalidate list

    def __init__(self, pid):
        #add setopts
        self.pid = pid
        self.iter_method = "step"
        self.mmap = MemMap(self)
        self.stack = self.mmap.get_stack()
        self._set_update = set()
        self._get_update = set(("regs", "fpregs"))
        
    def iter_step(self):
        while self.step():
            yield self
        raise StopIteration

    def iter_syscall(self):
        while self.next_syscall():
            yield self
        raise StopIteration
    
    @advance
    def cont(self):
        _continue(self.pid)

    @advance
    def next_syscall(self):
        #fucking magnets
        _next_syscall(self.pid)
        os.wait()

    @advance
    def step(self):
        _single_step(self.pid)
        #make sure the process is still running
        os.wait()

    def get_signal(self):
        return _get_siginfo(self.pid)

    def _update_attr(self, attr):
        if attr == "regs":
            self.regs = _getregs(self.pid)
        elif attr == "fpregs":
            self.fpregs = _getfpregs(self.pid)
        elif attr == "mmap":
            self.mmap = MemMap(self)

    def _invalidate_attr(self, attr):
        self._get_update.add(attr)

    def _set_regs(self):
        _setregs(self.pid, self._regs)

    def detach(self):
        #fucking magnets
        try:
            os.kill(self.pid, signal.SIGINT)
            _detach(self.pid)
        except:
            self.cont()
            _detach(self.pid)

    def wait(self):
        os.wait()

    def stop(self):
        os.kill(signal.SIGSTOP)

    def read_from_frame(self, num_bytes):
        return self.stack.read_from_frame(num_bytes)

Process.syscall_info = syscall_info


###############################################################################
# Exposed functions
###############################################################################


def trace(pid):
    _attach(pid)
    return Process(pid)

attach = trace


if __name__ == "__main__":
    import doctest
    if not doctest.testmod().failed:
        open("README.md",'w').write(__doc__)
