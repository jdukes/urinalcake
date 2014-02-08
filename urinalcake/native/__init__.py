#!/usr/bin/env python

import struct
import ctypes
import ctypes.util
import signal
import platform

from os import wait, kill, execl, fork
from sys import stdout

from ..meta import Live, advance, MetaProcess

#__all__ = []

libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)

#this may be linux specific
libc.__errno_location.restype = ctypes.POINTER(ctypes.c_int)
get_errno_loc = libc.__errno_location

ptrace = libc.ptrace
WORD_LEN = ctypes.sizeof(ctypes.c_void_p)

errors = {
    1: "Ptrace Permission denied", #'EPERM',
    3: ('The specified process does not exist, '
        'is not being traced, or has not stopped'),
    # ^ ESRC
    5: "Memory Access Volation - EIO",
    14: "Memory Access Volation - EFAULT",
    16: "There was an error with allocating or freeing a debug register.",
    # ^ EBUSY
    22: "An attempt was made to set an invalid option."} #EINVAL

PROCESS_ALIVE = 1407 #???
PTRACE_TRACEME = 0
PTRACE_PEEKTEXT = 1
PTRACE_PEEKDATA = 2
PTRACE_PEEKUSER = 3
PTRACE_POKETEXT = 4
PTRACE_POKEDATA = 5
PTRACE_POKEUSER = 6
PTRACE_CONT = 7
PTRACE_KILL = 8
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_GETFPREGS = 14
PTRACE_SETFPREGS = 15
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_GETFPXREGS = 18
PTRACE_SETFPXREGS = 19
PTRACE_SYSCALL = 24
PTRACE_SETOPTIONS = 0x4200
PTRACE_GETEVENTMSG = 0x4201
PTRACE_GETSIGINFO = 0x4202
PTRACE_SETSIGINFO = 0x4203
PTRACE_GETREGSET = 0x4204
PTRACE_SETREGSET = 0x4205
PTRACE_SEIZE = 0x4206
PTRACE_INTERRUPT = 0x4207
PTRACE_LISTEN = 0x4208
PTRACE_PEEKSIGINFO = 0x4209

#/usr/include/asm-generic/signal.h
#/usr/include/sys/syscall.h
#/usr/include/asm/unistd_64.h


###############################################################################
# Type validataion and error checking
###############################################################################

def errcheck(ret, func, args):
    # make cross platform
    if ret != 0:
        e = ctypes.get_errno()
        ctypes.set_errno(0)
        if e in errors:
            #make this different exceptions
            raise OSError(errors[e])
    return ret

ptrace.argtypes = (ctypes.c_int, ctypes.c_uint,
                   ctypes.c_void_p, ctypes.c_void_p)
ptrace.errcheck = errcheck
if platform.machine() == 'x86_64':
    ptrace.restype = ctypes.c_ulonglong
else:
    ptrace.restype = ctypes.c_ulong



###############################################################################
# CType Definitions
###############################################################################

class Siginfo(ctypes.Structure):
    """The siginfo_t struct
    """
    _fields_ = (
        ("si_signo", ctypes.c_int),
        ("si_errno", ctypes.c_int),
        ("si_code", ctypes.c_int),
        ("si_trapno", ctypes.c_int),
        ("si_pid", ctypes.c_int),
        ("si_uid", ctypes.c_int),
        ("si_status", ctypes.c_int),
        #this needs to be fixed. need to get actual clock_t size per platform
        ("si_utime", ctypes.c_ulong),
        ("si_stime", ctypes.c_ulong),
        #this needs to be fixed. need to get actual sigval_t size per platform
        ("si_value", ctypes.c_int),
        ("si_int", ctypes.c_int),
        ("si_ptr", ctypes.c_void_p),
        ("si_overrun", ctypes.c_int),
        ("overrun count", ctypes.c_int),
        ("si_timerid", ctypes.c_int),
        ("si_addr", ctypes.c_void_p),
        ("si_band", ctypes.c_long),
        ("si_fd", ctypes.c_int),
        ("si_addr_lsb", ctypes.c_short)
    )

    def __repr__(self):
        attrs = '\n '.join( "%s = %s" % (i[0],self.__getattribute__(i[0]))
                            for i in self._fields_)
        return "<siginfo_t\n %s>" % attrs


class Regs(ctypes.Structure):
    """The user_regs_struct from user.h
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._agnostic_names = ARCH_AGNOSTIC_REGS

    def __repr__(self):
        attrs = '\n '.join( "%s = %0.{}x".format(WORD_LEN*2) % \
                            (i[0],self.__getattribute__(i[0]))
                            for i in self._fields_)
        return "<user_regs_struct\n %s>" % attrs

    def get_agnostic(self, name):
        return self.__getattribute__(self._agnostic_names[name])


class FPRegs(ctypes.Structure):
    """The user_fpregs_struct from user.h
    """
    #this shit segfaults
    def __repr__(self):
        return "<user_fpregs_struct>"

################################################################################
# Platform/Arch Specific
################################################################################

def set_x86_regnames(prefix):
    REGS = dict((i, "%s%sx" % (prefix, i)) for i in ("a","b","c","d"))
    REGS.update(dict((r,"%s%s" % (prefix,r)) for r in ("ip",
                                                       "si",
                                                       "di",
                                                       "bp",
                                                       "sp")))
    return REGS

if platform.machine() == 'x86_64':
    #some of these will be pointers always, fix the defs to match
    ARCH_AGNOSTIC_REGS = set_x86_regnames("r")
    FPRegs._fields_ = [
        ("cwd", ctypes.c_ushort),
        ("swd", ctypes.c_ushort),
        ("ftw", ctypes.c_ushort),
        ("fop", ctypes.c_ushort),
        ("rip",ctypes.c_ulonglong),
        ("rdp",ctypes.c_ulonglong),
        ("mxcsr", ctypes.c_uint),
        ("mask", ctypes.c_uint),
        ("st_space", ctypes.c_uint * 32),
        ("xmm_space", ctypes.c_uint * 64),
        ("padding", ctypes.c_uint * 24)]
    Regs._fields_ = (
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong))
elif platform.machine() == 'i686':
    ARCH_AGNOSTIC_REGS = set_x86_regnames("e")
    FPRegs._fields_ = [
        ("cwd", ctypes.c_long),
        ("swd", ctypes.c_long),
        ("twd", ctypes.c_long),
        ("fip", ctypes.c_long),
        ("fcs", ctypes.c_long),
        ("foo", ctypes.c_long),
        ("fos", ctypes.c_long),
        ("st_space", ctypes.c_long * 20)]
    Regs._fields_ = (
        ("ebx", ctypes.c_long),
        ("ecx", ctypes.c_long),
        ("edx", ctypes.c_long),
        ("esi", ctypes.c_long),
        ("edi", ctypes.c_long),
        ("ebp", ctypes.c_long),
        ("eax", ctypes.c_long),
        ("xds", ctypes.c_long),
        ("xes", ctypes.c_long),
        ("xfs", ctypes.c_long),
        ("xgs", ctypes.c_long),
        ("orig_eax", ctypes.c_long),
        ("eip", ctypes.c_long),
        ("xcs", ctypes.c_long),
        ("eflags", ctypes.c_long),
        ("esp", ctypes.c_long),
        ("xss", ctypes.c_long))

###############################################################################
# Helper Functions
###############################################################################

def _traceme():
    """Internal wrapper for PTRACE_TRACEME, only used in luanch_process."""
    ptrace(PTRACE_TRACEME, 0, 0, 0)

def attach_process(pid):
    """Internal wrapper for PTRACE_ATTACH.

    This must be run as root or on a child process on modern
    unices. To execute this as a stand alone function in an
    interactive shell requires a bit of mad hackery...
    
    >>> launch = lambda *args: fork() or execl(*args)
    >>> attach_process(launch('/bin/ls', 'ls'))

    You are now attached. Of course you don't know the pid... so,
    there's that. This function is not intended to be used alone. 

    """
    ptrace(PTRACE_ATTACH, pid, 0, 0)

def launch_process(filename, *args):
    """Launch a process traced, returns the pid.

    >>> pid = launch_process('/bin/ls', 'ls')
    
    You are now attached.    
    """
    child = fork()
    if (child == 0):
        ptrace(PTRACE_TRACEME, 0, 0, 0)
        execl(filename, *args)
    else:
        pid, signal = wait()
        while not pid == child:
            pid, signal = wait()
        return child

def _getregs(pid):
    """Internal wrapper for PTRACE_GETREGS which returns a Regs object.

    Regs is a ctypes wrapper that also provides an arch agnostic way
    to access registers.

    >>> pid = launch_process('/bin/ls', 'ls')
    >>> regs = _getregs(pid)
    >>> instruction_pointer = regs.get_agnostic("ip")
    >>> type(instruction_pointer)
    <class 'int'>

    """
    regs = Regs()
    ptrace(PTRACE_GETREGS, pid, 0, ctypes.byref(regs));
    return regs


def _peek_data(pid, addr):
    """Internal wrapper for PTRACE_PEEKDATA, returns a numeric value.

    The numeric value returned from _peek_data is one WORD:

    >>> pid = launch_process('/bin/ls', 'ls')
    >>> regs = _getregs(pid)
    >>> instruction_pointer = regs.get_agnostic("ip")
    >>> data = _peek_data(pid, instruction_pointer)
    >>> len(data) == ctypes.sizeof(ctypes.c_void_p)
    True
    
    It will raise an exception if you try to access an invalid memory
    location:

    >>> try:
    ... 	data = _peek_data(pid, 0)
    ... except OSError as e:
    ... 	print(e)
    ... 
    Memory Access Volation - EIO

    """
    data = ptrace(PTRACE_PEEKDATA, pid, addr, 0)
    if WORD_LEN == 8:
        return struct.pack('q', data)
    if WORD_LEN == 4:
        return struct.pack('l', data)


def _dump_mem(pid, addr, num_bytes):
    """Helper function for that wrapps _peek_data returning bytes.

    This function allows you to dump a number of bytes of memory
    starting at an address from a given traced pid.

    >>> pid = launch_process('/bin/ls', 'ls')
    >>> regs = _getregs(pid)
    >>> instruction_pointer = regs.get_agnostic("ip")
    >>> len(_dump_mem(pid, instruction_pointer, 10))
    10

    """
    buf = b""
    for a in range(addr, addr + num_bytes, WORD_LEN):
        buf += _peek_data(pid, a)
    return buf[:num_bytes]


def _peek_user(pid, addr):
    """Internal wrapper for PTRACE_PEEKUSER, returns a word.

    This dumps the USER area, which contains regs and such. It is not
    useful for us as we have other functions that do the same thing in
    a better way. This code exists for consistency. Basically, fuck
    this shit.

    """
    assert addr % WORD_LEN == 0, "addr must be word aligned"
    return ptrace(PTRACE_PEEKUSER, pid, addr, 0)


def _setregs(pid, regs):
    """Internal wrapper for PTRACE_SETREGS.

    This function allows you to set registers.
    """
    #!!fill out unit testing for this
    return ptrace(PTRACE_SETREGS, pid, 0, ctypes.byref(regs));


def _getfpregs(pid):
    fpregs = FPRegs()
    ptrace(PTRACE_GETFPREGS, pid, 0, ctypes.byref(fpregs));
    return fpregs


def _get_siginfo(pid):
    sig = Siginfo()
    ptrace(PTRACE_GETSIGINFO, pid, 0, ctypes.byref(sig))
    return sig


def _set_siginfo(pid, sig):
    return ptrace(PTRACE_SETSIGINFO, pid, 0, ctypes.byref(sig))


def _continue(pid):
    ptrace(PTRACE_CONT, pid, 0, 0)

#PTRACE_SETOPTIONS


def _next_syscall(pid):
    ptrace(PTRACE_SYSCALL, pid, 0, 0)


def _single_step(pid):
    ptrace(PTRACE_SINGLESTEP, pid, 0, 0)


#PTRACE_LISTEN


def _kill(pid):
    ptrace(PTRACE_KILL, pid, 0, 0)


def _interrupt(pid):
    ptrace(PTRACE_INTERRUPT, pid, 0, 0)


#PTRACE_SEIZE

def _detach(pid):
    ptrace(PTRACE_DETACH, pid, 0, 0)


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
        try:
            return next(m for m in self if m.name == '[stack]')
        except StopIteration:
            return None

    def get_addr_in_maps(self, addr):
        return [m for m in self if m.contains_addr(addr)]



class Memory:
    #I feel as though memory objects should expose a file like interface. 

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


class GenericProcess(metaclass=MetaProcess):
    regs = Live()
    fpregs = Live()
    mmap = Live()
    stack = Live()
    last_sig = Live()

    def __init__(self, pid):
        #add setopts
        self.pid = pid
        self._set_update = set()
        self._get_update = set(self._live)
        
    def __del__(self):
        self.detach()
        
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
        pid, status = wait()
        return status == PROCESS_ALIVE

    @advance
    def step(self):
        """Single step the process

        """
        _single_step(self.pid)
        pid, status = wait()
        return status == PROCESS_ALIVE

    def get_signal(self):
        return _get_siginfo(self.pid)

    def _update_attr(self, attr):
        #actually... I can make Live take an update function and this
        #goes away.
        if attr == "regs":
            self.regs = _getregs(self.pid)
        elif attr == "fpregs":
            self.fpregs = _getfpregs(self.pid)
        elif attr == "mmap":
            self.mmap = MemMap(self)
        elif attr == "stack":
            self.stack = self.mmap.get_stack()
        elif attr == "last_sig":
            self.last_sig = self.get_signal()

    def _invalidate_attr(self, attr):
        self._get_update.add(attr)

    def _set_regs(self):
        _setregs(self.pid, self._regs)

    def detach(self):
        #fucking magnets
        try:
            kill(self.pid, signal.SIGINT)
            _detach(self.pid)
        except:
            self.cont()
            _detach(self.pid)

    def wait(self):
        #make everything use this and record status for future use
        pid, status = wait()
        while not pid == self.pid:
            pid, status = wait()
        return pid, sig
        
    def kill(self):
        _kill(self.pid)

    def stop(self):
        kill(signal.SIGSTOP)

    def read_from_frame(self, num_bytes):
        return self.stack.read_from_frame(num_bytes)

