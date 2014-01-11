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
import signal
import ctypes
import ctypes.util
import struct

import platform

def debug(func):
    
    return lambda *args, **kwargs: func(*args, **kwargs)

#libc = ctypes.cdll.LoadLibrary(ctypes.util.find_library('c'))
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
# Type Definitions
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
    def __repr__(self):
        attrs = '\n '.join( "%s = %0.{}x".format(WORD_LEN*2) % \
                            (i[0],self.__getattribute__(i[0]))
                            for i in self._fields_)
        return "<user_regs_struct\n %s>" % attrs


class FPRegs(ctypes.Structure):
    """The user_fpregs_struct from user.h
    """
    #this shit segfaults
    def __repr__(self):
        return "<user_fpregs_struct>"


#platform_specific
if platform.machine() == 'x86_64': 
    #some of these will be pointers always, fix the defs to match
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
else:
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


def _attach(pid):
    ptrace(PTRACE_ATTACH, pid, 0, 0) 


def _detach(pid):
    ptrace(PTRACE_DETACH, pid, 0, 0) 


def _peek_data(pid, addr):
    data = ptrace(PTRACE_PEEKDATA, pid, addr, 0)
    if WORD_LEN == 8:
        return struct.pack('q', data)
    if WORD_LEN == 4:
        return struct.pack('l', data)


def _peek_user(pid, addr):
    assert addr % WORD_LEN == 0, "addr must be word aligned"
    return ptrace(PTRACE_PEEKUSER, pid, addr, 0)


def _getregs(pid):
    regs = Regs()
    ptrace(PTRACE_GETREGS, pid, 0, ctypes.byref(regs));
    return regs


def _setregs(pid, regs):
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
    

###############################################################################
# Classes
###############################################################################

#Create class of SeizedProcess, AttachedProcess, and NewProcess
#(traceme) that operate differently

class Process:

    def __init__(self, pid, **options):
        
        #add setopts
        self.pid = pid
        self.iter_method = "step"


    def __iter__(self):
        return self

    def cont(self):
        _continue(self.pid)

    def set_iter_method(self, method):
        assert method in ["step", "syscall"], "Must be one of step or syscall"
        self.iter_method = method

    def next(self):
        if self.iter_method == "step":
            return self.step()
        elif self.iter_method == "syscall":
            return self.next_syscall()

    def next_syscall(self):
        #fucking magnets
        _next_syscall(self.pid)
        os.wait()
        return self

    def step(self):
        _single_step(self.pid)
        os.wait()
        return self

    def get_regs(self):
        self._update_regs()
        return self.regs
        
    def get_sig(self):
        return _get_siginfo(self.pid)

    def _update_regs(self):
        self.regs = _getregs(self.pid)

    def set_regs(self):
        _setregs(self.pid, self.regs)

    def dump_mem(self, addr, num_bytes):
        buf = ""
        for a in xrange(addr, addr + num_bytes, WORD_LEN):
            buf += _peek_data(self.pid, a)
        return buf[:num_bytes]

    def detach(self):
        #fucking magnets
        try:
            self.cont()
            _detach(self.pid)
        except:
            os.kill(self.pid, signal.SIGINT)
            _detach(self.pid)

    def wait(self):
        os.wait()
        
    def stop(self):
        os.kill(signal.SIGSTOP)
        
    

if platform.machine() == 'x86_64': 
    def _syscall_info(self):
        return {"syscall_number": self.regs.orig_rax,
                "args":[self.regs.rdi,
                    
                        self.regs.rsi,
                        self.regs.rdx,
                        self.regs.r10,
                        self.regs.r8,
                        self.regs.r9]}
else:
    def _syscall_info(self):
        return {"syscall_number": self.regs.orig_eax,
                "args":[self.regs.ebx,
                        self.regs.ecx,
                        self.regs.edx,
                        self.regs.esi,
                        self.regs.edi,
                        self.regs.ebp]}

Process.syscall_info = _syscall_info
    

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
