#!/usr/bin/env python
"""A simple ctypes python wrapper designed to be simple, geneirc,
clear, and pythonic.

I was going to name this project pytrace or ptracepy, but there are so
damn many projects with names similar already that I decided to name
it something totally different. Since one of my ideas was ptracepy
(pronounced "pee trace pie") I figured urinalcake was close enough.

"""

from .native import PtraceProcess, attach_process, launch_process

# class Process(PtraceProcess):
#     pass

Process = PtraceProcess

###############################################################################
# Exposed functions
###############################################################################


def trace(pid):
    attach_process(pid)
    return Process(pid)

def launch(*args):
    """This should launch a process traced. 

    Arguments are passed directly in to execl, then the process is
    launched. 

    >>> p = launch('/bin/ls', 'ls')

    """
    p = launch_process(*args)
    return Process(p)

#attach = trace


