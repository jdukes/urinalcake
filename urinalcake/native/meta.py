#!/usr/bin/env python
import inspect
import functools

###############################################################################
# getters/Setters
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

###############################################################################
# Decorators
###############################################################################


def advance(fn):
    #watch that video again and fix this
    argspec = inspect.getargspec(fn)
    @functools.wraps(fn)
    def update_and_invalidate(cls, *args, **kwargs):
        for attr in cls._invalidate_on_advance:
            cls._invalidate_attr(attr)
        return fn(cls, *args, **kwargs)
    return update_and_invalidate

