#!/usr/bin/env python
from decorator import decorator
from collections import OrderedDict

###############################################################################
# Metaclass
###############################################################################

class MetaProcess(type):
    @classmethod
    def __prepare__(cls, name, bases):
        return OrderedDict()

    def __new__(cls, name, bases, clsdict):
        _live = [ key for key, val in clsdict.items()
                  if isinstance(val, Live) ]
        for name in _live:
            clsdict[name].name = name
        for base in bases:
            if "_live" in base.__dict__:
                _live.extend(base._live)
        clsdict["_live"] = _live
        clsobj = super().__new__(cls, name, bases,
                                 dict(clsdict))
        return clsobj


###############################################################################
# Getters/Setters
###############################################################################

class Live:
    """This descriptor allows attributes to determine if they have been
    modified.

    This is useful for things like registers or file descriptors. On
    set it adds

    """
    def __init__(self):
        self.name = None
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


@decorator
def advance(fn, cls, *args, **kwargs):
    for attr in cls._live:
        cls._invalidate_attr(attr)
    return fn(cls, *args, **kwargs)

