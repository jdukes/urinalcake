#!/usr/bin/env python
import doctest
import urinalcake

if not ( doctest.testmod(m=urinalcake).failed or 
         doctest.testmod(m=urinalcake.native).failed):
    open("README.md",'w').write(__doc__)
