# Licensed under the Apache License: http://www.apache.org/licenses/LICENSE-2.0
# For details: https://github.com/nedbat/coveragepy/blob/master/NOTICE.txt

"""Dump information so we can get a quick look at what's available."""

import platform
import sys


def whatever(f):
    try:
        return f()
    except:
        return f


def dump_module(mod):
    print("\n###  {} ---------------------------".format(mod.__name__))
    for name in dir(mod):
        if name.startswith("_"):
            continue
        print("{:30s}: {!r:.100}".format(name, whatever(getattr(mod, name))))


for mod in [platform, sys]:
    dump_module(mod)
