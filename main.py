#!/usr/bin/env python
# -*- coding: utf-8 -*-

from emu import EmuArm, EmuX86
from functions import Fstrncpy, Fmemcpy, Fstrncat, Fmempcpy, Fstpncpy, Fmemset, Fstrlen
from tqdm import tqdm
from multiprocessing import Pool
from functools import partial
import idb
import logging
import sys

def findAllFunction(idbpath):
    r = []
    with idb.from_file(idbpath) as db:
        api = idb.IDAPython(db)
        for addr in api.idautils.Functions():
            r.append(api.ida_funcs.get_func(addr))
    return r

def findOneFunction(idbpath, addr):
    r = []
    with idb.from_file(idbpath) as db:
        api = idb.IDAPython(db)
        r.append(api.ida_funcs.get_func(addr))
    return r

def initProcEmu(idbpath):
    global e
    #e = EmuArm(32)
    e = EmuX86(64)
    e.logger.setLevel(logging.WARN)
    e.loadIdb(idbpath)
    e.preStack()

def testFunc(function, func):
    global e
    t = function(e, func.startEA, func.endEA)
    e.resetRegs()
    e.preStack()
    if t.test():
        tqdm.write('{}: 0x{:x}'.format(t.name, func.startEA))

def main():
    idbpath = sys.argv[1]
    libfuncs = [Fstrncpy, Fmemcpy, Fstrncat, Fmempcpy, Fstpncpy, Fmemset, Fstrlen]
    funcs = findAllFunction(idbpath)
    with Pool(processes=12, initializer=initProcEmu, initargs=(idbpath,)) as p:
        for f in libfuncs:
            it = tqdm(p.imap(partial(testFunc, f), funcs), total=len(funcs))
            r = list(it)

def test(addr, function):
    idbpath = sys.argv[1]
    funcs = findOneFunction(idbpath, addr)
    e = EmuX86(64)
    e.logger.setLevel(logging.DEBUG)
    e.loadIdb(idbpath)
    e.preStack()
    for func in funcs:
        t = function(e, func.startEA, func.endEA)
        if t.test():
            tqdm.write('{}: 0x{:x}'.format(t.name, func.startEA))
    exit(0)


if __name__ == '__main__':
    #test(740656, Fstrlen)
    main()