#!/usr/bin/env python
# -*- coding: utf-8 -*-

from emu import EmuArm, EmuX86, EmuMips, EmuPpc
from tqdm import tqdm
from multiprocessing import Pool
from functools import partial
import idb
import logging
import sys

idbfileformatLogger = logging.getLogger('idb.fileformat')
idbfileformatLogger.setLevel(logging.ERROR)

def findAllFunction(idbpath):
    r = []
    with idb.from_file(idbpath) as db:
        api = idb.IDAPython(db)
        for addr in api.idautils.Functions():
            r.append(api.ida_funcs.get_func(addr))
    return r

def findArchInfo(idbpath):
    '''
    Determine Processs Arch/bitness/endian
    learned from https://reverseengineering.stackexchange.com/questions/11396/how-to-get-the-cpu-architecture-via-idapython
    '''
    with idb.from_file(idbpath) as db:
        api = idb.IDAPython(db)
        inf = api.idaapi.get_inf_structure()
        if inf.is_64bit():
            bits = 64
        elif inf.is_32bit():
            bits = 32
        else:
            bits = 16
        try:
            is_be = inf.is_be()
        except:
            is_be = inf.mf
        endian = 'be' if is_be else 'le'
        if inf.filetype == 11:
            filetype = 'PE'
        elif inf.filetype == 25:
            filetype = 'MACHO'
        elif inf.filetype == 18:
            filetype = 'ELF'
        else:
            filetype = 'unk'
        return (inf.procname, bits, endian, filetype)

def initProcEmu(idbpath, initEmu):
    global e
    e = initEmu()
    e.logger.setLevel(logging.WARN)
    e.loadIdb(idbpath)
    e.preStack()

def testFunc(function, func):
    global e
    t = function(e, func.startEA, func.endEA)
    if t.test():
        tqdm.write('{}: 0x{:x}'.format(t.name, func.startEA))

def genInitEmu(idbpath):
    arch, bitness, endian, filetype = findArchInfo(idbpath)
    if arch == 'ARM':
        if bitness == 32 and endian == 'le':
            initEmu = lambda: EmuArm(32, endian=endian)
        else:
            raise Exception('Unimplement')
    elif arch in ('metapc','8086','80286r','80286p','80386r','80386p','80486r','80486p','80586r','80586p','80686p','k62','p2','p3','athlon','p4','8085'):
        if bitness in (64, 32) and endian in ('le', ):
            if filetype == 'PE':
                initEmu = lambda: EmuX86(bitness, endian=endian, convention=EmuX86.CC_WIN64)
            else:
                initEmu = lambda: EmuX86(bitness, endian=endian)
        else:
            raise Exception('Unimplement')
    elif arch == 'mipsl' and endian == 'le':
            initEmu = lambda: EmuMips(bitness, endian)
    elif arch == 'mipsb' and endian == 'be':
            initEmu = lambda: EmuMips(bitness, endian)
    elif arch == 'PPC': #or arch == 'PPCL':
            initEmu = lambda: EmuPpc(bitness, endian)
    else:
        raise Exception('Unimplement')
    return initEmu

from glibc import *
from ntoskrnl import *

def main():
    idbpath = sys.argv[1]
    initEmu = genInitEmu(idbpath)
    libfuncs = []
    libfuncs += [Fstrncpy, Fmemcpy, Fstrncat, Fmempcpy, Fstpncpy, Fmemset, Fstrlen, Fstrcpy, Fmemcmp, Fstrcmp, Fstrncmp]
    libfuncs += [Fmemcpy_s]
    funcs = findAllFunction(idbpath)
    tqdm.write('there are {} functions in idb, and {} lib functions to match'.format(len(funcs), len(libfuncs)))
    with Pool(processes=12, initializer=initProcEmu, initargs=(idbpath, initEmu)) as p:
        for f in libfuncs:
            it = tqdm(p.imap(partial(testFunc, f), funcs), total=len(funcs))
            r = list(it)

if __name__ == '__main__':
    main()
