#!/usr/bin/env python
# -*- coding: utf-8 -*-
import unicorn as uc
import idb
import logging
import struct

logging.basicConfig(level=logging.WARN)


class Emu(object):
    def __init__(self, arch, ptrSize: int, pageSize: int=1024):
        self._ptrSize = ptrSize
        self._arch = arch
        self._pageSize = pageSize
        self._initRegs()
        self.initUc()
        self.initHook()
        self.stack = None
        self.logger = logging.getLogger('Emu')
        self.logger.setLevel(logging.DEBUG)

    def pageAlign(self, size:int) -> int:
        return (size + (self._pageSize - size % self._pageSize))
    
    def startEmu(self, startEa, endEa, count=1000):
        try:
            self.target.emu_start(startEa, endEa, count=count)
        except uc.unicorn.UcError as e:
            self.logger.debug('run into Error @ 0x{:x}, Error:'.format(self.readReg('pc')))
            self.logger.debug(e)

    def initUc(self):
        raise Exception('need implement')
    
    def initHook(self):
        self.target.hook_add(uc.UC_HOOK_MEM_READ_UNMAPPED | uc.UC_HOOK_MEM_WRITE_UNMAPPED |uc.UC_HOOK_MEM_FETCH_UNMAPPED, self._hookMemInvalid, ())
        self.target.hook_add(uc.UC_HOOK_INSN_INVALID, self._hookInsnInvalid, ())

    def preStack(self):
        if self.stack is None:
            addr = self.allocMem(0x20000)
            mid = addr + 0x10000
            self.writeReg('sp', mid)
            self.stack = mid
        else:
            mid = self.stack
            self.writeReg('sp', mid)
        return self.stack

    def _initRegs(self):
        raise Exception('need implement')


    def loadIdb(self, path):
        class Segement(object):
            def __init__(self, start, end, size, name, data):
                self.start = start
                self.end = end
                self.size = size
                self.name = name
                self.data = data
        segs = []
        with idb.from_file(path) as db:
            api = idb.IDAPython(db)
            for segStart in api.idautils.Segments():
                segEnd = api.idaapi.get_segm_end(segStart)
                segSize = segEnd - segStart
                segs.append(Segement(segStart, segEnd, segSize, api.idaapi.get_segm_name(segStart), api.ida_bytes.get_bytes(segStart, segSize)))
        merged_segs = []
        for seg in segs:
            if not merged_segs or merged_segs[-1].end != seg.start:
                merged_segs.append(seg)
            else :
                old = merged_segs[-1]
                merged_segs[-1] = Segement(old.start, seg.end, old.size+seg.size, '&'.join((old.name,seg.name)), old.data+seg.data)
        for seg in merged_segs:
            self.logger.debug('start mapping segment:{} at 0x{:x}-0x{:x}'.format(seg.name, seg.start, seg.end))
            mask = (1<<self._ptrSize)-1-(self._pageSize-1)
            segStart = seg.start&(mask)
            segSize = self.pageAlign(seg.size)
            self.logger.debug('real mapping segment:{} at 0x{:x}-0x{:x}'.format(seg.name, segStart, segStart+segSize))
            self.target.mem_map(segStart, segSize)#, perms=uc.UC_PROT_EXEC|uc.UC_PROT_READ)
            self.target.mem_write(segStart, seg.data)
        self.logger.info('idb loading finished')

    def getArgv(self):
        raise Exception('need implement')
    
    def getRet(self):
        return Exception('need implement')
    
    def setArgv(self, num, value):
        return Exception('need implement')
        if self._arch == uc.UC_ARCH_ARM:
            argRegs = ('R0', 'R1', 'R2', 'R3')
            if num < len(argRegs):
                self.writeReg(argRegs[num], value)
            else:
                sp = self.readReg('sp')
                num = num - len(argRegs)
                self.writeMem(sp+(self._ptrSize/8*num), struct.pack('<I', value))
        else:
            raise Exception('not implement yet')
    
    def setRetAddr(self, addr):
        raise Exception('need implement')
    
    def setArgvAll(self, args:list):
        for i, v in enumerate(args):
            self.setArgv(i, v)
    
    def showMemRegions(self):
        self.logger.warn('memory region maps:')
        width = int(self._ptrSize/4)
        for region in self.target.mem_regions():
            perm = ['.']*3
            if region[2] & 0x1:
                perm[0] = 'R'
            if region[2] & 0x2:
                perm[1] = 'W'
            if region[2] & 0x4:
                perm[2] = 'X'
            self.logger.warn('addr: 0x{:0{width}x}, size: 0x{:0{width}x}, perm: {}'.format(region[0], region[1], "".join(perm), width=width))

    def showRegs(self):
        self.logger.warn('Registers:')
        for name in self.regs:
            self.logger.warn('  {} : 0x{:x}'.format(name, self.readReg(name)))
    
    def resetRegs(self):
        for name in self.regs:
            if self._arch == uc.UC_ARCH_ARM:
                if name in ('APSR', 'apsr'):
                    self.writeReg(name, 0x40000000)
                else:
                    self.writeReg(name, 0)

    def readReg(self, regName):
        regVal = self.target.reg_read(self.regs[regName])
        # handle various subregister addressing
        if self._arch == uc.UC_ARCH_X86:
            if regName[:-1] in ["l", "b"]:
                regVal = regVal & 0xFF
            elif regName[:-1] == "h":
                regVal = (regVal & 0xFF00) >> 8
            elif len(regName) == 2 and regName[:-1] == "x":
                regVal = regVal & 0xFFFF
            elif regName[0] == "e":
                regVal = regVal & 0xFFFFFFFF
            elif regName[:-1] == "d":
                regVal = regVal & 0xFFFFFFFF
            elif regName[:-1] == "w":
                regVal = regVal & 0xFFFF
        elif self._arch == uc.UC_ARCH_ARM64:
            if regName[0] == "W":
                regVal = regVal & 0xFFFFFFFF
        return regVal
    
    def writeReg(self, regName, value):
        self.target.reg_write(self.regs[regName], value)

    def _isRegionOverlap(self, addr, size):
        start = addr 
        end = addr + size
        for region in self.target.mem_regions():
            if (start >= region[0] and start < region[1]) or (end >= region[0] and end < region[1]):
                return True
            if start < region[0] and end > region[1]:
                return True

    def _findUnusedMem(self, size: int) -> int:
        candidate = 0x10000
        maxAddr = 0xffffffff
        size = self.pageAlign(size)
        while self._isRegionOverlap(candidate, size):
            candidate += 0x1000
        if candidate < maxAddr:
            return candidate
        return None

    def allocMem(self, size):
        addr = self._findUnusedMem(size)
        self.target.mem_map(addr , self.pageAlign(size))
        return addr

    def writeMem(self, addr, content):
        self.target.mem_write(addr, content)
    
    def readMem(self, addr, size):
        return self.target.mem_read(addr, size)
    
    def _hookMemInvalid(self, uc, access, address, size, value, data):
        self.logger.debug('Invalid memory access 0x{:x} @0x{:x}'.format(address, self.readReg('pc')))

    def _hookInsnInvalid(self, data, a):
        self.logger.debug('Invalid Insn {}, {}'.format(data, a))


class EmuArm(Emu):
    def __init__(self, ptrSize, **kwargs):
        super().__init__(uc.UC_ARCH_ARM, ptrSize, **kwargs)

    def initUc(self):
        self.target = uc.Uc(self._arch, uc.UC_MODE_ARM)
    
    def getArgv(self):
        sp = self.readReg("SP")
        argv = [
            self.readReg('R0'),
            self.readReg('R1'),
            self.readReg('R2'),
            self.readReg('R3'),
            struct.unpack('<I', self.readMem(sp, 4))[0],
            struct.unpack('<I', self.readMem(sp + 4, 4))[0],
            struct.unpack('<I', self.readMem(sp + 8, 4))[0],
            struct.unpack('<I', self.readMem(sp + 12, 4))[0]]
        return argv
    
    def setArgv(self, num, value):
        argRegs = ('R0', 'R1', 'R2', 'R3')
        if num < len(argRegs):
            self.writeReg(argRegs[num], value)
        else:
            sp = self.readReg('sp')
            num = num - len(argRegs)
            self.writeMem(sp+(self._ptrSize/8*num), struct.pack('<I', value))

    def getRet(self):
        return self.readReg('R0')

    def setRetAddr(self, addr):
        self.writeReg('LR', addr)

    def _initRegs(self):
        if self._ptrSize == 64:
            self.regs = {"R0": uc.arm64_const.UC_ARM64_REG_X0, "R1": uc.arm64_const.UC_ARM64_REG_X1,
                 "R2": uc.arm64_const.UC_ARM64_REG_X2, "R3": uc.arm64_const.UC_ARM64_REG_X3,
                 "R4": uc.arm64_const.UC_ARM64_REG_X4, "R5": uc.arm64_const.UC_ARM64_REG_X5,
                 "R6": uc.arm64_const.UC_ARM64_REG_X6, "R7": uc.arm64_const.UC_ARM64_REG_X7,
                 "R8": uc.arm64_const.UC_ARM64_REG_X8, "R9": uc.arm64_const.UC_ARM64_REG_X9,
                 "R10": uc.arm64_const.UC_ARM64_REG_X10, "R11": uc.arm64_const.UC_ARM64_REG_X11,
                 "R12": uc.arm64_const.UC_ARM64_REG_X12, "R13": uc.arm64_const.UC_ARM64_REG_X13,
                 "R14": uc.arm64_const.UC_ARM64_REG_X14, "R15": uc.arm64_const.UC_ARM64_REG_X15,
                 "X0": uc.arm64_const.UC_ARM64_REG_X0, "X1": uc.arm64_const.UC_ARM64_REG_X1,
                 "X2": uc.arm64_const.UC_ARM64_REG_X2, "X3": uc.arm64_const.UC_ARM64_REG_X3,
                 "X4": uc.arm64_const.UC_ARM64_REG_X4, "X5": uc.arm64_const.UC_ARM64_REG_X5,
                 "X6": uc.arm64_const.UC_ARM64_REG_X6, "X7": uc.arm64_const.UC_ARM64_REG_X7,
                 "X8": uc.arm64_const.UC_ARM64_REG_X8, "X9": uc.arm64_const.UC_ARM64_REG_X9,
                 "X10": uc.arm64_const.UC_ARM64_REG_X10, "X11": uc.arm64_const.UC_ARM64_REG_X11,
                 "X12": uc.arm64_const.UC_ARM64_REG_X12, "X13": uc.arm64_const.UC_ARM64_REG_X13,
                 "X14": uc.arm64_const.UC_ARM64_REG_X14, "X15": uc.arm64_const.UC_ARM64_REG_X15,
                 "X16": uc.arm64_const.UC_ARM64_REG_X16, "X17": uc.arm64_const.UC_ARM64_REG_X17,
                 "X18": uc.arm64_const.UC_ARM64_REG_X18, "X19": uc.arm64_const.UC_ARM64_REG_X19,
                 "X20": uc.arm64_const.UC_ARM64_REG_X20, "X21": uc.arm64_const.UC_ARM64_REG_X21,
                 "X22": uc.arm64_const.UC_ARM64_REG_X22, "X23": uc.arm64_const.UC_ARM64_REG_X23,
                 "X24": uc.arm64_const.UC_ARM64_REG_X24, "X25": uc.arm64_const.UC_ARM64_REG_X25,
                 "X26": uc.arm64_const.UC_ARM64_REG_X26, "X27": uc.arm64_const.UC_ARM64_REG_X27,
                 "X28": uc.arm64_const.UC_ARM64_REG_X28, "X29": uc.arm64_const.UC_ARM64_REG_X29,
                 "X30": uc.arm64_const.UC_ARM64_REG_X30, "W0": uc.arm64_const.UC_ARM64_REG_X0,
                 "W1": uc.arm64_const.UC_ARM64_REG_X1, "W2": uc.arm64_const.UC_ARM64_REG_X2,
                 "W3": uc.arm64_const.UC_ARM64_REG_X3, "W4": uc.arm64_const.UC_ARM64_REG_X4,
                 "W5": uc.arm64_const.UC_ARM64_REG_X5, "W6": uc.arm64_const.UC_ARM64_REG_X6,
                 "W7": uc.arm64_const.UC_ARM64_REG_X7, "W8": uc.arm64_const.UC_ARM64_REG_X8,
                 "W9": uc.arm64_const.UC_ARM64_REG_X9, "W10": uc.arm64_const.UC_ARM64_REG_X10,
                 "W11": uc.arm64_const.UC_ARM64_REG_X11, "W12": uc.arm64_const.UC_ARM64_REG_X12,
                 "W13": uc.arm64_const.UC_ARM64_REG_X13, "W14": uc.arm64_const.UC_ARM64_REG_X14,
                 "W15": uc.arm64_const.UC_ARM64_REG_X15, "W16": uc.arm64_const.UC_ARM64_REG_X16,
                 "W17": uc.arm64_const.UC_ARM64_REG_X17, "W18": uc.arm64_const.UC_ARM64_REG_X18,
                 "W19": uc.arm64_const.UC_ARM64_REG_X19, "W20": uc.arm64_const.UC_ARM64_REG_X20,
                 "W21": uc.arm64_const.UC_ARM64_REG_X21, "W22": uc.arm64_const.UC_ARM64_REG_X22,
                 "W23": uc.arm64_const.UC_ARM64_REG_X23, "W24": uc.arm64_const.UC_ARM64_REG_X24,
                 "W25": uc.arm64_const.UC_ARM64_REG_X25, "W26": uc.arm64_const.UC_ARM64_REG_X26,
                 "W27": uc.arm64_const.UC_ARM64_REG_X27, "W28": uc.arm64_const.UC_ARM64_REG_X28,
                 "W29": uc.arm64_const.UC_ARM64_REG_X29, "W30": uc.arm64_const.UC_ARM64_REG_X30,
                 "PC": uc.arm64_const.UC_ARM64_REG_PC, "pc": uc.arm64_const.UC_ARM64_REG_PC,
                 "LR": uc.arm64_const.UC_ARM64_REG_X30, "SP": uc.arm64_const.UC_ARM64_REG_SP,
                 "sp": uc.arm64_const.UC_ARM64_REG_SP, "ret": uc.arm64_const.UC_ARM64_REG_X0,
                 "S0": uc.arm64_const.UC_ARM64_REG_S0, "S1": uc.arm64_const.UC_ARM64_REG_S1,
                 "S2": uc.arm64_const.UC_ARM64_REG_S2, "S3": uc.arm64_const.UC_ARM64_REG_S3,
                 "S4": uc.arm64_const.UC_ARM64_REG_S4, "S5": uc.arm64_const.UC_ARM64_REG_S5,
                 "S6": uc.arm64_const.UC_ARM64_REG_S6, "S7": uc.arm64_const.UC_ARM64_REG_S7,
                 "S8": uc.arm64_const.UC_ARM64_REG_S8, "S9": uc.arm64_const.UC_ARM64_REG_S9,
                 "S10": uc.arm64_const.UC_ARM64_REG_S10, "S11": uc.arm64_const.UC_ARM64_REG_S11,
                 "S12": uc.arm64_const.UC_ARM64_REG_S12, "S13": uc.arm64_const.UC_ARM64_REG_S13,
                 "S14": uc.arm64_const.UC_ARM64_REG_S14, "S15": uc.arm64_const.UC_ARM64_REG_S15,
                 "S16": uc.arm64_const.UC_ARM64_REG_S16, "S17": uc.arm64_const.UC_ARM64_REG_S17,
                 "S18": uc.arm64_const.UC_ARM64_REG_S18, "S19": uc.arm64_const.UC_ARM64_REG_S19,
                 "S20": uc.arm64_const.UC_ARM64_REG_S20, "S21": uc.arm64_const.UC_ARM64_REG_S21,
                 "S22": uc.arm64_const.UC_ARM64_REG_S22, "S23": uc.arm64_const.UC_ARM64_REG_S23,
                 "S24": uc.arm64_const.UC_ARM64_REG_S24, "S25": uc.arm64_const.UC_ARM64_REG_S25,
                 "S26": uc.arm64_const.UC_ARM64_REG_S26, "S27": uc.arm64_const.UC_ARM64_REG_S27,
                 "S28": uc.arm64_const.UC_ARM64_REG_S28, "S29": uc.arm64_const.UC_ARM64_REG_S29,
                 "S30": uc.arm64_const.UC_ARM64_REG_S30, "S31": uc.arm64_const.UC_ARM64_REG_S31,
                 "D0": uc.arm64_const.UC_ARM64_REG_D0, "D1": uc.arm64_const.UC_ARM64_REG_D1,
                 "D2": uc.arm64_const.UC_ARM64_REG_D2, "D3": uc.arm64_const.UC_ARM64_REG_D3,
                 "D4": uc.arm64_const.UC_ARM64_REG_D4, "D5": uc.arm64_const.UC_ARM64_REG_D5,
                 "D6": uc.arm64_const.UC_ARM64_REG_D6, "D7": uc.arm64_const.UC_ARM64_REG_D7,
                 "D8": uc.arm64_const.UC_ARM64_REG_D8, "D9": uc.arm64_const.UC_ARM64_REG_D9,
                 "D10": uc.arm64_const.UC_ARM64_REG_D10, "D11": uc.arm64_const.UC_ARM64_REG_D11,
                 "D12": uc.arm64_const.UC_ARM64_REG_D12, "D13": uc.arm64_const.UC_ARM64_REG_D13,
                 "D14": uc.arm64_const.UC_ARM64_REG_D14, "D15": uc.arm64_const.UC_ARM64_REG_D15,
                 "D16": uc.arm64_const.UC_ARM64_REG_D16, "D17": uc.arm64_const.UC_ARM64_REG_D17,
                 "D18": uc.arm64_const.UC_ARM64_REG_D18, "D19": uc.arm64_const.UC_ARM64_REG_D19,
                 "D20": uc.arm64_const.UC_ARM64_REG_D20, "D21": uc.arm64_const.UC_ARM64_REG_D21,
                 "D22": uc.arm64_const.UC_ARM64_REG_D22, "D23": uc.arm64_const.UC_ARM64_REG_D23,
                 "D24": uc.arm64_const.UC_ARM64_REG_D24, "D25": uc.arm64_const.UC_ARM64_REG_D25,
                 "D26": uc.arm64_const.UC_ARM64_REG_D26, "D27": uc.arm64_const.UC_ARM64_REG_D27,
                 "D28": uc.arm64_const.UC_ARM64_REG_D28, "D29": uc.arm64_const.UC_ARM64_REG_D29,
                 "D30": uc.arm64_const.UC_ARM64_REG_D30, "D31": uc.arm64_const.UC_ARM64_REG_D31,
                 "H0": uc.arm64_const.UC_ARM64_REG_H0, "H1": uc.arm64_const.UC_ARM64_REG_H1,
                 "H2": uc.arm64_const.UC_ARM64_REG_H2, "H3": uc.arm64_const.UC_ARM64_REG_H3,
                 "H4": uc.arm64_const.UC_ARM64_REG_H4, "H5": uc.arm64_const.UC_ARM64_REG_H5,
                 "H6": uc.arm64_const.UC_ARM64_REG_H6, "H7": uc.arm64_const.UC_ARM64_REG_H7,
                 "H8": uc.arm64_const.UC_ARM64_REG_H8, "H9": uc.arm64_const.UC_ARM64_REG_H9,
                 "H10": uc.arm64_const.UC_ARM64_REG_H10, "H11": uc.arm64_const.UC_ARM64_REG_H11,
                 "H12": uc.arm64_const.UC_ARM64_REG_H12, "H13": uc.arm64_const.UC_ARM64_REG_H13,
                 "H14": uc.arm64_const.UC_ARM64_REG_H14, "H15": uc.arm64_const.UC_ARM64_REG_H15,
                 "H16": uc.arm64_const.UC_ARM64_REG_H16, "H17": uc.arm64_const.UC_ARM64_REG_H17,
                 "H18": uc.arm64_const.UC_ARM64_REG_H18, "H19": uc.arm64_const.UC_ARM64_REG_H19,
                 "H20": uc.arm64_const.UC_ARM64_REG_H20, "H21": uc.arm64_const.UC_ARM64_REG_H21,
                 "H22": uc.arm64_const.UC_ARM64_REG_H22, "H23": uc.arm64_const.UC_ARM64_REG_H23,
                 "H24": uc.arm64_const.UC_ARM64_REG_H24, "H25": uc.arm64_const.UC_ARM64_REG_H25,
                 "H26": uc.arm64_const.UC_ARM64_REG_H26, "H27": uc.arm64_const.UC_ARM64_REG_H27,
                 "H28": uc.arm64_const.UC_ARM64_REG_H28, "H29": uc.arm64_const.UC_ARM64_REG_H29,
                 "H30": uc.arm64_const.UC_ARM64_REG_H30, "H31": uc.arm64_const.UC_ARM64_REG_H31,
                 "Q0": uc.arm64_const.UC_ARM64_REG_Q0, "Q1": uc.arm64_const.UC_ARM64_REG_Q1,
                 "Q2": uc.arm64_const.UC_ARM64_REG_Q2, "Q3": uc.arm64_const.UC_ARM64_REG_Q3,
                 "Q4": uc.arm64_const.UC_ARM64_REG_Q4, "Q5": uc.arm64_const.UC_ARM64_REG_Q5,
                 "Q6": uc.arm64_const.UC_ARM64_REG_Q6, "Q7": uc.arm64_const.UC_ARM64_REG_Q7,
                 "Q8": uc.arm64_const.UC_ARM64_REG_Q8, "Q9": uc.arm64_const.UC_ARM64_REG_Q9,
                 "Q10": uc.arm64_const.UC_ARM64_REG_Q10, "Q11": uc.arm64_const.UC_ARM64_REG_Q11,
                 "Q12": uc.arm64_const.UC_ARM64_REG_Q12, "Q13": uc.arm64_const.UC_ARM64_REG_Q13,
                 "Q14": uc.arm64_const.UC_ARM64_REG_Q14, "Q15": uc.arm64_const.UC_ARM64_REG_Q15,
                 "Q16": uc.arm64_const.UC_ARM64_REG_Q16, "Q17": uc.arm64_const.UC_ARM64_REG_Q17,
                 "Q18": uc.arm64_const.UC_ARM64_REG_Q18, "Q19": uc.arm64_const.UC_ARM64_REG_Q19,
                 "Q20": uc.arm64_const.UC_ARM64_REG_Q20, "Q21": uc.arm64_const.UC_ARM64_REG_Q21,
                 "Q22": uc.arm64_const.UC_ARM64_REG_Q22, "Q23": uc.arm64_const.UC_ARM64_REG_Q23,
                 "Q24": uc.arm64_const.UC_ARM64_REG_Q24, "Q25": uc.arm64_const.UC_ARM64_REG_Q25,
                 "Q26": uc.arm64_const.UC_ARM64_REG_Q26, "Q27": uc.arm64_const.UC_ARM64_REG_Q27,
                 "Q28": uc.arm64_const.UC_ARM64_REG_Q28, "Q29": uc.arm64_const.UC_ARM64_REG_Q29,
                 "Q30": uc.arm64_const.UC_ARM64_REG_Q30, "Q31": uc.arm64_const.UC_ARM64_REG_Q31,
                 "V0":uc.arm64_const.UC_ARM64_REG_V0,"V1":uc.arm64_const.UC_ARM64_REG_V1,
                 "V2":uc.arm64_const.UC_ARM64_REG_V2,"V3":uc.arm64_const.UC_ARM64_REG_V3,
                 "V4":uc.arm64_const.UC_ARM64_REG_V4,"V5":uc.arm64_const.UC_ARM64_REG_V5,
                 "V6":uc.arm64_const.UC_ARM64_REG_V6,"V7":uc.arm64_const.UC_ARM64_REG_V7,
                 "V8":uc.arm64_const.UC_ARM64_REG_V8,"V9":uc.arm64_const.UC_ARM64_REG_V9,
                 "V10":uc.arm64_const.UC_ARM64_REG_V10,"V11":uc.arm64_const.UC_ARM64_REG_V11,
                 "V12":uc.arm64_const.UC_ARM64_REG_V12,"V13":uc.arm64_const.UC_ARM64_REG_V13,
                 "V14":uc.arm64_const.UC_ARM64_REG_V14,"V15":uc.arm64_const.UC_ARM64_REG_V15,
                 "V16":uc.arm64_const.UC_ARM64_REG_V16,"V17":uc.arm64_const.UC_ARM64_REG_V17,
                 "V18":uc.arm64_const.UC_ARM64_REG_V18,"V19":uc.arm64_const.UC_ARM64_REG_V19,
                 "V20":uc.arm64_const.UC_ARM64_REG_V20,"V21":uc.arm64_const.UC_ARM64_REG_V21,
                 "V22":uc.arm64_const.UC_ARM64_REG_V22,"V23":uc.arm64_const.UC_ARM64_REG_V23,
                 "V24":uc.arm64_const.UC_ARM64_REG_V24,"V25":uc.arm64_const.UC_ARM64_REG_V25,
                 "V26":uc.arm64_const.UC_ARM64_REG_V26,"V27":uc.arm64_const.UC_ARM64_REG_V27,
                 "V28":uc.arm64_const.UC_ARM64_REG_V28,"V29":uc.arm64_const.UC_ARM64_REG_V29,
                 "V30":uc.arm64_const.UC_ARM64_REG_V30,"V31":uc.arm64_const.UC_ARM64_REG_V31}
        elif self._ptrSize == 32:
            self.regs = {"R0": uc.arm_const.UC_ARM_REG_R0, "R1": uc.arm_const.UC_ARM_REG_R1,
             "R2": uc.arm_const.UC_ARM_REG_R2, "R3": uc.arm_const.UC_ARM_REG_R3,
             "R4": uc.arm_const.UC_ARM_REG_R4, "R5": uc.arm_const.UC_ARM_REG_R5,
             "R6": uc.arm_const.UC_ARM_REG_R6, "R7": uc.arm_const.UC_ARM_REG_R7,
             "R8": uc.arm_const.UC_ARM_REG_R8, "R9": uc.arm_const.UC_ARM_REG_R9,
             "R10": uc.arm_const.UC_ARM_REG_R10, "R11": uc.arm_const.UC_ARM_REG_R11,
             "R12": uc.arm_const.UC_ARM_REG_R12, "R13": uc.arm_const.UC_ARM_REG_R13,
             "R14": uc.arm_const.UC_ARM_REG_R14, "R15": uc.arm_const.UC_ARM_REG_R15,
             "PC": uc.arm_const.UC_ARM_REG_R15, "pc": uc.arm_const.UC_ARM_REG_R15,
             "LR": uc.arm_const.UC_ARM_REG_R14, "SP": uc.arm_const.UC_ARM_REG_R13,
             "sp": uc.arm_const.UC_ARM_REG_R13, "apsr": uc.arm_const.UC_ARM_REG_APSR,
             "APSR": uc.arm_const.UC_ARM_REG_APSR, "ret": uc.arm_const.UC_ARM_REG_R0,
             "S0": uc.arm_const.UC_ARM_REG_S0, "S1": uc.arm_const.UC_ARM_REG_S1,
             "S2": uc.arm_const.UC_ARM_REG_S2, "S3": uc.arm_const.UC_ARM_REG_S3,
             "S4": uc.arm_const.UC_ARM_REG_S4, "S5": uc.arm_const.UC_ARM_REG_S5,
             "S6": uc.arm_const.UC_ARM_REG_S6, "S7": uc.arm_const.UC_ARM_REG_S7,
             "S8": uc.arm_const.UC_ARM_REG_S8, "S9": uc.arm_const.UC_ARM_REG_S9,
             "S10": uc.arm_const.UC_ARM_REG_S10, "S11": uc.arm_const.UC_ARM_REG_S11,
             "S12": uc.arm_const.UC_ARM_REG_S12, "S13": uc.arm_const.UC_ARM_REG_S13,
             "S14": uc.arm_const.UC_ARM_REG_S14, "S15": uc.arm_const.UC_ARM_REG_S15,
             "S16": uc.arm_const.UC_ARM_REG_S16, "S17": uc.arm_const.UC_ARM_REG_S17,
             "S18": uc.arm_const.UC_ARM_REG_S18, "S19": uc.arm_const.UC_ARM_REG_S19,
             "S20": uc.arm_const.UC_ARM_REG_S20, "S21": uc.arm_const.UC_ARM_REG_S21,
             "S22": uc.arm_const.UC_ARM_REG_S22, "S23": uc.arm_const.UC_ARM_REG_S23,
             "S24": uc.arm_const.UC_ARM_REG_S24, "S25": uc.arm_const.UC_ARM_REG_S25,
             "S26": uc.arm_const.UC_ARM_REG_S26, "S27": uc.arm_const.UC_ARM_REG_S27,
             "S28": uc.arm_const.UC_ARM_REG_S28, "S29": uc.arm_const.UC_ARM_REG_S29,
             "S30": uc.arm_const.UC_ARM_REG_S30, "S31": uc.arm_const.UC_ARM_REG_S31}
        else:
            self.logger.fatal("m")

CC_CDECL = 1
class EmuX86(Emu):
    def __init__(self, ptrSize, convention=CC_CDECL, pageSize=4096, **kwargs):
        super().__init__(uc.UC_ARCH_X86, ptrSize, pageSize=pageSize, **kwargs)
        self._convention = CC_CDECL

    def initUc(self):
        if self._ptrSize == 16:
            self.target = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_16)
        elif self._ptrSize == 32:
            self.target = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_32)
        elif self._ptrSize == 64:
            self.target = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_64)
        else:
            raise Exception('Unknwon pointer size')

    
    def getArgv(self):
        # need to be fucked again
        if self._convention == CC_CDECL:
            argv = [
            self.getRegVal("rdi"),
            self.getRegVal("rsi"),
            self.getRegVal("rdx"),
            self.getRegVal("rcx"),
            self.getRegVal("r8"),
            self.getRegVal("r9"),
            struct.unpack("<Q", self.readMem(sp, 8))[0],
            struct.unpack("<Q", self.readMem(sp + 8, 8))[0]]
        else:
            raise Exception('Unknown call convention')
        return argv
    
    def setArgv(self, num, value):
        if self._ptrSize == 16:
            raise Exception('fucked')
        elif self._ptrSize == 32:
            if self._convention == CC_CDECL:
                argRegs = ()
                if num < len(argRegs):
                    self.writeReg(argRegs[num], value)
                else:
                    sp = self.readReg('rsp')
                    num = num - len(argRegs)
                    self.writeMem(sp+(self._ptrSize/8*num), struct.pack('<I', value))
            else:
                raise Exception('Unknown call convention')
        elif self._ptrSize == 64:
            if self._convention == CC_CDECL:
                argRegs = ('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9')
                if num < len(argRegs):
                    self.writeReg(argRegs[num], value)
                else:
                    sp = self.readReg('rsp')
                    num = num - len(argRegs)
                    self.writeMem(sp+(self._ptrSize/8*num), struct.pack('<I', value))
            else:
                raise Exception('Unknown call convention')

        else:
            raise Exception('Unknown call convention')

    def getRet(self):
        return self.readReg('ret')

    def setRetAddr(self, addr):
        sp = self.readReg('sp')
        if self._ptrSize == 16:
            self.writeMem(sp, struct.pack('<H', addr))
        elif self._ptrSize == 32:
            self.writeMem(sp, struct.pack('<I', addr))
        elif self._ptrSize == 64:
            self.writeMem(sp, struct.pack('<Q', addr))
        else:
            raise Exception('Unknown ptrSize')


    def _initRegs(self):
        if self._ptrSize == 16:
            self.regs = {"ax": uc.x86_const.UC_X86_REG_AX, "bx": uc.x86_const.UC_X86_REG_BX,
             "cx": uc.x86_const.UC_X86_REG_CX, "dx": uc.x86_const.UC_X86_REG_DX,
             "di": uc.x86_const.UC_X86_REG_DI, "si": uc.x86_const.UC_X86_REG_SI,
             "bp": uc.x86_const.UC_X86_REG_BP, "sp": uc.x86_const.UC_X86_REG_SP,
             "ip": uc.x86_const.UC_X86_REG_IP, "pc": uc.x86_const.UC_X86_REG_IP,
             "ret": uc.x86_const.UC_X86_REG_AX}
        elif self._ptrSize == 32:
            self.regs = {"ax": uc.x86_const.UC_X86_REG_EAX, "bx": uc.x86_const.UC_X86_REG_EBX,
             "cx": uc.x86_const.UC_X86_REG_ECX, "dx": uc.x86_const.UC_X86_REG_EDX,
             "di": uc.x86_const.UC_X86_REG_EDI, "si": uc.x86_const.UC_X86_REG_ESI,
             "bp": uc.x86_const.UC_X86_REG_EBP, "sp": uc.x86_const.UC_X86_REG_ESP,
             "ip": uc.x86_const.UC_X86_REG_EIP, "pc": uc.x86_const.UC_X86_REG_EIP,
             "eax": uc.x86_const.UC_X86_REG_EAX, "ebx": uc.x86_const.UC_X86_REG_EBX,
             "ecx": uc.x86_const.UC_X86_REG_ECX, "edx": uc.x86_const.UC_X86_REG_EDX,
             "edi": uc.x86_const.UC_X86_REG_EDI, "esi": uc.x86_const.UC_X86_REG_ESI,
             "ebp": uc.x86_const.UC_X86_REG_EBP, "esp": uc.x86_const.UC_X86_REG_ESP,
             "ret": uc.x86_const.UC_X86_REG_EAX}
        elif self._ptrSize == 64:
            self.regs = {"ax": uc.x86_const.UC_X86_REG_RAX, "bx": uc.x86_const.UC_X86_REG_RBX,
            "cx": uc.x86_const.UC_X86_REG_RCX, "dx": uc.x86_const.UC_X86_REG_RDX,
            "di": uc.x86_const.UC_X86_REG_RDI, "si": uc.x86_const.UC_X86_REG_RSI,
            "bp": uc.x86_const.UC_X86_REG_RBP, "sp": uc.x86_const.UC_X86_REG_RSP,
            "eax": uc.x86_const.UC_X86_REG_RAX, "ebx": uc.x86_const.UC_X86_REG_RBX,
            "ecx": uc.x86_const.UC_X86_REG_RCX, "edx": uc.x86_const.UC_X86_REG_RDX,
            "edi": uc.x86_const.UC_X86_REG_RDI, "esi": uc.x86_const.UC_X86_REG_RSI,
            "ebp": uc.x86_const.UC_X86_REG_RBP, "esp": uc.x86_const.UC_X86_REG_RSP,
            "ip": uc.x86_const.UC_X86_REG_RIP, "pc": uc.x86_const.UC_X86_REG_RIP,
            "rax": uc.x86_const.UC_X86_REG_RAX, "rbx": uc.x86_const.UC_X86_REG_RBX,
            "rcx": uc.x86_const.UC_X86_REG_RCX, "rdx": uc.x86_const.UC_X86_REG_RDX,
            "rdi": uc.x86_const.UC_X86_REG_RDI, "rsi": uc.x86_const.UC_X86_REG_RSI,
            "rbp": uc.x86_const.UC_X86_REG_RBP, "rsp": uc.x86_const.UC_X86_REG_RSP,
            "r8": uc.x86_const.UC_X86_REG_R8, "r9": uc.x86_const.UC_X86_REG_R9,
            "r10": uc.x86_const.UC_X86_REG_R10, "r11": uc.x86_const.UC_X86_REG_R11,
            "r12": uc.x86_const.UC_X86_REG_R12, "r13": uc.x86_const.UC_X86_REG_R13,
            "r14": uc.x86_const.UC_X86_REG_R14, "r15": uc.x86_const.UC_X86_REG_R15,
            "r8d": uc.x86_const.UC_X86_REG_R8, "r9d": uc.x86_const.UC_X86_REG_R9,
            "r10d": uc.x86_const.UC_X86_REG_R10, "r11d": uc.x86_const.UC_X86_REG_R11,
            "r12d": uc.x86_const.UC_X86_REG_R12, "r13d": uc.x86_const.UC_X86_REG_R13,
            "r14d": uc.x86_const.UC_X86_REG_R14, "r15d": uc.x86_const.UC_X86_REG_R15,
            "r8w": uc.x86_const.UC_X86_REG_R8, "r9w": uc.x86_const.UC_X86_REG_R9,
            "r10w": uc.x86_const.UC_X86_REG_R10, "r11w": uc.x86_const.UC_X86_REG_R11,
            "r12w": uc.x86_const.UC_X86_REG_R12, "r13w": uc.x86_const.UC_X86_REG_R13,
            "r14w": uc.x86_const.UC_X86_REG_R14, "r15w": uc.x86_const.UC_X86_REG_R15,
            "r8b": uc.x86_const.UC_X86_REG_R8, "r9b": uc.x86_const.UC_X86_REG_R9,
            "r10b": uc.x86_const.UC_X86_REG_R10, "r11b": uc.x86_const.UC_X86_REG_R11,
            "r12b": uc.x86_const.UC_X86_REG_R12, "r13b": uc.x86_const.UC_X86_REG_R13,
            "r14b": uc.x86_const.UC_X86_REG_R14, "r15b": uc.x86_const.UC_X86_REG_R15,
            "ret": uc.x86_const.UC_X86_REG_RAX, "rip": uc.x86_const.UC_X86_REG_RIP}