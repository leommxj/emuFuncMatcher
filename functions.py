class Mem(object):
    def __init__(self, addr, size, isUsed):
        self.addr = addr
        self.size = size
        self.isUsed = isUsed


class Function(object):
    argc = 0
    testcases = (
        (None, None),
    )
    def __init__(self, emu, startEa, endEa):
        self.emu = emu
        self.startEa = startEa
        self.endEa = endEa
        self.ownMem = []
        self.debug = False
        self.debug_func = None
    
    def dlog(self, s):
        if self.debug == True:
            if self.debug_func is None:
                print(s)
            else:
                self.debug_func(s)
    
    def __del__(self):
        self.unmapAllMem()
    
    def cleanup(self):
        self.emu.restore()
        self.emu.preStack()

    def test(self):
        for case in self.testcases:
            self.cleanup()
            if not self.checkOne(case):
                return False
            self.clearMem()
        if not self.checkTwo():
            return False
        return True
    
    def start(self):
        try:
            self.emu.startEmu(self.startEa, self.endEa)
        except Exception as e:
            raise e

    def getMem(self, size):
        if self.ownMem:
            for mem in self.ownMem:
                if mem.isUsed:
                    continue
                elif mem.size <= size:
                    mem.isUsed = True
                    return mem.addr
        addr = self.emu.allocMem(size)
        self.ownMem.append(Mem(addr, self.emu.pageAlign(size), True))
        return addr

    def clearMem(self):
        for mem in self.ownMem:
            if mem.isUsed:
                self.emu.writeMem(mem.addr, b'\x00'*mem.size)
                mem.isUsed = False
    
    def unmapAllMem(self):
        while self.ownMem:
            mem = self.ownMem.pop()
            self.emu.target.mem_unmap(mem.addr, mem.size)
            
    def setArgWithMem(self, i, size, data=None):
        addr = self.getMem(size)
        if data:
            self.emu.writeMem(addr, data)
        self.emu.setArgv(i, addr)
        return addr

    def setArgWithImm(self, i, value):
        self.emu.setArgv(i, value)

    def checkOne(self, case):
        pass
    
    def checkTwo(self):
        '''
        do more check when things get funny
        '''
        return True