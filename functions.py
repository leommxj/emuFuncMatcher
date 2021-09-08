
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
    
    def __del__(self):
        self.unmapAllMem()

    def test(self):
        for case in self.testcases:
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
    
### Define functions with 3 arguments
class Fstrncpy(Function):
    name = 'strncpy'
    argc = 3
    testcases = (
        ((b'\x00'*20, b'aaa', 3), (b'aaa', )),
        ((b'\x00'*20, b'a\x00b', 3), (b'a\x00\x00', )),
        ((b'\x00'*20, b'beniceplase', 9), (b'benicepla\x00', )),
        ((b'a'*20, b'beniceplase', 9), (b'beniceplaaaaaa', )),
    )
    def setupOne(self, caseIn):
        dstData = caseIn[0]
        srcData = caseIn[1]
        n = caseIn[2]

        dstAddr = self.setArgWithMem(0, len(dstData), dstData)
        self.setArgWithMem(1, len(srcData), srcData)
        self.setArgWithImm(2, n)
        self.emu.setRetAddr(0xcafebabe)
        return dstAddr
    
    def retOne(self, caseOut, dstAddr):
        expectation = caseOut[0]
        retPtr = self.emu.getRet()
        result = self.emu.readMem(dstAddr, len(expectation))
        if (result == expectation) and (retPtr == dstAddr):
            return True
        else:
            #print('result:{}, expect: {}, dstAddr: 0x{:x}, retPtr: 0x{:x}'.format(result, expectation, dstAddr, retPtr))
            return False

    def checkOne(self, case):
        dstAddr = self.setupOne(case[0])
        self.start()
        return self.retOne(case[1], dstAddr)

class Fstpncpy(Fstrncpy):
    name = 'stpncpy'
    testcases = (
        ((b'\x00'*20, b'aaa', 3), (b'aaa', 3)),
        ((b'\x00'*20, b'a\x00b', 3), (b'a\x00\x00', 1)),
        ((b'\x00'*20, b'beniceplase', 9), (b'benicepla\x00', 9)),
        ((b'a'*20, b'beniceplase', 9), (b'beniceplaaaaaa', 9)),
    )
    def retOne(self, caseOut, dstAddr):
        expectation = caseOut[0]
        expectAddrM = caseOut[1]
        retPtr = self.emu.getRet()
        result = self.emu.readMem(dstAddr, len(expectation))
        if (result == expectation) and (retPtr == dstAddr+expectAddrM):
            return True
        else:
            #print('result:{}, expect: {}, dstAddr+expectAddrM: 0x{:x}, retPtr: 0x{:x}'.format(result, expectation, dstAddr+expectAddrM, retPtr))
            return False

class Fmemcpy(Fstrncpy):
    name = 'memcpy' # or memmove
    testcases = (
        ((b'a'*10, b'aaa', 3), (b'aaaa', )),
        ((b'a'*10, b'a\x00b', 3), (b'a\x00ba', )),
        ((b'a'*20, b'beniceplase', 9), (b'beniceplaa', ))
    )

class Fmempcpy(Fmemcpy):
    name = 'mempcpy'
    def retOne(self, caseOut, dstAddr):
        expectation = caseOut[0]
        retPtr = self.emu.getRet()
        result = self.emu.readMem(dstAddr, len(expectation))
        if (result == expectation) and (retPtr == dstAddr+len(expectation)-1):
            return True
        else:
            #print('result:{}, expect: {}, dstAddr: 0x{:x}, retPtr: 0x{:x}'.format(result, expectation, dstAddr, retPtr))
            return False

class Fstrncat(Fstrncpy):
    name = 'strncat'
    testcases = (
        ((b'\x00'*20, b'aaa', 3), (b'aaa', )),
        ((b'\x00'*20, b'a\x00b', 3), (b'a\x00\x00', )),
        ((b'\x00'*20, b'beniceplase', 9), (b'benicepla\x00', )),
        ((b'a'+b'\x00'*20, b'beniceplase', 9), (b'abenicepla\x00', )),
    )

class Fmemset(Fstrncpy):
    name = 'memset'
    testcases = (
        ((b'\x00'*20, ord('a'), 4), (b'aaaa'+b'\x00'*16, )),
        ((b'x'*20, ord('b'), 4), (b'bbbb'+b'x'*16, )),
        ((b'b'*20, 0, 7), (b'\x00'*7+b'b'*13, )),
        ((b'b'*20, ord('b'), 4), (b'b'*20, )),
    )
    def setupOne(self, caseIn):
        dstData = caseIn[0]
        cvalue = caseIn[1]
        n = caseIn[2]

        dstAddr = self.setArgWithMem(0, len(dstData), dstData)
        self.setArgWithImm(1, cvalue)
        self.setArgWithImm(2, n)
        self.emu.setRetAddr(0xcafebabe)
        return dstAddr


### Define functions with 2 arguments
class Fstrcpy(Function):
    name = 'strcpy'
    argc = 2
    testcases = (
        ((), ()),

    )
    def checkOne(self):
        pass


### Define functions with 1 argument
class Fstrlen(Function):
    name = 'strlen'
    argc = 1
    testcases = (
        ((b'aaaabbbb\x00aabcc',), (8,)),
        ((b'\x00'+b'a'*12,), (0,)),
        ((b'aa\x00c'*4,), (2,)),
    )

    def checkOne(self, case):
        strbuf = case[0][0]
        expectation = case[1][0]
        self.setArgWithMem(0, len(strbuf), strbuf)
        self.emu.setRetAddr(0xcafebabe)
        self.start()
        result = self.emu.getRet()
        if result == expectation:
            return True
        else:
            print(result)
            print(expectation)
            return False