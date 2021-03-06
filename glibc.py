from functions import Function
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
            self.dlog('result:{}, expect: {}, dstAddr: 0x{:x}, retPtr: 0x{:x}'.format(result, expectation, dstAddr, retPtr))
            return False

    def checkOne(self, case):
        dstAddr = self.setupOne(case[0])
        self.start()
        return self.retOne(case[1], dstAddr)

class Fstpncpy(Fstrncpy):
    name = 'stpncpy'
    argc = 3
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
            self.dlog('result:{}, expect: {}, dstAddr+expectAddrM: 0x{:x}, retPtr: 0x{:x}'.format(result, expectation, dstAddr+expectAddrM, retPtr))
            return False

class Fmemcpy(Fstrncpy):
    name = 'memcpy' # or memmove
    argc = 3
    testcases = (
        ((b'a'*10, b'aaa', 3), (b'aaaa', )),
        ((b'a'*10, b'a\x00b', 3), (b'a\x00ba', )),
        ((b'a'*20, b'beniceplase', 9), (b'beniceplaa', ))
    )

class Fmempcpy(Fmemcpy):
    name = 'mempcpy'
    argc = 3
    def retOne(self, caseOut, dstAddr):
        expectation = caseOut[0]
        retPtr = self.emu.getRet()
        result = self.emu.readMem(dstAddr, len(expectation))
        if (result == expectation) and (retPtr == dstAddr+len(expectation)-1):
            return True
        else:
            self.dlog('result:{}, expect: {}, dstAddr: 0x{:x}, retPtr: 0x{:x}'.format(result, expectation, dstAddr, retPtr))
            return False

class Fstrncat(Fstrncpy):
    name = 'strncat'
    argc = 3
    testcases = (
        ((b'\x00'*20, b'aaa', 3), (b'aaa', )),
        ((b'\x00'*20, b'a\x00b', 3), (b'a\x00\x00', )),
        ((b'\x00'*20, b'beniceplase', 9), (b'benicepla\x00', )),
        ((b'a'+b'\x00'*20, b'beniceplase', 9), (b'abenicepla\x00', )),
    )

class Fmemset(Fstrncpy):
    name = 'memset'
    argc = 3
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

class Fmemcmp(Function):
    name = 'memcmp'
    argc = 3
    testcases = (
        ((b'aaa\x00\x00bb', b'aaa\x00\x00bb', 7), (0,)),
        ((b'aabbcc', b'aabddd', 3), (0,)),
        ((b'aabbcc', b'aabddd', 6), (-1,)),
        ((b'abc', b'abb', 6), (1,)),
        ((b'abc\x00\x01efg',b'abc\x00\x01efg', 8), (0,)),
        ((b'abc\x00\x01afg',b'abc\x00\x01efg', 8), (-1,)),
    )
    def setupOne(self, caseIn):
        a1 = caseIn[0]
        a2 = caseIn[1]
        n = caseIn[2]

        self.setArgWithMem(0, len(a1), a1)
        self.setArgWithMem(1, len(a2), a2)
        self.setArgWithImm(2, n)
        self.emu.setRetAddr(0xcafebabe)
    
    def retOne(self, caseOut):
        e = caseOut[0]
        r = self.emu.getRet()
        if e < 0:
            if r&(1<<(self.emu._ptrSize-1)) != 0:
                return True
        elif e > 0:
            if r&((1<<self.emu._ptrSize)-1) > 0:
                return True
        else:
            if r == 0:
                return True
        self.dlog('r:0x{:x}, e:{}'.format(r, e))
        return False

    def checkOne(self, case):
        self.setupOne(case[0])
        self.start()
        return self.retOne(case[1])

class Fstrncmp(Fmemcmp):
    name = 'strncmp'
    argc = 3
    testcases = (
        ((b'aaa\x00\x00bb', b'aaa\x00\x00bb', 7), (0,)),
        ((b'aabbcc', b'aabddd', 3), (0,)),
        ((b'aabbcc', b'aabddd', 6), (-1,)),
        ((b'a'*8+b'c', b'a'*8+b'b', 9), (1,)),
        ((b'abc', b'abb', 6), (1,)),
        ((b'abc\x00\x01afg',b'abc\x00\x01efg', 8), (0,)),
        ((b'abc', b'abb', 1), (0,)),
    )

### Define functions with 2 arguments
class Fstrcpy(Fstrncpy):
    name = 'strcpy'
    argc = 2
    testcases = (
        ((b'\x00'*20, b'aaa', 3), (b'aaa', )),
        ((b'\x00'*20, b'a\x00b', 3), (b'a\x00\x00', )),
        ((b'\x00'*20, b'beniceplase', 9), (b'beniceplase\x00', )),
        ((b'a'*20, b'beniceplase', 9), (b'beniceplase\x00aaaaa', )),
    )

class Fstrcmp(Fmemcmp):
    name = 'strcmp' #TODO: differentiate strverscmp
    argc = 2
    testcases = (
        ((b'aaa\x00\x00bb', b'aaa\x00\x00bb', 7), (0,)),
        ((b'aabbcc', b'aabddd', 3), (-1,)),
        ((b'aabbcc', b'aabddd', 6), (-1,)),
        ((b'a'*8+b'c', b'a'*8+b'b', 6), (1,)),
        ((b'abc', b'abb', 6), (1,)),
        ((b'abc\x00\x01afg',b'abc\x00\x01efg', 8), (0,)),
        ((b'abc', b'abb', 1), (1,)),
    )

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
            return False