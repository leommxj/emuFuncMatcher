from functions import Function

class Fmemcpy_s(Function):
    name = 'memcpy_s'
    argc = 4
    testcases = (
        ((b'\x00'*10, 3, b'aaa', 3), (b'aaa',)),
        ((b'a'*10, 3, b'a\x00b', 3), (b'a\x00ba',)),
        ((b'a'*20, 9, b'beniceplase', 9), (b'beniceplaa',)),
        ((b'a'*20, 9, b'beniceplase', 4), (b'benia',)),
        ((b'\x00'*20, 10, b'shhhhhhhhhhhhhot', 20), (b'\x00'*20,)),
    )
    def setupOne(self, caseIn):
        a1 = caseIn[0]
        DstSize = caseIn[1]
        Src = caseIn[2]
        MaxCount = caseIn[3]

        dstAddr = self.setArgWithMem(0, len(a1), a1)
        self.setArgWithImm(1, DstSize)
        self.setArgWithMem(2, len(Src), Src)
        self.setArgWithImm(3, MaxCount)
        self.emu.setRetAddr(0xcafebabe)
        return dstAddr
    
    def retOne(self, caseOut, dstAddr):
        expectation = caseOut[0]
        result = self.emu.readMem(dstAddr, len(expectation))
        if (result == expectation):
            return True
        else:
            self.dlog('result:{}, expect: {}, dstAddr: 0x{:x}'.format(result, expectation, dstAddr))
            return False

    def checkOne(self, case):
        dstAddr = self.setupOne(case[0])
        self.start()
        return self.retOne(case[1], dstAddr)
