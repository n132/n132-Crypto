# Warning: 
# 1. It's just a demo to understand AES-CBC 
# 2. Do NOT use it to encrypt anything.
# 3. This implementation is definitely not secure.
# ==============
# Author: n132
# Brooklyn, NY
# AD 06/19/2023
# ==============
# Ref
'''
# Wiki
[AES Key Schedule](https://en.wikipedia.org/wiki/AES_key_schedule)
[Sbox](https://en.wikipedia.org/wiki/Rijndael_S-box)
[AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
[MixColumns](https://en.wikipedia.org/wiki/Rijndael_MixColumns)
[CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
# Personal Implementation
[Personla-AES-CBC-Implementation](https://xuanxuanblingbling.github.io/ctf/crypto/2019/10/25/aes/)
'''
from pwn import *
import os
import profile
class AES():
    def __init__(self,Mode=128,DEBUG=0) -> None:
        self.MODE    = Mode
        self.DEBUG   = DEBUG
        self.N       = int(self.MODE // 32) # N blocks, e.g. 4 for AES 128
        self.R       = self.N+7 # R rounds, 11 for AES 128
        self.Sbox    = profile.sbox
        self.Cbox    = profile.cbox
        self.CboxInv = profile.cbox_inv
    def panic(self,s):
        print(s)
        exit(1)
    def randn(self,l):
        return os.urandom(l)
    def GenKey(self):
        return self.randn(0x10)
    def GenIv(self):
        return self.randn(0x10)
    def GenRc(self):
        r = self.R-1
        # round constants
        rc = [1]# init the value rc[0]
        for x in range(1,r):
            next_rc = rc[x-1]*2 if rc[x-1]*2<=0x80 else (rc[x-1]*2)^(0x11b)
            rc.append(next_rc)
        return rc
    def RotWord(self,dt):
        assert(len(dt)==4)
        return dt[-1:]+dt[:-1]
    def SftWord(self,dt):
        assert(len(dt)==4)
        return dt[1:]+dt[:1]
    def SftWordDec(self,dt):
        assert(len(dt)==4)
        return dt[-1:]+dt[:-1]
    def SubWord(self,dt):
        assert(len(dt)==4)
        return [self.Sbox[x] for x in dt]
    def XorNbytes(self,b1,b2,n):
        assert(len(b1)==n)
        assert(len(b2)==n)
        return [b1[x]^b2[x] for x in range(n)]
    def XorWord(self,b1,b2):
        return self.XorNbytes(b1,b2,4)
    def KeyExpansion(self):
        ExpandedKey = [0]*self.R*4*4 # size in bytes, 176 for AES-128 (16*11)
        for _ in range(4):
            for x in range(4):
                ExpandedKey[_*4+3-x] =  self.key[_*4+x]
        for _ in range(self.N,self.R*4):
            prev_block = ExpandedKey[(_-self.N)*4:(_-self.N)*4+4]
            four_blocks_ago = ExpandedKey[(_-1)*4:_*4]
            if _ % self.N == 0:
                rc_val  = [0]*3 + [self.rc[int(_//4)-1]]
                tmp_val = self.SubWord(self.RotWord(four_blocks_ago))
                tmp_res = self.XorWord(self.XorWord(prev_block,tmp_val),rc_val)
            elif _ % self.N == 4 and self.N > 6:
                tmp_res = self.XorWord(prev_block,self.SubWord(four_blocks_ago))
            else:
                tmp_res = self.XorWord(prev_block,four_blocks_ago)
            for i in range(4):
                ExpandedKey[_*4+i] = tmp_res[i]
        self.W = ExpandedKey
    def AddRoundKey(self,state,key):
        assert(len(key)==0x10)
        assert(len(state)==0x10)
        res = []
        for x in range(4):
            for y in range(4):
                res.append(state[x*4+y]^key[y*4+3-x])
        return res
    def SubBytes(self,state):
        assert(len(state)==0x10)
        return [self.Sbox[x] for x in state]
    def SubBytesDec(self,state):
        assert(len(state)==0x10)
        return [self.Sbox.index(x) for x in state]
    def ShiftRows(self,state):
        assert(len(state)==0x10)
        res = state[:4]
        for x in range(3):
            dt = state[4+x*4:8+x*4]
            for _ in range(x+1):
                dt = self.SftWord(dt)
            res+=dt
        return res
    def ShiftRowsDec(self,state):
        assert(len(state)==0x10)
        res = state[:4]
        for x in range(3):
            dt = state[4+x*4:8+x*4]
            for _ in range(x+1):
                dt = self.SftWordDec(dt)
            res+=dt
        return res
    def Gmul(self,a,b):
        if a == 1:
            return b
        p = 0
        for _ in range(8):
            if a % 2:
                p ^= b
            f = bool(b&0x80)
            b*=2
            b%=0x100
            if f:
                b ^= 0x1B
            a = int(a//2)
        return p
    def MixColumns(self,state,dec=False):
        assert(len(state)==0x10)
        res = [0]*len(state)
        if dec:
            cbox = self.Cbox
        else:
            cbox = self.CboxInv
        for x in range(4):
            for y in range(4):
                for z in range(4):
                    res[y*4+x] ^= self.Gmul(cbox[x*4+z],state[z*4+y])
        res = [x%0x100 for x in res]
        res = self.twitch(res)
        return res
    def twitch(self,state):
        res = []
        for x in range(4):
            for y in range(4):
                res.append(state[y*4+x])
        return res
    def DoEncode(self,state):
        assert(len(state)==0x10)
        # Initial round key addition
        state   = self.twitch(state)
        state   = self.AddRoundKey(state,self.W[:16])
        # 9, 11 or 13 rounds 
        for ct in range(1,self.R-1):
            state = self.SubBytes(state) # SubBytes 
            state = self.ShiftRows(state) # ShiftRows
            state = self.MixColumns(state) # MixColumns
            state = self.AddRoundKey(state,self.W[ct*16:(ct+1)*16])
        # Final round
        state = self.SubBytes(state)
        state = self.ShiftRows(state)
        state = self.AddRoundKey(state,self.W[-0x10:])
        return self.twitch(state)
    def padding(self,plaintext):
        l = len(plaintext)
        if l%0x10 == 0:
            plaintext+=[0x10]*0x10
        else:
            n = 0x10-(l%0x10)
            plaintext += [n]*n
        return plaintext
    def encrypt(self,plaintext,key=None,iv=None):
        self.key = bytes.fromhex(key) if key else self.GenKey()
        self.iv  = bytes.fromhex(iv) if iv else self.GenIv()
        self.rc  = self.GenRc()
        self.KeyExpansion()
        # check type of plaintext
        if type(plaintext) == type(b''):
            plaintext = list(plaintext)
        elif type(plaintext) == type([]):
            pass
        else:
            self.panic("[!] Plaintext should be a bytes array or a list")
        # check the len of key and iv
        if len(self.key) != 0x10 or len(self.iv)!=0x10:
            self.panic("[!] Invalid Key or IV")
        plaintext = self.padding(plaintext)
        if not key or not iv or self.DEBUG:
            info("Key: "+self.key.hex())
            info("IV:  "+self.iv.hex())
            info("Plaintext: \n"+bytes(plaintext).hex())
            # info("W:  "+bytes(self.W).hex())
        prev_block = self.iv
        encode = []
        for x in range(int(len(plaintext)//16)):
            prev_block = self.DoEncode(self.XorNbytes(plaintext[x*0x10:x*0x10+0x10],prev_block,0x10))
            encode+=prev_block
        return bytes(encode).hex()
    def DoDecode(self,state,prev):
        assert(len(state)==0x10)
        state   = self.twitch(state)
        state   = self.AddRoundKey(state,self.W[:16])
        for ct in range(1,self.R-1):
            state = self.ShiftRowsDec(state)
            state = self.SubBytesDec(state)
            state = self.AddRoundKey(state,self.W[ct*16:(ct+1)*16])
            state = self.MixColumns(state,dec=True)
        state = self.SubBytesDec(state)
        state = self.ShiftRowsDec(state)
        state = self.AddRoundKey(state,self.W[-0x10:])
        return self.XorNbytes(self.twitch(state),prev,0x10)
    def KeyExpansionDec(self):
        l = len(self.W)
        res = []
        for i in range(l-0x10,-0x10,-0x10):
            res+=self.W[i:i+0x10]
        self.W = res
    def decrypt(self,ciphertext,key=None,iv=None):
        self.key = bytes.fromhex(key) if key else self.key
        self.iv = bytes.fromhex(iv) if iv else self.iv
        
        if (not self.key) or (not self.iv):
            self.panic("[!] Key and Iv are needed")
        self.rc  = self.GenRc()
        self.KeyExpansion()
        self.KeyExpansionDec()
        ciphertext = self.iv + bytes.fromhex(ciphertext)
        assert(len(ciphertext)%0x10==0)
        bnum = int(len(ciphertext)//0x10)
        decode = []
        for x in range(bnum-1,0,-1):
            tmp_plaintext =  self.DoDecode(ciphertext[x*0x10:x*0x10+0x10],ciphertext[x*0x10-0x10:x*0x10])
            decode = tmp_plaintext+decode
        return bytes(decode).hex()
if __name__ =="__main__":
    aes = AES()
    key = None
    iv  = None
    p = aes.randn(0x132)
    res = aes.encrypt(p,key=key,iv=iv)
    info("Ciphertext: \n"+res)
    res = aes.decrypt(res,key,iv)
    info("Plaintext: \n"+res)
    assert(bytes.fromhex(res)[:0x132]==p)
