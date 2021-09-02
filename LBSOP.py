'''
 
| From: "LBSOP"
| Available from: 

* type:			Level-Based Signcryption
* setting:		bilinear groups (asymmetric)

:Authors:	Pairat Thorncharoensri
:Date:			02/09/2021

''' 
from __future__ import print_function
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from Crypto.Util.Padding import pad, unpad
#from charm.toolbox.IBEnc import IBEnc
#from charm.toolbox.hash_module import Waters
#from charm.schemes.aggrsign_bls import BLSAggregation
import math, string, random
from functools import reduce
from charm.core.engine.util import objectToBytes ,bytesToObject, serializeObject, deserializeObject
import time 
from charm.core.math.integer import randomBits,integer,bitsize
from charm.toolbox.hash_module import Hash, int2Bytes,integer
from charm.toolbox.IBEnc import *
from charm.toolbox.ABEnc import *
from charm.toolbox.schemebase import *

def randomStringGen(size=30, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for x in range(size))

debug = False
#class LBSOP(BLSAggregation):
class LBSOP(ABEnc):
    """
    >>> from charm.toolbox.pairinggroup import PairingGroup,GT
    >>> from charm.toolbox.hash_module import Waters
    >>> group = PairingGroup('SS512')
    >>> waters_hash = Waters(group)
    >>> ibe = IBE_N04_z(group)
    >>> (master_public_key, master_key) = ibe.setup()
    >>> ID = "bob@mail.com"
    >>> kID = waters_hash.hash(ID)
    >>> secret_key = ibe.extract(master_key, ID)
    >>> msg = group.random(GT)
    >>> cipher_text = ibe.encrypt(master_public_key, ID, msg)
    >>> decrypted_msg = ibe.decrypt(master_public_key, secret_key, cipher_text)
    >>> decrypted_msg == msg
    True
    """
    
    """Implementation of LBSOP"""
    def __init__(self, groupObj):
        ABEnc.__init__(self)
        #BLSAggregation .__init__(self)
        global group
        group = groupObj
        global H1,H2, h
        h = lambda a: group.hash(str(a), ZR)
        H1= lambda a: group.hash(str(a), G1)
        H2= lambda a: group.hash(str(a), G2)
    
    def encodeToZn(self, message):
        assert type(message) == bytes, "Input must be of type bytes"
        return integer(message)
        
    def decodeFromZn(self, element):
        if type(element) == integer:
            msg = int2Bytes(element)
            return msg

    #def XOR(self,  GM=group.random(GT), MM=""):
    def XOR(self, GM, MM=""):
        a=True
        if (type(MM) == integer):
            EM=MM
            if debug:
                print("EM:", EM)
            a=False
        else:    
            M2=self.dump(MM)
            EM = self.encodeToZn(M2)
            if debug:
                print("M2:",M2)
                print("EM:", EM)
                print("bitsize EM", bitsize(EM) )
        if bitsize(EM) / 8 >= group.messageSize() and a:
            print("Message size: ", group.messageSize())
            print("bitsize /8--->", bitsize(EM) / 8)
            print( "bitsize--->", bitsize(EM) )
            print("size not match")
            return 0
        hGM= group.serialize(GM)
        hG= self.encodeToZn(hGM)
        #print("bitsize hG", bitsize(hG))
        #print("print hG", hG)
        De=EM^hG
        #De=self.decodeFromZn(EM^hG)
        #De2=pad(De,64)
        #print("print De", De)
        #print("print De type", type(De))
        #print("print De2", De2)
        return De


    def product(self, seq):
        #return reduce(lambda x, y: x * y, seq)
        sq = [i for i in seq]
        for i in range(0, len(sq)):
            #ii = group.random(G1)
            ii = seq[i]
            if (i==0):
                qs=ii
            else:    
                qs= qs * ii
        return qs

#    @staticmethod
    def addition(self,seq):
        sq = [i for i in seq]
        for i in range(0, len(sq)):
            #ii = group.random(G1)
            ii = seq[i]
            if (i==0):
                qs=ii
            else:    
                qs= qs + ii
        return qs

    @staticmethod
    def dump(objM):
        return objectToBytes(objM,group)

    @staticmethod
    def dedump(bytesobj):
        return bytesToObject(bytesobj, group)


    def setup(self):

        """
        Generates public key and master secret key.
        """
        g = group.random(G1)  # generator for group G of prime order p
        o = group.random(G2)  # from Zp
        #W    = g ** a         # G1 
        pk = {'g':g,'o':o}


        return (pk)
  
    def extractPKG(self, pkk,n):
        n=n+1
        '''  extract the secretkey'''
        u = [group.random(ZR) for i in range(n)]
        v = [group.random(ZR) for i in range(n)]
        a = group.random(ZR) 	
        b = group.random(ZR) 
        g=pkk['g']
        o=pkk['o']
        U = [o**(u[i]*a) for i in range(n)]
        V = [g**(v[i]) for i in range(n)]
        U[0]=o
        W=[g]	
        for i in range(1, n):
            #uu=[u[l] for l in range(i,n)]
            #vv=[v[l] for l in range(i,n)]
            uv=[u[l]*v[l]*a for l in range(i,n)]
            if debug:
                print("uv    =>%s " % uv)
                print("uv size ", str(i) ,"   = ",len(uv))
            tsum=self.addition(uv)
            tw=g**(tsum+v[0]*u[0]*a+b)	    
            W.append(tw)
            if debug:
                print("W    =>%s " % W)
        if debug:
            print("U    =>", U)
            print("V    =>", V)
            print("W    =>%s "%W)
            print("U-count    =>%s" %len(U))
            print("V-count    =>", len(V))
            print("W-count    =>%s"%len(W))

        pk={'U': U, 'V' : V, 'W' : W, 'g': g, 'o': o, 'n': n-1}
        sk= {'u': u, 'v' : v, 'a' : a,  'b' : b}
        return ( pk,sk )

        
    def extractKey(self, kpk):
        n=kpk['n'] 
        n=n+1
        #  user key generation
        x = group.random(ZR)
        V=kpk['V']   
        X= [ V[i]**x  for i in range(n) ]
        if debug:
            print("X   =>", X)
            print("X-count    =>", len(X))
        spk = {'X': X}
        ssk =  {'x': x}
        if debug:
            print("pk    =>", spk)
            print("sk    =>", ssk)
        return (spk, ssk)

    def extractCred(self, kpk, ksk, t):
        #--------------------------------	
        #  user key generation
        n=kpk['n']
        n=n+1
        y0 = group.random(ZR)
        #pk=kpk['pk']
        #sk=ksk['sk']
        u=ksk['u']
        v=ksk['v']
        a=ksk['a']
        b=ksk['b']
        #g=kpk['g']
        o=kpk['o']       
        if (t>n):
            t=n
        y1=((v[0]*u[0]*a+v[t]*u[t]*a)+b-y0*v[0])/v[t]
        C0=o**y0
        C1=o**y1
        
          
        cpk = {'t': t}
        csk =  {'C0': C0, 'C1': C1}
        if debug:
            print("cpk    =>", cpk)
            print("csk    =>", csk)
#            print ("M-key---%s"%M)
#            mm={'ID':IDU, 'T':Tu}
#            MID=self.dump(mm)
#            
#            lv=group.hash(MID, ZR)
#            m2={'ID':IDU, 'X': Xu, 'Y': Yu, 'Z': Zu, 'T': Tu,'B': Bu}
#            MG=self.dump(m2)
#            gamma_v =group.hash(MG, ZR)
#            temp1=g**cu
#            temp2=Bu*((Tu * (kpk['W'] ** lv)) **gamma_v)
#            print ("ID-key---%s"%MID)
#            print ("MG-key---%s"%MG)
#            if temp1!=temp2:
#                print ("Error check extract not pass: "+IDU)
#            else:
#                print ("pass extract")
        return (cpk, csk)

    def testCred(self, kpk, ssk,spk, cpk, csk):
        t= cpk['t']
        C0=csk['C0']
        C1=csk['C1']
        U=kpk['U']
        V=kpk['V']
        W=kpk['W']
        X=spk['X']
        g=kpk['g']
        o=kpk['o']
        x=ssk['x']
        MP=1
        k=t
        n=kpk['n']
        n=n+1
        WQ2 = pair(W[MP], o)
        X0C0 = pair(X[0], C0)
        XLC1 = pair(X[k], C1)
        XIUI = X0C0 * XLC1
        for i in range(MP, n):
            if debug:
                print("n---%s" %i)
                print("X---%s" %X[i])
            if i == k:
                continue
            XIUI = XIUI * pair(X[i], U[i])
        OT = (XIUI)
        WQB=WQ2**x
        check=WQB==OT
        print("check credit---%s" %check)



    def signcrypt(self, kpk, spk, ssk, MP, M):
        t=MP
        g=kpk['g']
        o=kpk['o']
        #U=kpk['U']
        #V=kpk['V']
        W=kpk['W']
        #X=spk['X']
        x=ssk['x']
        r = group.random(ZR)
        K= group.random(GT)
        #M=group.encode(Message)
        R=pair(W[t], (o**r))
        Q3=self.XOR(R, M)
        if debug:
            print("Q3",Q3)
        MPG=group.init(ZR,MP)
        #Q3G = group.init(ZR, Q3)
        Q3G = self.decodeFromZn(Q3)
        mq1={'R': R, 'spk':spk,  'kpk':kpk,  'MP':MPG , 'Q3': Q3G}
        MQ1=self.dump(mq1)
        Q1=h(MQ1)
        Q2=o**(Q1*x+r)
        CT={'Q1': Q1, 'Q2': Q2, 'Q3': Q3, 'MP': MP}
        return (CT)


    def decrypt(self, kpk, spk, vsk, vpk,  CT):
        n=kpk['n'] 
        n=n+1
        g=kpk['g']
        o=kpk['o']
        U=kpk['U']
        V=kpk['V']
        W=kpk['W']
        X=spk['X']
        C0=vsk['C0']
        C1=vsk['C1']
        k=vpk['t']
        Q1=CT['Q1']
        Q2=CT['Q2']
        Q3=CT['Q3']
        MP=CT['MP']
        WQ2=pair(W[MP], Q2)
        X0C0=pair(X[0], C0)
        XLC1=pair(X[k], C1)
        XIUI=X0C0*XLC1
        for i in range(MP, n):
            if i==k:
                continue
            XIUI=XIUI*pair(X[i], U[i])
        R= WQ2*((XIUI)**(-Q1))
        MPG = group.init(ZR, MP)
        #Q3G = self.encodeToZn(Q3)
        Q3G = self.decodeFromZn(Q3)
        mq1 = {'R': R, 'spk': spk, 'kpk': kpk, 'MP': MPG, 'Q3': Q3G}
        MQ1 = self.dump(mq1)
        QV1 = h(MQ1)

        check = QV1==Q1
        if debug:
            print("QV1:", QV1)
            print("Q1:", Q1)
            print("check:", check)
        if check:
            if debug:
                print("Q1 matched")
            out=self.XOR(R,Q3)
            M=self.decodeFromZn(out)

            #Mout=self.dedump(M)
            if debug:
                print("M :",M )
                print("Q3 :", Q3)
                print("R :", R)
            #print("Mout :", Mout)
            #M=self.dedump(out)
            return M
        return 0

        
        # start here

def main():
    group = PairingGroup('MNT224')
    bls = LBSOP(group)
    (pkk) = bls.setup()
    # IDS = "bob@mail.com"
    # ID=LBSOP.dump(IDS)
    # group.hash(ID, ZR)
    IDS = "bob@mail.com"
    # group.hash((IDS), ZR)
    (kpk, ksk) = bls.extractPKG(pkk, 2)
    (spk, ssk) = bls.extractKey(kpk)
    (cpk, csk) = bls.extractCred(kpk,ksk,1)
    print("spk-ver--%s" % spk)
    MM = b'I love PC'
    Mpad =pad(MM,225)
    m=Mpad.decode('latin-1')
    MM2 = group.random(GT)
    # MM=b'I love PC'
    MM3=bls.dump(MM2)
    m = bls.encodeToZn(MM3)
    #MM = MM1.encode('latin-1')
    #m=MM.decode('latin-1')
    print("MM", m)
    print("MM size", bitsize(m))

    MP = 1
    (CT) = bls.signcrypt( kpk, spk, ssk, MP, m)
    print("ciphertext-ver--%s" % CT)
    bls.testCred(kpk, ssk,spk, cpk, csk)
    out = bls.decrypt( kpk, spk, csk, cpk, CT)
    print("Original pad m:", m)
    # for real message
    #print("Original data:", bls.dump(m))
    print("output   byte:", out)
   # print("bitsite decrypted output M:", bitsize(out))
    # pad and unpad
    #out2=bls.dedump(out)
    # below only real message
    #out3= bytes(out2,'latin-1')
    #Munpad = unpad(out3,225)
    #print("output:", Munpad)
    print("bitsite Q3", bitsize(CT['Q3']))

def maintest(num, gup, n,MP, L, padNum,message):
    number=num
    data=[]
    counter=1
    group = PairingGroup(gup)
    bls = LBSOP(group)
    (pkk) = bls.setup()
    GTtest=True
    #start with one random IDV
    #IDV=randomStringGen(8)+"@mail.com"
    #IDV = "other@mail.com"
    #(kpk, ksk) = bls.extractPKG(pkk, n)
    # start sign
    for i in range(1, number+1):
        # start record key gen
        n=i+3
        start = time.perf_counter()
        (kpk, ksk) = bls.extractPKG(pkk, n)
        end = time.perf_counter()
        setup = ((end - start) * 1000)
        start = time.perf_counter()
        (spkE, sskE) = bls.extractKey(kpk)
        (cpkE, cskE) = bls.extractCred(kpk, ksk, L)
        end = time.perf_counter()
        keyextract = ((end - start) * 1000)
        (spkR, sskR) = bls.extractKey(kpk)
        (cpkR, cskR) = bls.extractCred(kpk, ksk, L)
        # Random generate messsage
        if not GTtest:
            MM1=randomStringGen(20)
            #MM=b'I love PC'
            MM = MM1.encode('latin-1')
            print("m", MM)
            Mpad = pad(MM, padNum)
            #Mpad = pad(MM.encode('utf-8'), 225)
            m = Mpad.decode('latin-1')
            #print("m",m)
        else:
            # random message from GT
            MM2=group.random(GT)
            #MM=bls.dump(MM3)
            MM=group.serialize(MM2)
            #MM=b'I love PC'
            m=bls.encodeToZn(MM)
            #print("m", m)
        #start record sign
        start=time.perf_counter()
        (CT) = bls.signcrypt(kpk, spkE, sskE, MP, m)
        end=time.perf_counter()
        sign=((end-start)*1000)
        if debug:
            print("-------------------------------signatur number {0}:{1}------------------------------------".format(i, j))
            print ("IDI-sign--%s"%IDI)
            print ("IDS-sign--%s"%IDS)
            print ("spk-sign--%s"%spk)
            print ("sspk-sign--%s"%sspk)
            print("q--{0}: {0}".format(i, q))
            print("-------------------------------signatur number {0}:{1}------------------------------------".format(i, j))
        #start record varidate pk
        start=time.perf_counter()
        out = bls.decrypt( kpk, spkE, cskR, cpkR, CT)
        end=time.perf_counter()
        verify=((end-start)*1000)
        total=keyextract+sign+verify
        data.append( (counter, setup,keyextract, sign, verify, total) )
        print("Counter:",counter)
        counter+=1
        if debug:
            print ("verify out for {:d} : {:}".format(counter-1,  out))
        if not GTtest:
            out2 = bls.dedump(out)
            #out3 = out2.decode('latin-1')
            out3 = bytes(out2, 'latin-1')
            Munpad = unpad(out3, padNum)
            assert MM == Munpad, "invalid signature"
        else:
            #MM3=bls.dump(m)
            #MM4 = bls.encodeToZn(MM3)
            MM4 = bls.decodeFromZn(m)
            #print("m byte:", bytes(M, 'latin-1'))
            #print("MM4:",MM4)
            #print ("m:",m)
            #print ("out:",out)
            #out2 = bls.dedump(out)
            #m2=bls.encodeToZn()
            #out2a=bls.dump(out)
            #out2= bls.encodetoZn(out2a)
            #out3=
            #print("out2:", out2)
            assert MM4 == out, "invalid signature"
            print("Out:",MM4 == out)
        if debug:
            continue
            #print("q--{0}: {0}".format(i, q))
            #print("-------------------------------End verify signatur number {0}:{1}------------------------------------".format(i, j))
    fileout="LBS_data_"+gup+"_MP_"+str(MP)+"_L_"+str(L)+"_PAD_"+str(padNum)+"_"+message+"_"+randomStringGen(2)+".csv"
    f=open(fileout, "w+")
    out="counter, setup, keyextract, sign, verify, total \n"
    f.write(out)
    for i in data:
        out="{:d},{:f},{:f},{:f},{:f},{:f} \n".format(i[0], i[1], i[2], i[3], i[4],i[5])
        f.write(out)


if __name__ == "__main__":
    debug = True
    main()
print("---------------------------------------------------------------------------")
debug=False
#gup='MNT224'
gup='SS512'
n=5
MP=2
L=3
padNum=192 # multiple of 64 is the best 192 or 196 is still work
message="MessageGT"
#maintest(500,gup,n,MP,L,padNum,message)
maintest(10,gup,n,MP,L,padNum,message)
#mainindividual(250, gup)
print("end")