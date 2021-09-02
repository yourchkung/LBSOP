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
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth

def randomStringGen(size=30, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for x in range(size))
def encodeToZn(message):
        assert type(message) == bytes, "Input must be of type bytes"
        return integer(message)
debug = False
#class MLCSC(BLSAggregation):
def main():
    group = PairingGroup('SS512')
    cpabe = CPabe_BSW07(group)
    msg = group.random(GT)
    attributes = ['ONE', 'TWO', 'THREE']
    access_policy = '((four or three) and (three or one))'
    (master_public_key, master_key) = cpabe.setup()
    secret_key = cpabe.keygen(master_public_key, master_key, attributes)
    cipher_text = cpabe.encrypt(master_public_key, msg, access_policy)
    decrypted_msg = cpabe.decrypt(master_public_key, secret_key, cipher_text)
    print(msg == decrypted_msg)


def maintest(num, gup, n,MP, L, padNum,messageV):
    number=num
    data=[]
    counter=1
    group = PairingGroup(gup)
    cpabe = CPabe_BSW07(group)
    (master_public_key, master_key) = cpabe.setup()
    # start sign
    for i in range(1, number+1):
        # set attribute
        attributesAll = ['ONE', 'TWO', 'THREE', 'FOUR', 'FIVE', 'SIX', 'SEVEN', 'EIGHT', 'NIGHT', 'TEN', 'ELEVEN',
                         'TWELVE', 'THIRTEEN']
        attributes = attributesAll[0:i + 2]
        # set policy
        access_policy = '((two or three) and (three or one))'
        # user key
        #setup
        start = time.perf_counter()
        (master_public_key, master_key) = cpabe.setup()
        end = time.perf_counter()
        setup = ((end - start) * 1000)
        # key extract
        start = time.perf_counter()
        secret_key = cpabe.keygen(master_public_key, master_key, attributes)
        end = time.perf_counter()
        keyextract = ((end - start) * 1000)
        # Random generate messsage
        message = group.random(GT)
        #start record sign
        start=time.perf_counter()
        cipher_text = cpabe.encrypt(master_public_key, message, access_policy)
        end=time.perf_counter()
        sign=((end-start)*1000)
        #if debug:
            #print("-------------------------------signatur number {0}:{1}------------------------------------".format(i, j))
            #print ("IDI-sign--%s"%IDI)
            #print ("IDS-sign--%s"%IDS)
            #print ("spk-sign--%s"%spk)
            #print ("sspk-sign--%s"%sspk)
            #print("q--{0}: {0}".format(i, q))
            #print("-------------------------------signatur number {0}:{1}------------------------------------".format(i, j))
        #start record varidate pk
        start=time.perf_counter()
        decrypted_message = cpabe.decrypt(master_public_key, secret_key, cipher_text)
        end=time.perf_counter()
        verify=((end-start)*1000)
        total=keyextract+sign+verify
        data.append( (counter, setup, keyextract, sign, verify, total) )
        print("Counter:",counter)
        counter+=1
        #if debug:
        #    print ("verify out for {:d} : {:}".format(counter-1,  out))
        assert message== decrypted_message, "invalid ciphertext"
        mm=objectToBytes(message,group)
        #out3 = bytes(mm, 'latin-1')
        print(mm)
        mm2=encodeToZn(mm)
        print("bitsite", bitsize(mm2))
        #if debug:
        #    #print("q--{0}: {0}".format(i, q))
        #    print("-------------------------------End verify signatur number {0}:{1}------------------------------------".format(i, j))
    fileout="ABENC_bsw07_data_"+gup+"_MP_"+str(MP)+"_L_"+str(L)+"_PAD_"+str(padNum)+"_"+messageV+"_"+randomStringGen(2)+".csv"
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

gup='MNT224'
#gup='SS512'
n=5
MP=2
L=3
padNum=192 # multiple of 64 is the best 192 or 196 is still work
message="random MessageGT"
#maintest(500,gup,n,MP,L,padNum,message)
maintest(10,gup,n,MP,L,padNum,message)
# #mainindividual(250, gup)
print("end")