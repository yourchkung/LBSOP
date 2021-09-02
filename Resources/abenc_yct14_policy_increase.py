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
from charm.schemes.abenc.abenc_yct14 import EKPabe
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
    kpabe = EKPabe(group)
    MM2 = group.random(GT)
    MM = group.serialize(MM2)
    #message = encodeToZn(MM)
    message =MM
    print(MM)
    #message = b"Some Random Message"
    attributes = ['ONE', 'TWO', 'THREE']
    #access_policy = '((four or three) and (three or one))'
    policy = '(ONE or THREE) and (THREE or TWO)'
    (master_public_key, master_key) = kpabe.setup(attributes)
    user_attributes = ['ONE', 'TWO']
    secret_key = kpabe.keygen(master_public_key, master_key, policy)
    cipher_text = kpabe.encrypt(master_public_key,message, attributes)
    decrypted_message = kpabe.decrypt(cipher_text, secret_key)
    print(message == decrypted_message)


def maintest(num, gup, n,MP, L, padNum,messageV):
    number=num
    data=[]
    counter=1
    group = PairingGroup(gup)
    kpabe = EKPabe(group)
    # set attribute
    #attributes = ['ONE', 'TWO', 'THREE',"FOUR"]

    #(master_public_key, master_key) = kpabe.setup(attributes)
    # start sign
    for i in range(1, number+1):
        # set attribute
        #attributes = ['ONE', 'TWO', 'THREE']
        # set policy
        attributesAll = ['ONE', 'TWO', 'THREE', 'FOUR', 'FIVE', 'SIX', 'SEVEN', 'EIGHT', 'NIGHT', 'TEN', 'ELEVEN',
                         'TWELVE', 'THIRTEEN']
        attributes = attributesAll[0:i + 2]
        # user key
        start = time.perf_counter()
        (master_public_key, master_key) = kpabe.setup(attributes)
        end = time.perf_counter()
        setup = ((end - start) * 1000)
        policy = '(ONE or THREE) and (THREE or TWO)'
        # user key
        start = time.perf_counter()
        secret_key = kpabe.keygen(master_public_key, master_key, policy)
        end = time.perf_counter()
        keyextract = ((end - start) * 1000)
        # Random generate messsage
        MM2 = group.random(GT)
        message = group.serialize(MM2)
        #start record sign
        user_attributes = ['ONE', 'TWO']
        start=time.perf_counter()
        cipher_text = kpabe.encrypt(master_public_key,message, user_attributes)
        end=time.perf_counter()
        sign=((end-start)*1000)

        #start record varidate pk
        start=time.perf_counter()
        decrypted_message = kpabe.decrypt(cipher_text, secret_key)
        end=time.perf_counter()
        verify=((end-start)*1000)
        total=keyextract+sign+verify
        data.append( (counter, setup, keyextract, sign, verify, total) )
        print("Counter:",counter)
        counter+=1
        #if debug:
        #    print ("verify out for {:d} : {:}".format(counter-1,  out))
        assert message== decrypted_message, "invalid ciphertext"
        #mm=objectToBytes(message,group)
        #out3 = bytes(mm, 'latin-1')
        #print(mm)
        mm2=encodeToZn(message)
        print("bitsite", bitsize(mm2))
        #if debug:
        #    #print("q--{0}: {0}".format(i, q))
        #    print("-------------------------------End verify signatur number {0}:{1}------------------------------------".format(i, j))
    fileout="ABENC_yct14_data_"+gup+"_MP_"+str(MP)+"_L_"+str(L)+"_PAD_"+str(padNum)+"_"+messageV+"_"+randomStringGen(2)+".csv"
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

#gup='MNT224'
gup='SS512'
n=5
MP=2
L=3
padNum=192 # multiple of 64 is the best 192 or 196 is still work
message="random MessageGT"
#maintest(500,gup,n,MP,L,padNum,message)
maintest(10,gup,n,MP,L,padNum,message)
# #mainindividual(250, gup)
print("end")