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
from charm.schemes.abenc.abenc_maabe_rw15 import MaabeRW15,merge_dicts
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
    maabe = MaabeRW15(group)
    public_parameters = maabe.setup()
    attributes1 = ['ONE', 'TWO']
    attributes2 = ['THREE', 'FOUR']
    (public_key1, secret_key1) = maabe.authsetup(public_parameters, 'UT')
    (public_key2, secret_key2) = maabe.authsetup(public_parameters, 'OU')
    public_keys = {'UT': public_key1, 'OU': public_key2}
    gid = "bob"
    user_attributes1 = ['STUDENT@UT', 'PHD@UT']
    user_attributes2 = ['STUDENT@OU']
    user_keys1 = maabe.multiple_attributes_keygen(public_parameters, secret_key1, gid, user_attributes1)
    user_keys2 = maabe.multiple_attributes_keygen(public_parameters, secret_key2, gid, user_attributes2)
    user_keys = {'GID': gid, 'keys': merge_dicts(user_keys1, user_keys2)}
    message = group.random(GT)
    #print("message len", len(message))
    mm = objectToBytes(message, group)
    print(mm)
    mm2 = encodeToZn(mm)
    print("message size", bitsize(mm2))
    access_policy = '(STUDENT@UT or PROFESSOR@OU) and (STUDENT@UT or MASTERS@OU)'
    cipher_text = maabe.encrypt(public_parameters, public_keys, message, access_policy)
    decrypted_message = maabe.decrypt(public_parameters, user_keys, cipher_text)
    print(decrypted_message == message)


    # # IDS = "bob@mail.com"
    # # ID=MLCSC.dump(IDS)
    # # group.hash(ID, ZR)
    # IDS = "bob@mail.com"
    # # group.hash((IDS), ZR)
    # (kpk, ksk) = bls.extractPKG(pkk, 2)
    # (spk, ssk) = bls.extractKey(kpk)
    # (cpk, csk) = bls.extractCred(kpk,ksk,1)
    # print("spk-ver--%s" % spk)
    # MM = b'I love PC'
    # Mpad =pad(MM,225)
    # m=Mpad.decode('latin-1')
    # MP = 1
    # (CT) = bls.signcrypt( kpk, spk, ssk, MP, m)
    # print("ciphertext-ver--%s" % CT)
    # bls.testCred(kpk, ssk,spk, cpk, csk)
    # out = bls.decrypt( kpk, spk, csk, cpk, CT)
    # print("Original pad m:", m)
    # print("Original data:", bls.dump(m))
    # print("output   byte:", out)
    # # pad and unpad
    # out2=bls.dedump(out)
    # out3= bytes(out2,'latin-1')
    # Munpad = unpad(out3,225)
    # print("output:", Munpad)


def maintest(num, gup, n,MP, L, padNum,messageV):
    number=num
    data=[]
    counter=1
    group = PairingGroup(gup)
    maabe = MaabeRW15(group)
    public_parameters = maabe.setup()
    #(public_key1, secret_key1) = maabe.authsetup(public_parameters, 'UT')
    #(public_key2, secret_key2) = maabe.authsetup(public_parameters, 'OU')
    #public_keys = {'UT': public_key1, 'OU': public_key2}
    # start sign
    for i in range(1, number+1):
        start = time.perf_counter()
        (public_key1, secret_key1) = maabe.authsetup(public_parameters, 'UT')
        end = time.perf_counter()
        setup = ((end - start) * 1000)
        (public_key2, secret_key2) = maabe.authsetup(public_parameters, 'OU')
        public_keys = {'UT': public_key1, 'OU': public_key2}
        gid = "bob"
        #user_attributes1 = ['LEVEL1@UT', 'LEVEL2@UT','LEVEL3@UT']
        user_attributes2 = ['STUDENT@OU']
        attributesAll = ['ONE', 'TWO', 'THREE','FOUR','FIVE','SIX','SEVEN','EIGHT','NIGHT','TEN', 'ELEVEN','TWELVE','THIRTEEN']
        al=attributesAll[0:i+2]
        user_attributes1=[i+'@UT' for i in al ]
        user_keys1 = maabe.multiple_attributes_keygen(public_parameters, secret_key1, gid, user_attributes1)
        start = time.perf_counter()
        user_keys2 = maabe.multiple_attributes_keygen(public_parameters, secret_key2, gid, user_attributes2)
        end = time.perf_counter()
        keyextract = ((end - start) * 1000)
        # user key
        user_keys = {'GID': gid, 'keys': merge_dicts(user_keys1, user_keys2)}
        # Random generate messsage
        message = group.random(GT)
        # set policy
        #access_policy = '(LEVEL2@UT or LEVEL3@OU)'
        access_policy = '(ONE@UT or TWO@OU)'
        #start record sign
        start=time.perf_counter()
        cipher_text = maabe.encrypt(public_parameters, public_keys, message, access_policy)
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
        decrypted_message = maabe.decrypt(public_parameters, user_keys, cipher_text)
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
    fileout="ABENC_RW15_data_"+gup+"_MP_"+str(MP)+"_L_"+str(L)+"_PAD_"+str(padNum)+"_"+messageV+"_"+randomStringGen(2)+".csv"
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
# debug=False
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



