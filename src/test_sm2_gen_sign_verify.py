from tools import rand_gen
from tools import sm2_keygen
from tools import sm2_sign
from tools import sm2_verify

from printdata import print_data
from ctypes import *

ret, pub, pri = sm2_keygen()
print("pub:", pub)
print("pri:", pri)
print_data("pub", bytes.fromhex(pub), len(bytes.fromhex(pub)), 16)
print_data("pri", bytes.fromhex(pri), len(bytes.fromhex(pri)), 16)

ret, rand = rand_gen(32)
print("rand:", rand)
print_data("rand", bytes.fromhex(rand), len(bytes.fromhex(rand)), 16)

ret, sign = sm2_sign(rand, pri)
print("sign:", sign)
print_data("sign", bytes.fromhex(sign), len(bytes.fromhex(sign)), 16)

ret = sm2_verify(rand, pub, sign)
print("sm2 verify ret: ", ret)
