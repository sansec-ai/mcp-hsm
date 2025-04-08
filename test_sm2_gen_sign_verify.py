from tools import rand_gen
from tools import sm2_keygen
from tools import sm2_sign
from tools import sm2_verify

from printdata import print_data
from ctypes import *

ret, pub, pri = sm2_keygen()
print_data("pub", pub, len(pub), 16)
print_data("pri", pri, len(pri), 16)

ret, rand = rand_gen(32)
print_data("rand", rand, len(rand), 16)

ret, sign = sm2_sign(rand, pri)
print_data("sign", sign, len(sign), 16)

ret = sm2_verify(rand, pub, sign)
print("sm2 verify ret: ", ret)
