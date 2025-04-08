from tools import rand_gen
from printdata import print_data

ret, rand = rand_gen(16)
print("rand:", rand)
print_data("rand", bytes.fromhex(rand), len(bytes.fromhex(rand)), 16)