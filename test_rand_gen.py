from tools import rand_gen
from printdata import print_data

ret, rand = rand_gen(16)
print_data("rand", rand, len(rand), 16)