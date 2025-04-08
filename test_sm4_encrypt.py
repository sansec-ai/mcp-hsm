from tools import rand_gen
from tools import symm_encrypt
from tools import symm_decrypt
from hsm import SGD_SM4_CBC
from hsm import SGD_SM4_ECB

from printdata import print_data

ret, key = rand_gen(16)
print_data("key", key, len(key), 16)

ret, iv = rand_gen(16)
print_data("iv", iv, len(iv), 16)

ret, data = rand_gen(32)
print_data("data", data, len(data), 16)

ret, iv, enc_data = symm_encrypt(key, SGD_SM4_CBC, iv, data)
print_data("enc_data", enc_data, len(enc_data), 16)

ret, iv, plain_data = symm_decrypt(key, SGD_SM4_CBC, iv, enc_data)
print_data("plain_data", plain_data, len(plain_data), 16)


ret, key = rand_gen(16)
print_data("key", key, len(key), 16)

ret, data = rand_gen(32)
print_data("data", data, len(data), 16)

ret, iv, enc_data = symm_encrypt(key, SGD_SM4_ECB, "", data)
print_data("enc_data", enc_data, len(enc_data), 16)

ret, iv, plain_data = symm_decrypt(key, SGD_SM4_ECB, "", enc_data)
print_data("plain_data", plain_data, len(plain_data), 16)