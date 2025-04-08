from tools import rand_gen
from tools import symm_encrypt
from tools import symm_decrypt
from hsm import SGD_SM4_CBC

from printdata import print_data

ret, key = rand_gen(16)
print("key:", key)
print_data("key", bytes.fromhex(key), len(bytes.fromhex(key)), 16)

ret, iv = rand_gen(16)
print("iv:", iv)
print_data("iv", bytes.fromhex(iv), len(bytes.fromhex(iv)), 16)

ret, data = rand_gen(32)
print("data:", data)
print_data("data", bytes.fromhex(data), len(bytes.fromhex(data)), 16)

ret, iv, enc_data = symm_encrypt(key, SGD_SM4_CBC, iv, data)
print("enc_data:",enc_data)
print_data("enc_data", bytes.fromhex(enc_data), len(bytes.fromhex(enc_data)), 16)

ret, iv, plain_data = symm_decrypt(key, SGD_SM4_CBC, iv, enc_data)
print("plain_data:",plain_data)
print_data("plain_data", bytes.fromhex(plain_data), len(bytes.fromhex(plain_data)), 16)
