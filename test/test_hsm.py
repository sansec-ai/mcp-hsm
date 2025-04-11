import unittest,os,sys
# 获取当前文件所在目录的父目录（项目根目录）
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
# 将项目根目录添加到模块搜索路径
sys.path.insert(0, project_root)

from server import *
import sm2,symm
from printdata import print_data

class TestHSM(unittest.TestCase):
    def setUp(self):
        self.lib = os.getenv("LIBHSM_PATH", "./lib/libhsm_0018.so")
    def test_rand_gen(self):
        ret, rand = rand_gen(16)
        self.assertEqual(ret, 0)
        self.assertEqual(len(rand), 16*2)
        print_data("rand", rand, len(rand), 16)
    def test_sm2_sign_verify(self):
        ret, pub, pri = sm2_keygen()
        print_data("pub", pub, len(pub), 16)
        print_data("pri", pri, len(pri), 16)

        ret, rand = rand_gen(32)
        print_data("rand", rand, len(rand), 16)

        ret, sign = sm2_sign(rand, pri)
        print_data("sign", sign, len(sign), 16)

        ret = sm2_verify(rand, pub, sign)
        print("sm2 verify ret: ", ret)
    def test_sm4_encrypt(self):        
        ret, key = rand_gen(16)
        self.assertEqual(ret, 0)
        print_data("key", key, len(key), 16)

        ret, iv = rand_gen(16)
        self.assertEqual(ret, 0)
        print_data("iv", iv, len(iv), 16)

        ret, data = rand_gen(32)
        self.assertEqual(ret, 0)
        print_data("data", data, len(data), 16)

        ret, iv, enc_data = symm_encrypt(key, symm.SGD_SM4_CBC, iv, data)
        self.assertEqual(ret, 0)
        print_data("enc_data", enc_data, len(enc_data), 16)

        ret, iv, plain_data = symm_decrypt(key, symm.SGD_SM4_CBC, iv, enc_data)
        self.assertEqual(ret, 0)
        print_data("plain_data", plain_data, len(plain_data), 16)


        ret, key = rand_gen(16)
        self.assertEqual(ret, 0)
        print_data("key", key, len(key), 16)

        ret, data = rand_gen(32)
        self.assertEqual(ret, 0)
        print_data("data", data, len(data), 16)

        ret, iv, enc_data = symm_encrypt(key, symm.SGD_SM4_ECB, "", data)
        self.assertEqual(ret, 0)
        print_data("enc_data", enc_data, len(enc_data), 16)

        ret, iv, plain_data = symm_decrypt(key, symm.SGD_SM4_ECB, "", enc_data)
        self.assertEqual(ret, 0)
        print_data("plain_data", plain_data, len(plain_data), 16)

if __name__ == '__main__':
    unittest.main()