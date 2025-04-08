from ctypes import *

"""
《GM/T 0006-2012 密码应用标识规范》 非对称密码算法标识 SM2部分
"""
SGD_SM2 = 0x00020100
SGD_SM2_1 = 0x00020200
SGD_SM2_2 = 0x00020400
SGD_SM2_3 = 0x00020800


"""
《GM/T 0018-2012 密码设备应用接口规范》 ECC密钥数据结构定义
"""
ECCREF_MAX_BITS = 512
ECCREF_MAX_LEN = (ECCREF_MAX_BITS + 7) // 8


class ECCrefPublicKey(Structure):
    _fields_ = [
        ("bits", c_uint32),
        ("x", c_ubyte * ECCREF_MAX_LEN),
        ("y", c_ubyte * ECCREF_MAX_LEN)
    ]


class ECCrefPrivateKey(Structure):
    _fields_ = [
        ("bits", c_uint32),
        ("K", c_ubyte * ECCREF_MAX_LEN)
    ]


class ECCCipher(Structure):
    _fields_ = [
        ("x", c_ubyte * ECCREF_MAX_LEN),
        ("y", c_ubyte * ECCREF_MAX_LEN),
        ("M", c_ubyte * 32),
        ("L", c_uint32),
        ("C", c_ubyte * 1)
    ]


class ECCSignature(Structure):
    _fields_ = [
        ("r", c_ubyte * ECCREF_MAX_LEN),
        ("s", c_ubyte * ECCREF_MAX_LEN)
    ]
