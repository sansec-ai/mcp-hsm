from ctypes import *
from typing import Tuple
from sm2 import *


class hsm:
    def __init__(self, lib):
        self.lib = CDLL(lib)
        self._setup_function_prototypes()

    def _setup_function_prototypes(self):
        prototypes = {
            'SDF_OpenDevice': ([c_void_p], c_int32),
            'SDF_CloseDevice': ([c_void_p], c_int32),
            'SDF_OpenSession': ([c_void_p, c_void_p], c_int32),
            'SDF_CloseSession': ([c_void_p], c_int32),
            'SDF_GenerateRandom': ([c_void_p, c_uint32, c_void_p], c_int32),
            'SDF_ImportKey': ([c_void_p, c_void_p, c_uint32, c_void_p], c_int32),
            'SDF_DestroyKey': ([c_void_p, c_void_p], c_int32),
            'SDF_Encrypt': ([c_void_p, c_void_p, c_uint32, c_void_p, c_void_p,
                             c_uint32, c_void_p, c_void_p], c_int32),
            'SDF_Decrypt': ([c_void_p, c_void_p, c_uint32, c_void_p, c_void_p,
                             c_uint32, c_void_p, c_void_p], c_int32),
            'SDF_GenerateKeyPair_ECC': ([c_void_p, c_uint32, c_uint32, c_void_p, c_void_p], c_uint32),
            'SDF_ExternalSign_ECC': ([c_void_p, c_uint32, c_void_p, c_void_p, c_uint32, c_void_p], c_uint32),
            'SDF_ExternalVerify_ECC': ([c_void_p, c_uint32, c_void_p, c_void_p, c_uint32, c_void_p], c_uint32)
        }

        for func_name, (argtypes, restype) in prototypes.items():
            func = getattr(self.lib, func_name)
            func.argtypes = argtypes
            func.restype = restype

    def SDF_OpenDevice(self) -> int:
        """
        打开设备
        desc: 打开密码设备
        param dev: 返回设备句柄
        return: 0 成功 非0 失败
        ps: dev由函数初始化并填写内容
        """
        self.dev = c_void_p()
        return self.lib.SDF_OpenDevice(byref(self.dev))

    def SDF_CloseDevice(self) -> int:
        """
        关闭设备
        desc: 关闭密码设备，并释放相关资源
        param dev: 已打开的设备句柄
        return: 0 成功 非0 失败
        """
        return self.lib.SDF_CloseDevice(self.dev)

    def SDF_OpenSession(self) -> Tuple[int, c_void_p]:
        """
        创建会话
        desc: 创建与密码设备的会话
        param dev: 已打开的设备句柄
        param hsess: 返回与密码设备建立的新会话句柄
        return: 0 成功 非0 失败
        """
        hsess = c_void_p()
        return self.lib.SDF_OpenSession(self.dev, byref(hsess)), hsess

    def SDF_CloseSession(self, hsess: c_void_p) -> int:
        """
        关闭会话
        desc: 关闭与密码设备已建立的会话，并释放相关资源
        param hsess: 与密码设备已建立的会话句柄
        return: 0 成功 非0 失败
        """
        return self.lib.SDF_CloseSession(hsess)

    def SDF_GenerateRandom(self, hsess: c_void_p, length: int) -> Tuple[int, bytes]:
        """
        产生随机数
        desc: 获取指定长度的随机数
        param hsess: 与密码设备已建立的会话句柄
        param length: 欲获取的随机数长度
        param rand: 缓冲区，用于存放获得的随机数
        return: 0 成功 非0 失败
        """
        rand = (c_ubyte * length)()
        return self.lib.SDF_GenerateRandom(hsess, length, rand), bytes(rand)

    def SDF_ImportKey(self, hsess: c_void_p, key: str) -> Tuple[int, c_void_p]:
        """
        导入明文会话密钥
        desc: 导入明文会话密钥，同时返回密钥句柄
        param hsess: 与密码设备已建立的会话句柄
        param key: 缓冲区，用于存放输入的密钥明文
        param hkey: 返回密钥句柄
        return: 0 成功 非0 失败
        """
        hkey = c_void_p()
        key = bytes.fromhex(key)
        return self.lib.SDF_ImportKey(hsess, key, len(key), byref(hkey)), hkey

    def SDF_DestroyKey(self, hsess: c_void_p, hkey: c_void_p) -> int:
        """
        销毁会话密钥
        desc: 销毁会话密钥，并释放为密钥句柄分配的资源
        param hsess: 与密码设备已建立的会话句柄
        param hkey: 输入的密钥句柄
        return: 0 成功 非0 失败
        """
        return self.lib.SDF_DestroyKey(hsess, hkey)

    def SDF_Encrypt(self, hsess: c_void_p, hkey: c_void_p, algid: int, iv: str, plaintext: str) -> Tuple[int, bytes, int]:
        """
        对称加密
        desc: 使用指定的密钥句柄和IV对数据进行对称加密运算
        param hsess: 与密码设备已建立的会话句柄
        param hkey: 指定的密钥句柄
        param algid: 算法标识，指定对称加密算法
        param iv: 缓冲区，用于存放输入和返回的IV数据
        param plaintext: 缓冲区，用于存放输入的数据明文
        param ciphertext: 缓冲区，用于存放输出的数据密文
        return: 0 成功 非0 失败
        ps: 此函数不对数据进行填充处理，输入的数据必须是指定算法分组长度的整数倍
        """
        plaintext = bytes.fromhex(plaintext)
        ciphertext_len = len(plaintext)
        ciphertext = (c_ubyte * ciphertext_len)()
        return self.lib.SDF_Encrypt(hsess, hkey, algid, iv, plaintext, len(plaintext), ciphertext, byref(c_uint32(ciphertext_len))), bytes(ciphertext), ciphertext_len

    def SDF_Decrypt(self, hsess: c_void_p, hkey: c_void_p, algid: int, iv: str, ciphertext: str) -> Tuple[int, bytes, int]:
        """
        对称解密
        desc: 使用指定的密钥句柄和IV对数据进行对称解密运算
        param hsess: 与密码设备已建立的会话句柄
        param hkey: 指定的密钥句柄
        param algid: 算法标识，指定对称加密算法
        param iv: 缓冲区，用于存放输入和返回的IV数据
        param ciphertext: 缓冲区，用于存放输入的数据密文
        param plaintext: 缓冲区，用于存放输出的数据明文
        return: 0 成功 非0 失败
        ps: 此函数不对数据进行填充处理，输入的数据必须是指定算法分组长度的整数倍
        """
        ciphertext = bytes.fromhex(ciphertext)
        plaintext_len = len(ciphertext)
        plaintext = (c_ubyte * plaintext_len)()
        return self.lib.SDF_Decrypt(hsess, hkey, algid, iv, ciphertext, len(ciphertext), plaintext, byref(c_uint32(plaintext_len))), bytes(plaintext), plaintext_len

    def SDF_GenerateKeyPair_ECC(self, hsess: c_void_p, algid: int = SGD_SM2, keybits: int = 256) -> Tuple[int, bytes, bytes]:
        """
        产生ECC密钥对并输出
        desc: 请求密码设备产生指定类型和模长的ECC密钥对
        param hsess: 与密码设备已建立的会话句柄
        param algid: 指定算法标识
        param keybits: 指定密钥长度
        param pub: ECC公钥结构
        param pri: ECC私钥结构
        return: 0 成功 非0 失败
        """
        pub = ECCrefPublicKey()
        pri = ECCrefPrivateKey()
        return self.lib.SDF_GenerateKeyPair_ECC(hsess, algid, keybits, byref(pub), byref(pri)), bytes(pub), bytes(pri)

    def SDF_ExternalSign_ECC(self, hsess: c_void_p, algid: int, pri: str, data: str) -> Tuple[int, bytes]:
        """
        外部密钥ECC签名
        desc: 使用外部ECC私钥对数据进行签名运算
        param hsess: 与密码设备已建立的会话句柄
        param algid: 算法标识，指定使用的ECC算法
        param pri: 外部ECC私钥结构
        param data: 缓冲区，用于存放外部输入的数据
        param sign: 缓冲区，用于存放输出的签名值结构
        return: 0 成功 非0失败
        ps: 输入数据为待签数据的杂凑值。当使用SM2算法时，该输入数据为待签数据经过SM2签名预处理的结果。
        """
        sign = ECCSignature()
        pri = bytes.fromhex(pri)
        data = bytes.fromhex(data)
        return self.lib.SDF_ExternalSign_ECC(hsess, algid, pri, data, len(data), byref(sign)), bytes(sign)

    def SDF_ExternalVerify_ECC(self, hsess: c_void_p, algid: int, pub: str, data: str, sign: str) -> int:
        """
        外部密钥ECC验证
        desc: 使用外部ECC公钥对ECC签名值进行验证运算
        param hsess: 与密码设备已建立的会话句柄
        param algid: 算法标识，指定使用的ECC算法
        param pub: 外部ECC公钥结构
        param data: 缓冲区，用于存放外部输入的数据
        param sign: 缓冲区，用于存放输入的签名值结构
        return: 0 成功 非0失败
        ps: 输入数据为待签数据的杂凑值。当使用SM2算法时，该输入数据为待签数据经过SM2签名预处理的结果。
        """
        pub = bytes.fromhex(pub)
        data = bytes.fromhex(data)
        sign = bytes.fromhex(sign)
        return self.lib.SDF_ExternalVerify_ECC(hsess, algid, pub, data, len(data), sign)
