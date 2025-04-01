# 在文件顶部添加导入
from ctypes import *
from asn1crypto import core
from struct import pack
import base64
import os

# 加载HSM动态库（示例路径，需根据实际调整）
hsm_lib = CDLL('./libswsds.so')
# 算法标识符常量
SGD_SM3 = 0x00000001
SGD_SMS4_ECB = 0x00000401
SGD_SMS4_CBC = 0x00000402

# 定义C结构体和类型映射
class RSArefPublicKey(Structure):
    _fields_ = [("bits", c_uint),
                ("m", c_ubyte * 512),
                ("e", c_ubyte * 512)]

# 定义rsa加密函数原型
hsm_lib.SDF_InternalPublicKeyOperation_RSA.argtypes = [
    c_void_p,  # hSessionHandle
    c_uint32,  # uiKeyIndex
    POINTER(c_ubyte),  # pucDataInput
    c_uint32,  # uiInputLength
    POINTER(c_ubyte),  # pucDataOutput
    POINTER(c_uint32)  # puiOutputLength
]
hsm_lib.SDF_InternalPublicKeyOperation_RSA.restype = c_uint32

# 公钥结构体
class ECCrefPublicKey(Structure):
    _fields_ = [
        ("bits", c_uint),
        ("x", c_ubyte * 64),  # 根据头文件定义调整大小
        ("y", c_ubyte * 64)
    ]
# 定义导出公钥函数原型
hsm_lib.SDF_ExportSignPublicKey_ECC.argtypes = [
    c_void_p,        # hSessionHandle
    c_uint32,        # uiKeyIndex
    POINTER(ECCrefPublicKey)  # pucPublicKey
]
hsm_lib.SDF_ExportSignPublicKey_ECC.restype = c_uint32

# 定义哈希函数原型
hsm_lib.SDF_Hash.argtypes = [
    c_void_p,        # hSessionHandle
    c_uint32,        # uiAlgID
    POINTER(ECCrefPublicKey),  # pucPublicKey
    POINTER(c_ubyte),# pucID
    c_uint32,        # uiIDLength
    POINTER(c_ubyte),# pucData
    c_uint32,        # uiDataLength
    POINTER(c_ubyte),# pucHash
    POINTER(c_uint32)# puiHashLength
]
hsm_lib.SDF_Hash.restype = c_uint32

# 定义SM2签名结构体
class ECCSignature(Structure):
    _fields_ = [
        ("r", c_ubyte * 64),  # ECCref_MAX_LEN=64 for 512bit
        ("s", c_ubyte * 64)
    ]

# 设置签名函数原型
hsm_lib.SDF_InternalSign_ECC.argtypes = [
    c_void_p,        # hSessionHandle
    c_uint32,        # uiISKIndex
    POINTER(c_ubyte),# pucData
    c_uint32,        # uiDataLength
    POINTER(ECCSignature)  # pucSignature
]
hsm_lib.SDF_InternalSign_ECC.restype = c_uint32

# 绑定ImportKey函数参数类型
hsm_lib.SDF_ImportKey.argtypes = [
    c_void_p,           # hSessionHandle (会话句柄)
    POINTER(c_ubyte),   # pucKey (密钥数据指针)
    c_uint32,           # uiKeyLength (密钥长度)
    POINTER(c_void_p)   # phKeyHandle (输出的密钥句柄)
]
hsm_lib.SDF_ImportKey.restype = c_uint32

# 设置函数原型
hsm_lib.SDF_Encrypt.argtypes = [
    c_void_p,        # hSessionHandle
    c_void_p,        # hKeyHandle (密钥句柄)
    c_uint32,        # uiAlgID (算法标识)
    POINTER(c_ubyte),# pucIV
    POINTER(c_ubyte),# pucData
    c_uint32,        # uiDataLength
    POINTER(c_ubyte),# pucEncData
    POINTER(c_uint32)# puiEncDataLength
]
hsm_lib.SDF_Encrypt.restype = c_uint32

hsm_lib.SDF_Decrypt.argtypes = [
    c_void_p,        # hSessionHandle
    c_void_p,        # hKeyHandle
    c_uint32,        # uiAlgID
    POINTER(c_ubyte),# pucIV
    POINTER(c_ubyte),# pucEncData
    c_uint32,        # uiEncDataLength
    POINTER(c_ubyte),# pucData
    POINTER(c_uint32)# puiDataLength
]
hsm_lib.SDF_Decrypt.restype = c_uint32

# SM4 对称加密实现
def sm4_encrypt(plaintext: str, external_key: bytes) -> bytes:
    h_session = c_void_p()
    h_device = c_void_p()
    h_key = c_void_p()  # 密钥句柄
    
    # 打开设备会话
    if hsm_lib.SDF_OpenDevice(byref(h_device)) != 0:
        raise RuntimeError("Failed to open HSM device")
    if hsm_lib.SDF_OpenSession(h_device, byref(h_session)) != 0:
        raise RuntimeError("Failed to open HSM session")

    try:
        # 导入外部密钥
        ret = hsm_lib.SDF_ImportKey(
            h_session,
            cast(external_key, POINTER(c_ubyte)),
            len(external_key),
            byref(h_key)  # 获取密钥句柄
        )
        if ret != 0:
            raise RuntimeError(f"Import key failed: 0x{ret:08x}")

        # 准备数据和缓冲区
        plain_data = plaintext.encode()
        data_len = len(plain_data)
        encrypted = (c_ubyte * (data_len + 16))()
        output_len = c_uint32(0)

        # IV 初始化
        iv = (c_ubyte * 16)(*os.urandom(16))  # 生成随机IV
                
        # 执行加密
        ret = hsm_lib.SDF_Encrypt(
            h_session,
            h_key,                  # 使用密钥句柄(c_void_p)
            SGD_SMS4_CBC,           # 算法标识
            iv,                     # IV指针
            cast(plain_data, POINTER(c_ubyte)),
            data_len,
            encrypted,
            byref(output_len)       # 输出长度指针
            )
        if ret != 0:
            raise RuntimeError(f"Encrypt failed: 0x{ret:08x}")

         # 返回时需要包含IV
        return bytes(iv) + bytes(encrypted[:output_len.value])
    
    finally:
        hsm_lib.SDF_CloseSession(h_session)
        hsm_lib.SDF_CloseDevice(h_device)

# SM4 解密实现
def sm4_decrypt(ciphertext: bytes, external_key: bytes) -> str:
    """使用HSM硬件加速的SM4解密，导入外部密钥"""
    h_session = c_void_p()
    h_device = c_void_p()
    
    if hsm_lib.SDF_OpenDevice(byref(h_device)) != 0:
        raise RuntimeError("Failed to open HSM device")
    if hsm_lib.SDF_OpenSession(h_device, byref(h_session)) != 0:
        raise RuntimeError("Failed to open HSM session")

    try:
        h_key = c_void_p()
    
        # 分离IV和加密数据
        iv = ciphertext[:16]
        encrypted_data = ciphertext[16:]

        # 导入外部密钥
        ret = hsm_lib.SDF_ImportKey(
            h_session,
            cast(external_key, POINTER(c_ubyte)),
            len(external_key),
            byref(h_key)  # 获取密钥句柄
        )
        if ret != 0:
            raise RuntimeError(f"Import key failed: 0x{ret:08x}")

        # 准备缓冲区
        output_len = len(ciphertext)
        decrypted = (c_ubyte * output_len)()

        # 执行解密
        ret = hsm_lib.SDF_Decrypt(
                h_session,
                h_key,                  # 密钥句柄
                SGD_SMS4_CBC,           # 算法标识
                cast(iv, POINTER(c_ubyte)),  # IV
                cast(encrypted_data, POINTER(c_ubyte)),
                len(encrypted_data),
                decrypted,
                byref(output_len)
        )
        
        if ret != 0:
            raise RuntimeError(f"Decrypt failed: 0x{ret:08x}")

        return bytes(decrypted[:output_len]).decode()  # 返回解密结果
    
    finally:
        hsm_lib.SDF_CloseSession(h_session)
        hsm_lib.SDF_CloseDevice(h_device)

# RSA 加密实现
def rsa_encrypt(plaintext: str, key_index: str) -> str:
    """使用HSM硬件加速的RSA加密"""
    # 初始化HSM会话
    h_session = c_void_p()
    h_device = c_void_p()
    
    # 打开设备和会话（需根据实际库函数实现）
    if hsm_lib.SDF_OpenDevice(byref(h_device)) != 0:
        raise RuntimeError("Failed to open HSM device")
    if hsm_lib.SDF_OpenSession(h_device, byref(h_session)) != 0:
        raise RuntimeError("Failed to open HSM session")

    try:
        # 准备输入输出缓冲区
        input_data = plaintext.encode()
        input_len = len(input_data)
        output_len = c_uint32(512)  # RSA2048输出长度为256字节
        output_buf = (c_ubyte * 512)()

        # 调用HSM加密
        ret = hsm_lib.SDF_InternalPublicKeyOperation_RSA(
            h_session,
            key_index,
            cast(input_data, POINTER(c_ubyte)),
            input_len,
            output_buf,
            byref(output_len)
        )
        
        if ret != 0:
            raise RuntimeError(f"HSM operation failed with code 0x{ret:08x}")

        return bytes(output_buf[:output_len.value])
    finally:
        hsm_lib.SDF_CloseSession(h_session)
        hsm_lib.SDF_CloseDevice(h_device)
def sm2_signature_to_der(signature: ECCSignature) -> bytes:
    # 提取完整64字节（根据Go代码逻辑）
    r_bytes = bytes(bytearray(signature.r))
    s_bytes = bytes(bytearray(signature.s))
    print(f"signature.r: {', '.join(map(str, list(r_bytes)))}")
    print(f"signature.s: {', '.join(map(str, list(s_bytes)))}")
    #print(f"signature.r: {r_bytes.hex() }")
    #print(f"signature.s: {s_bytes.hex() }")

    # r_bytes = bytes(bytearray([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,82,179,249,217,67,184,227,20,193,7,224,10,124,231,6,227,98,246,199,39,253,193,239,98,93,228,107,107,170,96,230,218]))
    # s_bytes = bytes(bytearray([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4,140,132,152,223,99,231,137,8,29,184,167,70,117,14,203,238,197,200,87,95,77,40,231,142,19,179,201,10,140,91,214]))

    r_int = int.from_bytes(r_bytes, byteorder='big')
    s_int = int.from_bytes(s_bytes, byteorder='big')
    
    # 将整数转换为字节，确保最高位不是1（否则会被解释为负数）
    def int_to_bytes(value):
        byte_length = (value.bit_length() + 7) // 8
        if byte_length == 0:
            byte_length = 1
        bytes_value = value.to_bytes(byte_length, byteorder='big')
        # 如果最高位是1，前面补0
        if bytes_value[0] & 0x80:
            bytes_value = b'\x00' + bytes_value
        return bytes_value
    
    r_bytes_der = int_to_bytes(r_int)
    s_bytes_der = int_to_bytes(s_int)
    
    # 构造DER格式
    # DER格式为: 0x30 <总长度> 0x02 <r长度> <r值> 0x02 <s长度> <s值>
    der_sequence = b'\x30'
    total_length = 2 + len(r_bytes_der) + 2 + len(s_bytes_der)
    der_sequence += pack('B', total_length)
    der_sequence += b'\x02' + pack('B', len(r_bytes_der)) + r_bytes_der
    der_sequence += b'\x02' + pack('B', len(s_bytes_der)) + s_bytes_der
    
    return der_sequence

# SM2 签名
def sm2_sign(plaintext: str, key_index: str) -> str:
    """使用HSM硬件加速的SM2签名"""
    # 初始化HSM会话
    h_session = c_void_p()
    h_device = c_void_p()
    # 打开设备会话
    if hsm_lib.SDF_OpenDevice(byref(h_device)) != 0:
        raise RuntimeError("Failed to open HSM device")
    if hsm_lib.SDF_OpenSession(h_device, byref(h_session)) != 0:
        raise RuntimeError("Failed to open HSM session")

    try:
        # Step 1: 导出签名公钥
        public_key = ECCrefPublicKey()
        ret = hsm_lib.SDF_ExportSignPublicKey_ECC(
            h_session,
            key_index,
            byref(public_key)
        )
        if ret != 0:
            raise RuntimeError(f"导出公钥失败，错误码：0x{ret:08x}")

        # Step 2: 计算SM3哈希（带公钥信息）
        hash_buffer = (c_ubyte * 32)()  # SM3输出32字节
        hash_len = c_uint32(32)
        
        # 准备用户ID数据
        user_id_data = "1234567812345678".encode('utf-8')
        
        # 准备明文数据
        plaintext_data = plaintext.encode('utf-8')
        
        # 调用HSM哈希计算
        ret = hsm_lib.SDF_Hash(
            h_session,
            0x00000001,  # SGD_SM3
            byref(public_key),
            cast(user_id_data, POINTER(c_ubyte)),
            len(user_id_data),
            cast(plaintext_data, POINTER(c_ubyte)),
            len(plaintext_data),
            hash_buffer,
            byref(hash_len)
        )
        if ret != 0:
            raise RuntimeError(f"哈希计算失败，错误码：0x{ret:08x}")

        # Step 3: 对哈希值进行签名
        signature = ECCSignature()
        ret = hsm_lib.SDF_InternalSign_ECC(
            h_session,
            key_index,
            cast(bytes(hash_buffer[:hash_len.value]), POINTER(c_ubyte)),
            hash_len.value,
            byref(signature)
        )
        if ret != 0:
            raise RuntimeError(f"签名失败，错误码：0x{ret:08x}")

        signature_der = sm2_signature_to_der(signature)
        
        return {
            # "public_key": {
            #     "x": base64.b64encode(bytes(public_key.x)).decode(),
            #     "y": base64.b64encode(bytes(public_key.y)).decode()
            # },
            "hash": bytes(hash_buffer[:hash_len.value]).hex(),
            "signature":  base64.b64encode(signature_der).decode(),
            "debug":{
                "r": base64.b64encode(signature.r).decode(),
                "s": base64.b64encode(signature.s).decode(),
                "der":signature_der.hex()
            }
        }
    finally:
        hsm_lib.SDF_CloseSession(h_session)
        hsm_lib.SDF_CloseDevice(h_device)
