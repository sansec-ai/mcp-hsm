import sys
sys.path.append('.')

import hsm
from sm2 import ECCrefPublicKey
from sm2 import ECCrefPrivateKey
from sm2 import ECCSignature
from sm2 import SGD_SM2
from symm import SGD_SM4_ECB
from typing import Tuple

import os
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if os.name == 'nt':
    lib_dir = os.getenv("LIBHSM_PATH", ".\\lib\\hsm_0018.dll")
elif os.name == 'posix':
    lib_dir = os.getenv("LIBHSM_PATH", "./lib/libhsm_0018.so")

from mcp.server.fastmcp import FastMCP
mcp = FastMCP("mcp-hsm")


@mcp.tool()
def rand_gen(len: int) -> Tuple[int, str]:
    """
    生成随机数
    param len: 随机数长度
    return:
        ret: return code 0 成功，其他失败
        data: 随机数
    """
 
    hsm_instance = hsm.hsm(lib_dir)

    ret = hsm_instance.SDF_OpenDevice()
    if ret != 0:
        print("SDF_OpenDevice failed, err code: ", hex(ret))
        return ret, None

    ret, session = hsm_instance.SDF_OpenSession()
    if ret != 0:
        print("SDF_OpenSession failed, err code: ", hex(ret))
        return ret, None
    
    ret, data = hsm_instance.SDF_GenerateRandom(session, len)
    if ret != 0:
        print("SDF_GenerateRandom failed, err code: ", hex(ret))
        return ret, None
    
    hsm_instance.SDF_CloseSession(session)
    hsm_instance.SDF_CloseDevice()
    return ret, data.hex()

@mcp.tool()
def sm2_keygen() -> Tuple[int, str, str]:
    """
    产生SM2公私钥对
    return : ret, pub, pri
        ret: return code 0 成功，其他失败
        pub: SM2公钥
        pri: SM2私钥
    """
 
    hsm_instance = hsm.hsm(lib_dir)

    ret = hsm_instance.SDF_OpenDevice()
    if ret != 0:
        print("SDF_OpenDevice failed, err code: ", hex(ret))
        return ret, None, None

    ret, session = hsm_instance.SDF_OpenSession()
    if ret != 0:
        print("SDF_OpenSession failed, err code: ", hex(ret))
        return ret, None, None
    
    ret, pub, pri = hsm_instance.SDF_GenerateKeyPair_ECC(session)
    if ret != 0:
        print("SDF_GenerateKeyPair_ECC failed, err code: ", hex(ret))
        return ret, None, None
    
    hsm_instance.SDF_CloseSession(session)
    hsm_instance.SDF_CloseDevice()
    return ret, pub.hex(), pri.hex()

@mcp.tool()
def sm2_sign(data: str, pri: str) -> Tuple[int, str]:
    """
    SM2签名
    param : data, pri
        data: 待签名数据
        pri: SM2私钥
    return : ret, sign
        ret: return code 0 成功，其他失败
        sign: SM2签名
    """

    hsm_instance = hsm.hsm(lib_dir)

    ret = hsm_instance.SDF_OpenDevice()
    if ret != 0:
        print("SDF_OpenDevice failed, err code: ", hex(ret))
        return ret, None

    ret, session = hsm_instance.SDF_OpenSession()
    if ret != 0:
        print("SDF_OpenSession failed, err code: ", hex(ret))
        return ret, None
    
    ret, sign = hsm_instance.SDF_ExternalSign_ECC(session, SGD_SM2, pri, data)
    if ret != 0:
        print("SDF_ExternalSign_ECC failed, err code: ", hex(ret))
        return ret, None

    hsm_instance.SDF_CloseSession(session)
    hsm_instance.SDF_CloseDevice()
    return 0, sign.hex()

@mcp.tool()
def sm2_verify(data: str, pub: str, sign: str) -> int:
    """
    SM2签名验证
    param : data, pub, sign
        data: 待签名数据
        pub: SM2公钥
        sign: SM2签名
    return : ret
        ret: return code 0 成功，其他失败
    """

    hsm_instance = hsm.hsm(lib_dir)

    ret = hsm_instance.SDF_OpenDevice()
    if ret != 0:
        print("SDF_OpenDevice failed, err code: ", hex(ret))
        return ret

    ret, session = hsm_instance.SDF_OpenSession()
    if ret != 0:
        print("SDF_OpenSession failed, err code: ", hex(ret))
        return ret
    
    ret = hsm_instance.SDF_ExternalVerify_ECC(session, SGD_SM2, pub, data, sign)
    if ret != 0:
        print("SDF_ExternalVerify_ECC failed, err code: ", hex(ret))
        return ret

    hsm_instance.SDF_CloseSession(session)
    hsm_instance.SDF_CloseDevice()
    return 0

@mcp.tool()
def symm_encrypt(key: str, algid: int, iv: str, plaintext: str) -> Tuple[int, str, str]:
    """
    对称加密运算
    param : key, algid, iv, plaintext
        key: 对称密钥
        algid: 对称算法标识
        iv: 初始化向量
        plaintext: 待加密数据
    return : ret, iv, enc_data
        return code 0 成功，其他失败
        iv: 初始化向量
        enc_data: 密文
    """


    hsm_instance = hsm.hsm(lib_dir)

    ret = hsm_instance.SDF_OpenDevice()
    if ret != 0:
        print("SDF_OpenDevice failed, err code: ", hex(ret))
        return ret, None, None

    ret, session = hsm_instance.SDF_OpenSession()
    if ret != 0:
        print("SDF_OpenSession failed, err code: ", hex(ret))
        return ret, None, None

    ret, hkey = hsm_instance.SDF_ImportKey(session, key)
    if ret != 0:
        print("SDF_ImportKey failed, err code: ", hex(ret))
        return ret, None, None
    
    ret, enc_data, enc_data_len = hsm_instance.SDF_Encrypt(session, hkey, algid, iv, plaintext)
    if ret != 0:
        print("SDF_Encrypt failed, err code: ", hex(ret))
        return ret, None, None
    
    hsm_instance.SDF_DestroyKey(session, hkey)
    hsm_instance.SDF_CloseSession(session)
    hsm_instance.SDF_CloseDevice()
    return ret, iv, enc_data.hex()

@mcp.tool()
def symm_decrypt(key: str, algid: int, iv: str, enc_data: str) -> Tuple[int, str, str]:
    """
    对称解密运算
    param : key, algid, iv, enc_data
        key: 对称密钥
        algid: 对称算法标识
        iv: 初始化向量
        data: 待解密数据
    return : ret, iv, enc_data
        return code 0 成功，其他失败
        iv: 初始化向量
        plaintext: 明文
    """
 
    hsm_instance = hsm.hsm(lib_dir)

    ret = hsm_instance.SDF_OpenDevice()
    if ret != 0:
        print("SDF_OpenDevice failed, err code: ", hex(ret))
        return ret, None, None

    ret, session = hsm_instance.SDF_OpenSession()
    if ret != 0:
        print("SDF_OpenSession failed, err code: ", hex(ret))
        return ret, None, None

    ret, hkey = hsm_instance.SDF_ImportKey(session, key)
    if ret != 0:
        print("SDF_ImportKey failed, err code: ", hex(ret))
        return ret, None, None
    
    ret, plaintext, plaintext_len = hsm_instance.SDF_Decrypt(session, hkey, algid, iv, enc_data)
    if ret != 0:
        print("SDF_Decrypt failed, err code: ", hex(ret))
        return ret, None, None
    
    hsm_instance.SDF_DestroyKey(session, hkey)
    hsm_instance.SDF_CloseSession(session)
    hsm_instance.SDF_CloseDevice()
    return ret, iv, plaintext.hex()

@mcp.tool()
def get_sm4_ecb_algid() -> int:
    """
    获取SM4 ECB算法标识
    return : algid
    """
    return SGD_SM4_ECB

if __name__ == "__main__":
    # Initialize and run the server
    mcp.run(transport='stdio')