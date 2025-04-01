import base64
from pyasn1.codec.der import decoder
from asn1crypto.core import Sequence, Integer
from pyasn1_modules import rfc5208, rfc5915  # 新增RFC 5915
from gmssl import sm3, func, sm2
from hsm import hsm_utils

def load_pub_key_hex(file_path):
        # 读取PEM文件
        with open(file_path, 'r') as f:
            pem_data = f.read()

        # 提取公钥部分
        public_key_pem = []
        in_public_key = False
        for line in pem_data.split('\n'):
            if line == '-----BEGIN PUBLIC KEY-----':
                in_public_key = True
            elif line == '-----END PUBLIC KEY-----':
                in_public_key = False
            elif in_public_key:
                public_key_pem.append(line)

        # 解码DER数据
        public_key_der = base64.b64decode(''.join(public_key_pem))

        # 直接定位BIT STRING内容（跳过ASN.1解析）
        # 通过OpenSSL验证已知公钥结构：
        # 总长度=89字节，其中：
        # - 前23字节为算法标识
        # - 后66字节为BIT STRING（含1字节填充位+65字节公钥数据）
        bit_str_start = 23  # 根据ASN.1解析结果定位
        public_key_bitstr = public_key_der[bit_str_start:]

        # 提取公钥裸数据（格式：04 + X + Y）
        # 结构：[填充位(0x00)][04][32字节X][32字节Y]
        public_key_data = public_key_bitstr[3:]  # 跳过填充位
        if public_key_data[0] != 0x04:
            raise ValueError(f"非未压缩公钥格式, : {public_key_data[0]}")

        # 提取64字节核心数据
        raw_public_key = public_key_data[1:65]  # 跳过04后取64字节 
        return raw_public_key.hex()

class SM2Verifier:
    def __init__(self, private_key=None, public_key=None):
        """
        初始化 SM2Verifier 类，支持传入私钥和公钥。
        
        :param private_key: SM2 私钥，十六进制字符串格式
        :param public_key: SM2 公钥，十六进制字符串格式
        """
        # 检查私钥和公钥文件是否存在，如果存在则加载私钥和公钥文件的内容
        if public_key is not None or private_key is not None:
            self.sm2_crypt = sm2.CryptSM2(public_key=public_key, private_key=private_key)
        else:
            print("WARNING: SM2 public key is not provided.")
            self.sm2_crypt = None
    
    @staticmethod
    def parse_der_signature(der_bytes):
        """
        解析 DER 编码的签名，返回 r 和 s 的裸拼接值。
        
        :param der_bytes: DER 编码的签名
        :return: r 和 s 的裸拼接值
        """
        seq = Sequence.load(der_bytes)
        if len(seq) != 2:
            raise ValueError("无效的DER签名格式")
        r = seq[0].native.to_bytes(32, 'big').hex()  # 转换为Hex
        s = seq[1].native.to_bytes(32, 'big').hex()
        return r + s
    def verify_signature(self, sign_value, content):
            """
            验证签名。        
            :param signature: 签名值
            :param content: 原始内容
            :return: 验签结果，True 或 False
            """
            plain_sm3 = self.sm2_crypt._sm3_z(content.encode('utf-8'))  # SM3带ID预处理过程
            plain_e = bytes.fromhex(plain_sm3)

            # 将签名值从 Base64 解码为字节
            sign_value = base64.b64decode(sign_value).hex()
            try:
                sign_der = bytes.fromhex(sign_value)  # 十六进制 → 字节
                sign_hex_str = self.parse_der_signature(sign_der)  # DER → 裸签名
            except Exception as e:
                print(f"解码错误: {e}")
                return False

            # 使用 SM2 进行验签
            is_valid = self.sm2_crypt.verify(sign_hex_str, plain_e)
            return is_valid

if __name__ == '__main__':
    # 
    public_key = load_pub_key_hex("./src/test/SM2_1_.public.x509")
    verifier = SM2Verifier(private_key=None, public_key=public_key)
    # is_valid = verifier.verify_signature("MEQCIFKz+dlDuOMUwQfgCnznBuNi9scn/cHvYl3ka2uqYObaAiAEjISY32PniQgduKdGdQ7L7sXIV19NKOeOE7PJCoxb1g==","Hello, World!")
    # print(f"签名验证结果: {is_valid}")
    
    data_to_sign = "Hello, World!"
    signature_result = hsm_utils.sm2_sign(data_to_sign, 1)  # 使用1号密钥索引
    
    print(f"Base64签名结果: {signature_result}")
    #print(f"Base64签名结果: {signature_result['signature']}")
    #print(f"HEX格式签名: {signature_result['hex']}")
    is_valid = verifier.verify_signature(signature_result['signature'], data_to_sign)
    print(f"签名验证结果: {is_valid }")