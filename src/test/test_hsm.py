import base64
from pyasn1.codec.der import decoder
from asn1crypto.core import Sequence, Integer
from pyasn1_modules import rfc5208, rfc5915  # 新增RFC 5915
from gmssl import sm3, func, sm2
from hsm import hsm_utils

def test_sm4():
    plaintext = "Hello, World!"
    ciphertext = hsm_utils.sm4_encrypt(plaintext, "1234567812345678")
    decrypted_text = hsm_utils.sm4_decrypt(ciphertext, "1234567812345678")
    assert decrypted_text == plaintext, f"Decrypted text does not match original: {decrypted_text}"
    print("SM4 encryption and decryption test passed.")
    return


if __name__ == '__main__':
    test_sm4()