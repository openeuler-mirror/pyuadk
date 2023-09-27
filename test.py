from pyuadk import  pywd_cipher, pywd_digest, pywd_rsa
# from pyuadk.pywd_rsa import RSA_OP_TYPE
import unittest
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import time
import struct, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
from gmssl.sm3 import sm3_hash
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from cryptography.hazmat.primitives.asymmetric import rsa

class TestPyWdCipherSync(unittest.TestCase):

    def __init__(self, methodName='runTest'):
        super().__init__(methodName)
        self.cipher = pywd_cipher.Cipher()
        self.cipher.request_queue()
        self.cipher.pool_setup(1024*8, 128, 128)
        self.key = bytes([0x01]*16)
        self.iv = bytes([0x02]*16)
        self.pt = bytes([0x03]*16)
        
  
    def test_cipher_aes_cbc_sync(self):
        # cipher = pywd_cipher.Cipher()
        # cipher.request_queue()

        
        alg = pywd_cipher.CIPHER_ALG.AES
        mode = pywd_cipher.CIPHER_MODE.CBC
        self.cipher.ctx_setup(alg, mode)
        self.cipher.create_cipher_ctx()

        self.cipher.wcrypto_set_cipher_key(self.key, len(self.key))

        self.cipher.set_opdata(self.iv, pywd_cipher.CIPHER_OP_TYPE.ENCRYPT, self.pt)

        ret = self.cipher.wcrypto_do_cipher()
        cth = self.cipher.get_ct()
        self.assertEqual(ret, 0)

        aes_ecb = AES.new(self.key, AES.MODE_CBC, self.iv)
        cts = aes_ecb.encrypt(self.pt)

        self.assertEqual(cth[0], cts[0])

        self.cipher.set_opdata(self.iv, pywd_cipher.CIPHER_OP_TYPE.DECRYPT, cth)
        ret = self.cipher.wcrypto_do_cipher()
        pth = self.cipher.get_ct()
        self.assertEqual(ret, 0)

        self.assertEqual(pth[0], self.pt[0])

        print("\naes cbc test pass")

    def test_cipher_aes_ecb(self):
        
        alg = pywd_cipher.CIPHER_ALG.AES
        mode = pywd_cipher.CIPHER_MODE.ECB
        self.cipher.ctx_setup(alg, mode)
        self.cipher.create_cipher_ctx()


        self.cipher.wcrypto_set_cipher_key(self.key, len(self.key))
        self.cipher.set_opdata(bytes([]), pywd_cipher.CIPHER_OP_TYPE.ENCRYPT, self.pt)


        ret = self.cipher.wcrypto_do_cipher()
        cth = self.cipher.get_ct()
        self.assertEqual(ret, 0)

        aes_ecb = AES.new(self.key, AES.MODE_ECB)
        cts = aes_ecb.encrypt(self.pt)

        self.assertEqual(cth[:-1], cts)
        # print("cth = ", ct[:16])
        self.cipher.set_opdata(bytes([]), pywd_cipher.CIPHER_OP_TYPE.DECRYPT, cth[:-1])
        ret = self.cipher.wcrypto_do_cipher()
        pth = self.cipher.get_ct()
        self.assertEqual(ret, 0)
        self.assertEqual(pth[0], self.pt[0])
        

        print("\naes ecb test pass")


    def test_cipher_sm4_ecb(self):
            
        alg = pywd_cipher.CIPHER_ALG.SM4
        mode = pywd_cipher.CIPHER_MODE.ECB
        self.cipher.ctx_setup(alg, mode)
        self.cipher.create_cipher_ctx()


        self.cipher.wcrypto_set_cipher_key(self.key, len(self.key))
        self.cipher.set_opdata(bytes([]), pywd_cipher.CIPHER_OP_TYPE.ENCRYPT, self.pt)
        

        ret = self.cipher.wcrypto_do_cipher()
        cth = self.cipher.get_ct()
        self.assertEqual(ret, 0)

        
        sm4 = CryptSM4()
        sm4.set_key(self.key, SM4_ENCRYPT)
        cts = sm4.crypt_ecb(self.pt)


        self.assertEqual(cth[:16], cts[:16])

        self.cipher.set_opdata(bytes([]), pywd_cipher.CIPHER_OP_TYPE.DECRYPT, cth[:-1])
        ret = self.cipher.wcrypto_do_cipher()
        pth = self.cipher.get_ct()
        self.assertEqual(ret, 0)
        self.assertEqual(pth[0], self.pt[0])

        print("\nsm4 ecb test pass")
    
    def test_cipher_sm4_cbc(self):
            
        alg = pywd_cipher.CIPHER_ALG.SM4
        mode = pywd_cipher.CIPHER_MODE.CBC
        self.cipher.ctx_setup(alg, mode)
        self.cipher.create_cipher_ctx()


        self.cipher.wcrypto_set_cipher_key(self.key, len(self.key))
        self.cipher.set_opdata(self.iv, pywd_cipher.CIPHER_OP_TYPE.ENCRYPT, self.pt)


        ret = self.cipher.wcrypto_do_cipher()
        cth = self.cipher.get_ct()
        self.assertEqual(ret, 0)

        sm4 = CryptSM4()
        sm4.set_key(self.key, SM4_ENCRYPT)
        cts = sm4.crypt_cbc(self.iv, self.pt)

        self.assertEqual(cth[0], cts[0])

        self.cipher.set_opdata(self.iv, pywd_cipher.CIPHER_OP_TYPE.DECRYPT, cth)
        ret = self.cipher.wcrypto_do_cipher()
        pth = self.cipher.get_ct()
        self.assertEqual(ret, 0)
        self.assertEqual(pth[0], self.pt[0])

        print("\nsm4 cbc test pass")



class TestPyWdDigest(unittest.TestCase):

    def __init__(self, methodName: str = "runTest") -> None:
        super().__init__(methodName)
        self.digest = pywd_digest.Digest()
        self.digest.request_queue()
        self.digest.pool_setup(1024*8, 128, 128)

        self.pt = bytes([0x01]*10)
        self.iv = bytes([0x02]*16)
        self.key = bytes([0x03]*16)

        self.alg = pywd_digest.DIGEST_ALG.SM3



    def test_digest_sm3_normal(self):
        
        mode  = pywd_digest.DIGEST_MODE.NORMAL
        self.digest.ctx_setup(self.alg, mode)
        self.digest.create_digest_ctx()
        self.digest.set_opdata(self.pt, 16)
        ret = self.digest.wcrypto_do_digest()
        self.assertEqual(ret, 0)


        digest_h = self.digest.get_digest()
        digest_s = sm3_hash(list(self.pt))

        # print(digest_h)

        # self.assertEqual(digest_h[0], int(digest_s[:2], base=16))

        print("\nsm3 normal test pass")

    def test_digest_sm3_hmac(self):
        
        mode  = pywd_digest.DIGEST_MODE.HMAC
        self.digest.ctx_setup(self.alg, mode)
        self.digest.create_digest_ctx()
        self.digest.wcrypto_set_digest_key(self.key, len(self.key))
        self.digest.set_opdata(self.pt, 16)
        ret = self.digest.wcrypto_do_digest()
        self.assertEqual(ret, 0)
        
        digest = self.digest.get_digest()
        # print(digest)

        print("\nsm3 hmac test pass")

class TestPyWdRSA(unittest.TestCase):

    def __init__(self, methodName: str = "runTest") -> None:
        super().__init__(methodName)
        self.rsa = pywd_rsa.RSA()
        self.rsa.request_queue()
        self.rsa.pool_setup(64, 2048)

        self.msg = b'Hello World!'
        self.sig = None

        # use cryptography lib
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = self.private_key.public_key()
        self.e = bytes.fromhex(f"{public_key.public_numbers().e:#0{514}x}"[2:])
        self.n = bytes.fromhex(f"{public_key.public_numbers().n:#0{514}x}"[2:])
        self.d = bytes.fromhex(f"{self.private_key.private_numbers().d:#0{514}x}"[2:])
        self.p = bytes.fromhex(f"{self.private_key.private_numbers().p:#0{258}x}"[2:])
        self.q = bytes.fromhex(f"{self.private_key.private_numbers().q:#0{258}x}"[2:])
        self.dp = bytes.fromhex(f"{self.private_key.private_numbers().dmp1:#0{258}x}"[2:])
        self.dq = bytes.fromhex(f"{self.private_key.private_numbers().dmq1:#0{258}x}"[2:])
        self.qinv = bytes.fromhex(f"{self.private_key.private_numbers().iqmp:#0{258}x}"[2:])


    def test_rsa_genkey_common(self):

        self.rsa.ctx_setup(0)
        self.rsa.create_rsa_ctx()

        self.rsa.wcrypto_new_kg_in(self.e, self.p, self.q)
        self.rsa.wcrypto_new_kg_out()

        self.rsa.set_opdata(pywd_rsa.RSA_OP_TYPE.GENKEY)
        ret = self.rsa.wcrypto_do_rsa()
        self.assertEqual(ret, 0)

        d, n  = self.rsa.get_kg_out()
        # print(d.hex(), n.hex())
        self.assertEqual(int.from_bytes(d, byteorder="big"), self.private_key.private_numbers().d)
        self.assertEqual(int.from_bytes(n, byteorder="big"), self.private_key.public_key().public_numbers().n)
        print("\nrsa common genkey test pass")


    def test_rsa_genkey_crt(self):
        
        self.rsa.ctx_setup(1)
        self.rsa.create_rsa_ctx()

        self.rsa.wcrypto_new_kg_in(self.e, self.p, self.q)
        self.rsa.wcrypto_new_kg_out()
        
        self.rsa.set_opdata(pywd_rsa.RSA_OP_TYPE.GENKEY)
        
        ret = self.rsa.wcrypto_do_rsa()
        
        self.assertEqual(ret, 0)
        dq, dp, qinv = self.rsa.get_kg_out_crt()
        
        self.assertEqual(int.from_bytes(dp, byteorder="big"), self.private_key.private_numbers().dmp1)
        self.assertEqual(int.from_bytes(dq, byteorder="big"), self.private_key.private_numbers().dmq1)
        self.assertEqual(int.from_bytes(qinv, byteorder="big"), self.private_key.private_numbers().iqmp)
        
        print("\nrsa ctr genkey test pass")

    def test_rsa_sign_common(self):
        
        self.rsa.ctx_setup(0)
        self.rsa.create_rsa_ctx()

        self.rsa.wcrypto_set_rsa_prikey_params(self.d, self.n)
        
        self.rsa.set_opdata(pywd_rsa.RSA_OP_TYPE.SIGN, self.d)
        ret = self.rsa.wcrypto_do_rsa()
        self.assertEqual(ret, 0)

        self.sig = self.rsa.get_opdata_out()

        print("\nrsa sign common test pass")

    
    def test_rsa_sign_crt(self):

        self.rsa.ctx_setup(1)
        self.rsa.create_rsa_ctx()

        self.rsa.wcrypto_set_rsa_crt_prikey_params(self.dq, self.dp, self.qinv, self.q, self.p)
        
        self.rsa.set_opdata(pywd_rsa.RSA_OP_TYPE.SIGN, self.d)
        ret = self.rsa.wcrypto_do_rsa()
        self.assertEqual(ret, 0)

        self.sig = self.rsa.get_opdata_out()

        print("\nrsa sign crt test pass")

    def test_rsa_verify_common_and_crt(self):
        self.rsa.ctx_setup(0)
        self.rsa.create_rsa_ctx()

        self.rsa.wcrypto_set_rsa_pubkey_params(self.e, self.n)
        sig = self.private_key.sign(
                self.msg,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()), 
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                 hashes.SHA256()
            )
        
        self.rsa.set_opdata(pywd_rsa.RSA_OP_TYPE.VERIFY, data=sig)
        ret = self.rsa.wcrypto_do_rsa()
        self.assertEqual(ret, 0)

        ver = self.rsa.get_opdata_out()
        print("\nrsa verify common and crt test pass")


        
if __name__ == '__main__':
    unittest.main()
    