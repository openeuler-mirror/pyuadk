import unittest
import ctypes
from pyuadk import pywd_cipher, pywd_digest, pywd_rsa
from Crypto.Cipher import AES
import threading
from cryptography.hazmat.primitives.asymmetric import rsa


class test_sec_pthread_dt(ctypes.Structure):
    _fields_ = [
        ("cpu_id", ctypes.c_int),
        ("thread_num", ctypes.c_int),
        ("pool", ctypes.POINTER(ctypes.c_void_p)),
        ("q", ctypes.POINTER(ctypes.c_void_p)),
        ("send_task_num", ctypes.c_uint32),
        ("recv_task_num", ctypes.c_uint32),
    ]


class Cipher_Async_Tag(ctypes.Structure):
    _fields_ = [
        ("ctx", ctypes.POINTER(ctypes.c_void_p)),
        ("thread_id", ctypes.c_int),
        ("cnt", ctypes.c_int),
        ("thread_info", ctypes.POINTER(test_sec_pthread_dt)),
    ]


def cipher_cb(message, cipher_tag):
    tag = ctypes.cast(cipher_tag, ctypes.POINTER(Cipher_Async_Tag)).contents
    thread_info = ctypes.cast(
        tag.thread_info, ctypes.POINTER(test_sec_pthread_dt)
    ).contents
    thread_info.recv_task_num.contents.value += 1
    print("a")


cipher_cb_ptr = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p)


@staticmethod
def test_cb(a):
    print("test cb ", a)


class TestPyWdCipherAsync(unittest.TestCase):
    def __init__(self, methodName: str = "runTest") -> None:
        super().__init__(methodName)
        self.cipher = pywd_cipher.Cipher(async_mode=1)
        self.cipher.request_queue()
        self.cipher.pool_setup(1024 * 8, 128, 128)
        self.key = bytes([0x01] * 16)
        self.iv = bytes([0x02] * 16)
        self.pt = bytes([0x03] * 16)

    def test_aes_ecb_async(self):
        alg = pywd_cipher.CIPHER_ALG.AES
        mode = pywd_cipher.CIPHER_MODE.ECB

        self.cipher.ctx_setup(alg, mode)
        self.cipher.create_cipher_ctx()

        self.cipher.wcrypto_set_cipher_key(self.key, len(self.key))
        self.cipher.set_opdata(bytes([]), pywd_cipher.CIPHER_OP_TYPE.ENCRYPT, self.pt)
        ret = -22
        count = 0
        self.cipher.tag_setup(0, 27694)
        while ret != 0 and count < 2:
            ret = self.cipher.wcrypto_do_cipher()
            count += 1

        self.cipher.wcrypto_cipher_poll(2)
        self.assertEqual(ret, 0)
        # print(count)

        cth = self.cipher.get_ct()
        aes_ecb = AES.new(self.key, AES.MODE_ECB)
        cts = aes_ecb.encrypt(self.pt)
        self.assertEqual(cth[0], cts[0])
        
        print("\naes ecb async test pass")

class TestPyWdDigestAysnc(unittest.TestCase):
    def __init__(self, methodName: str = "runTest") -> None:
        super().__init__(methodName)
        self.digest = pywd_digest.Digest(async_mode=1)
        self.digest.request_queue()
        self.digest.pool_setup(1024 * 8, 128, 128)
        self.data = bytes([0x01] * 16)

    def test_digest_sm3_async(self):
        alg = pywd_digest.DIGEST_ALG.SM3
        mode = pywd_digest.DIGEST_MODE.NORMAL
        self.digest.ctx_setup(alg, mode)
        self.digest.create_digest_ctx()
        self.digest.set_opdata(self.data, 16)
        ret = -22
        count = 0
        self.digest.tag_setup(2, 27694)
        while ret != 0 and count < 2:
            ret = self.digest.wcrypto_do_digest()
            count += 1

        self.digest.wcrypto_digest_poll(2)
        self.assertEqual(ret, 0)
        # print(count)

        digest = self.digest.get_digest()
        # print(digest)
        print("\nsm3 normal async test pass")

class TestPyWdRSAAsync(unittest.TestCase):
    def __init__(self, methodName: str = "runTest") -> None:
        super().__init__(methodName)
        self.rsa = pywd_rsa.RSA(async_mode=1)
        self.rsa.request_queue()
        self.rsa.pool_setup(64, 2048)
       
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


    def test_rsa_genkey_common_async(self):

        self.rsa.ctx_setup(0)
        self.rsa.create_rsa_ctx()

        self.rsa.wcrypto_new_kg_in(self.e, self.p, self.q)
        self.rsa.wcrypto_new_kg_out()

        self.rsa.set_opdata(pywd_rsa.RSA_OP_TYPE.GENKEY)
        ret = -22
        count = 0
        self.rsa.tag_setup(2, 27694)
        while ret != 0 and count < 2:
            ret = self.rsa.wcrypto_do_rsa()
            count += 1
        print(count)
        self.assertEqual(ret, 0)
        # self.rsa.wcrypto_rsa_poll(2)
        d, n  = self.rsa.get_kg_out()
        self.assertEqual(int.from_bytes(d, byteorder="big"), self.private_key.private_numbers().d)
        self.assertEqual(int.from_bytes(n, byteorder="big"), self.private_key.public_key().public_numbers().n)
        print("\nrsa common genkey async test pass")


if __name__ == "__main__":
    unittest.main()
