# pyuadk
This project is a Python wrapper for the cryptographic acceleration library [UADK](https://gitee.com/openeuler/uadk), implemented using Cython. It currently supports:

1. Encryption and decryption, as well as common modes of operation, for AES and SM4.
2. Hashing operations and HMAC operations for SM3.
3. Key generation, signing, and verification for RSA in both regular and CRT modes.

## Compilation
```shell
git clone --recurse-submodules https://gitee.com/openeuler/pyuadk.git
pip3 install -r requirements.txt
python3 pyuadk/setup.py build_ext --inplace
```
## Usage
```python
from pyuadk import pywd_cipher

cipher = pywd_cipher.Cipher()
cipher.request_queue()
cipher.pool_setup(1024*8, 128, 128)

key = bytes([0x01]*16)
iv = bytes([0x02]*16)
pt = bytes([0x03]*16)

alg = pywd_cipher.CIPHER_ALG.AES
mode = pywd_cipher.CIPHER_MODE.CBC
cipher.ctx_setup(alg, mode)
cipher.create_cipher_ctx()

cipher.wcrypto_set_cipher_key(self.key, len(self.key))
cipher.set_opdata(self.iv, pywd_cipher.CIPHER_OP_TYPE.ENCRYPT, self.pt)

ret = self.cipher.wcrypto_do_cipher()
if ret == 0:
    ct = self.cipher.get_ct()
```
