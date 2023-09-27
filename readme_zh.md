# pyuadk
本项目是对密码加速库 [UADK](https://gitee.com/openeuler/uadk) 的 python 封装，使用 Cython 实现，目前支持：
1. AES 和 SM4 的加解密及常见工作模式
2. SM3 的哈希操作和 HMAC 操作
3. RSA 常规模式和 CRT 模式下的密钥生成、签名和验签

## 编译
```shell
git clone --recurse-submodules https://gitee.com/openeuler/pyuadk.git 
pip3 install -r requirements.txt
python3 pyuadk/setup.py build_ext --inplace
```

## 使用
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
