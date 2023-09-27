cimport cwd_cipher
cimport cwd
cimport cwd_bmm
from pyuadk.pywd cimport *
from libc.stdlib cimport malloc
from libc.string cimport memcpy
from enum import Enum


class CIPHER_ALG(Enum):
    AES = 0
    SM4 = 1


class CIPHER_MODE(Enum):
    ECB = 0
    CBC = 1
    CTR = 2
    XTS = 3
    OFB = 4
    CFB = 5
    CCM = 6
    GCM = 7


class CIPHER_OP_TYPE(Enum):
    ENCRYPT = 0
    DECRYPT = 1


cdef void callback(void *message, void *tag):
    print("cipher callback")

cdef struct wcrypto_cipher_tag:
    void *ctx
    int thread_id
    int cnt


cdef class Cipher(Wd):

    cdef cwd_cipher.wcrypto_cipher_ctx_setup *setup
    cdef cwd_cipher.wcrypto_cipher_op_data *opdata
    cdef wcrypto_cipher_tag *tag
    cdef bint async_mode

    def __cinit__(
            self,
            dev_path: str = None,
            node_mask: int = None,
            async_mode: int = 0
    ):
        self.setup = <cwd_cipher.wcrypto_cipher_ctx_setup*>\
            malloc(sizeof(cwd_cipher.wcrypto_cipher_ctx_setup))
        self.opdata = <cwd_cipher.wcrypto_cipher_op_data*>\
            malloc(sizeof(cwd_cipher.wcrypto_cipher_op_data))
        self.tag = NULL
        self.capa.alg = "cipher"
        cdef void *capa_ptr = &self.queue.capa
        memcpy(capa_ptr, self.capa, sizeof(cwd.wd_capa))
        self.async_mode = async_mode

    cpdef void pool_setup(self, block_size=1024*8, block_num=128, align_size=128):

        '''setup pool
        create pool memory: block_nm * block_size
        params:
            block_size: block size
            block_num: block number
            align_size: align size
        '''

        self.wsetup.block_size = block_size
        self.wsetup.block_num = block_num
        self.wsetup.align_size = align_size
        self.pool = \
            <cwd_bmm.wd_blkpool*>cwd_bmm.wd_blkpool_create(self.queue, self.wsetup)
        if self.pool == NULL:
            raise MemoryError("wd_blkpool_create failed")

    cpdef void ctx_setup(self, alg: CIPHER_ALG, mode: CIPHER_MODE):

        '''setup ctx (alg, mode, br)
        a callback func is needed in async mode
        params:
            alg: aes or sm4
            mode: ecb or cbc or ctr or xts or ofb or cfb or ccm or gcm
        '''

        if alg == CIPHER_ALG.AES:
            self.setup.alg = cwd_cipher.WCRYPTO_CIPHER_AES
        elif alg == CIPHER_ALG.SM4:
            self.setup.alg = cwd_cipher.WCRYPTO_CIPHER_SM4
        else:
            raise ValueError("alg must be CIPHER_ALG.AES or CIPHER_ALG.SM4")

        if mode == CIPHER_MODE.ECB:
            self.setup.mode = cwd_cipher.WCRYPTO_CIPHER_ECB
        elif mode == CIPHER_MODE.CBC:
            self.setup.mode = cwd_cipher.WCRYPTO_CIPHER_CBC
        elif mode == CIPHER_MODE.CTR:
            self.setup.mode = cwd_cipher.WCRYPTO_CIPHER_CTR
        elif mode == CIPHER_MODE.XTS:
            self.setup.mode = cwd_cipher.WCRYPTO_CIPHER_XTS
        elif mode == CIPHER_MODE.OFB:
            self.setup.mode = cwd_cipher.WCRYPTO_CIPHER_OFB
        elif mode == CIPHER_MODE.CFB:
            self.setup.mode = cwd_cipher.WCRYPTO_CIPHER_CFB
        elif mode == CIPHER_MODE.CCM:
            self.setup.mode = cwd_cipher.WCRYPTO_CIPHER_CCM
        elif mode == CIPHER_MODE.GCM:
            self.setup.mode = cwd_cipher.WCRYPTO_CIPHER_GCM
        else:
            raise ValueError("unexcepted mode")

        if self.async_mode == 1:
            self.setup.cb = <cwd.wcrypto_cb>callback
        else:
            self.setup.cb = NULL
        self.setup.br.alloc = <cwd.wd_alloc>cwd_bmm.wd_alloc_blk
        self.setup.br.free = <cwd.wd_free>cwd_bmm.wd_free_blk
        self.setup.br.iova_map = <cwd.wd_map>cwd_bmm.wd_blk_iova_map
        self.setup.br.iova_unmap = <cwd.wd_unmap>cwd_bmm.wd_blk_iova_unmap
        self.setup.br.get_bufsize = <cwd.wd_bufsize>cwd_bmm.wd_blksize
        self.setup.br.usr = self.pool

    cpdef int create_cipher_ctx(self):

        '''create ctx
        create cipher ctx after ctx setup
        return -1 means create failed
        '''

        self.ctx = cwd_cipher.wcrypto_create_cipher_ctx(self.queue, self.setup)
        if self.ctx == NULL:
            raise Exception("create ctx failed!")
            return -1
        return 0

    cpdef int wcrypto_set_cipher_key(self, key: bytes, key_len: int):

        '''set cipher key
        params:
            key: bytes with length of key_len
            key_len: cipher key length
        '''

        cdef unsigned char *ckey = <unsigned char*> \
            malloc (key_len*sizeof(unsigned char))
        for i in range(key_len):
            ckey[i] = <unsigned char>key[i]
        return cwd_cipher.wcrypto_set_cipher_key(self.ctx, ckey, key_len)

    cpdef void set_opdata(self, bytes iv, op_type: CIPHER_OP_TYPE, bytes text):

        ''' set opdata(iv, enc/dec. pt/ct)
        params:
            iv: iv, bytes with length of block_len
            op_type: encrypt or decrypt
            text: bytes with length of block_len
        '''

        # iv
        self.opdata.iv = <unsigned char*>cwd_bmm.wd_alloc_blk(self.pool)
        if self.opdata.iv == NULL:
            raise MemoryError("wd blk fail failed")
        cdef unsigned char *c_iv = <unsigned char*>iv
        memcpy(self.opdata.iv, c_iv, len(iv))
        self.opdata.iv_bytes = len(iv)

        # op_type
        if op_type == CIPHER_OP_TYPE.ENCRYPT:
            self.opdata.op_type = cwd_cipher.WCRYPTO_CIPHER_ENCRYPTION
            self.queue.capa.priv.direction = 0
        elif op_type == CIPHER_OP_TYPE.DECRYPT:
            self.opdata.op_type = cwd_cipher.WCRYPTO_CIPHER_DECRYPTION
            self.queue.capa.priv.direction = 1
        else:
            raise ValueError("op_type must be  \
            CIPHER_OP_TYPE.ENCRYPT or CIPHER_OP_TYPE.DECRYPT")
        self.opdata.priv = NULL

        # text
        self.opdata.in_ = \
            <unsigned char*>cwd_bmm.wd_alloc_blk(self.pool)
        if self.opdata.in_ == NULL:
            raise MemoryError("wd_alloc_blk failed")
        cdef unsigned char *c_text = <unsigned char*>text
        memcpy(self.opdata.in_, c_text, len(text))
        self.opdata.in_bytes = len(text)

        # out
        self.opdata.out_ = cwd_bmm.wd_alloc_blk(self.pool)
        if self.opdata.out_ == NULL:
            raise MemoryError("wd_alloc_blk failed")
        self.opdata.out_bytes = self.opdata.in_bytes

    cpdef void tag_setup(self, int cnt, int thread_id):

        """setup a fixed tag
        cnt: user set (0?)
        thread_id:  acquired from python
        """

        if self.async_mode == 1:
            self.tag = <wcrypto_cipher_tag*>malloc(sizeof(wcrypto_cipher_tag))
            self.tag.ctx = self.ctx
            self.tag.cnt = cnt
            self.tag.thread_id = thread_id
        else:
            print("sync mode no need to setup tag")

    cpdef int wcrypto_do_cipher(self):

        """do cipher
        do cipher in async mode(Non-Null tag is needed) or sync mode
        """

        if self.async_mode == 1:
            if self.tag == NULL:
                raise ValueError("tag must not be None in async mode")
            return cwd_cipher.wcrypto_do_cipher(self.ctx, self.opdata, self.tag)
        else:
            return cwd_cipher.wcrypto_do_cipher(self.ctx, self.opdata, NULL)

    cpdef int wcrypto_cipher_poll(self, num: int):

        """poll self.queue
        num: poll num (>1)
        """
        if num < 1:
            return -1

        return cwd_cipher.wcrypto_cipher_poll(self.queue, num)

    cpdef bytes get_ct(self):

        """get ciphertext in bytes format
        """

        cdef unsigned char *c_ct =\
            <unsigned char*>malloc(self.opdata.out_bytes*sizeof(unsigned char))
        memcpy(c_ct, self.opdata.out_, self.opdata.out_bytes)
        return bytes(c_ct)

    def __dealloc__(self):

        """free all resources
        """

        if self.opdata.in_ is not NULL and self.pool is not NULL:
            cwd_bmm.wd_free_blk(self.pool, self.opdata.in_)

        if self.opdata.out_ is not NULL and self.pool is not NULL:
            cwd_bmm.wd_free_blk(self.pool, self.opdata.out_)

        if self.opdata.iv is not NULL and self.pool is not NULL:
            cwd_bmm.wd_free_blk(self.pool, self.opdata.iv)

        cwd_cipher.wcrypto_del_cipher_ctx(self.ctx)

        if self.queue is not NULL and self.queue.qinfo is not NULL:
            cwd.wd_release_queue(self.queue)

        # cwd_bmm.wd_blkpool_destroy(self.pool)
