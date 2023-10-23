cimport cwd
cimport cwd_digest
cimport cwd_bmm
from pyuadk.pywd cimport *
from libc.stdlib cimport malloc
from libc.string cimport memcpy
from enum import Enum


class DIGEST_ALG(Enum):
    SM3 = 0


class DIGEST_MODE(Enum):
    NORMAL = 0
    HMAC = 1


cdef void callback(void *message, void *tag):
    print("digest callback")

cdef struct wcrypto_digest_tag:
    void *ctx
    int thread_id
    int cnt

cdef class Digest(Wd):

    cdef cwd_digest.wcrypto_digest_ctx_setup *setup
    cdef cwd_digest.wcrypto_digest_op_data *opdata
    cdef wcrypto_digest_tag *tag
    cdef bint async_mode

    def __cinit__(
        self,
        dev_path: str = None,
        node_mask: int = None,
        async_mode: int = 0
    ):
        self.setup = <cwd_digest.wcrypto_digest_ctx_setup*> \
            malloc (sizeof(cwd_digest.wcrypto_digest_ctx_setup))
        self.opdata = <cwd_digest.wcrypto_digest_op_data*> \
            malloc (sizeof(cwd_digest.wcrypto_digest_op_data))
        self.tag = <wcrypto_digest_tag*> \
            malloc (sizeof(wcrypto_digest_tag))
        self.async_mode = async_mode
        self.capa.alg = "digest"
        cdef void *capa_ptr = &self.queue.capa
        memcpy(capa_ptr, self.capa, sizeof(cwd.wd_capa))

    cpdef void pool_setup(self, block_size=1024*8, block_num=128, align_size=128):

        ''' setup and create pool
        params:
            block_size: block size
            block_num: block number
            align_size: align size
        '''

        self.wsetup.block_size = block_size
        self.wsetup.block_num = block_num
        self.wsetup.align_size = align_size
        self.pool =\
            <cwd_bmm.wd_blkpool *>cwd_bmm.wd_blkpool_create(self.queue, self.wsetup)
        if self.pool == NULL:
            raise MemoryError("create pool failed")

    cpdef ctx_setup(self, alg: DIGEST_ALG, mode: DIGEST_MODE):

        '''set ctx setup
        params:
            alg: digest algorithm(SM3 only)
            mode: digest mode(NORMAL or HMAC)
        '''

        if alg == DIGEST_ALG.SM3:
            self.setup.alg = cwd_digest.WCRYPTO_SM3
        else:
            raise ValueError("digest algorithm not support")

        if mode == DIGEST_MODE.NORMAL:
            self.setup.mode = cwd_digest.WCRYPTO_DIGEST_NORMAL
        elif mode == DIGEST_MODE.HMAC:
            self.setup.mode = cwd_digest.WCRYPTO_DIGEST_HMAC
        else:
            raise ValueError("digest mode not support")

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

    cpdef void create_digest_ctx(self):
        '''create ctx
        '''
        self.ctx = cwd_digest.wcrypto_create_digest_ctx(self.queue, self.setup)
        if self.ctx == NULL:
            raise Exception("create ctx failed!")

    cpdef int wcrypto_set_digest_key(self, key: bytes, key_len: int):

        ''' digest key (only for HMAC mode)
        params:
            key: digest key, byte array of digest key length
            key_len: digest key length
        '''

        if self.setup.mode != cwd_digest.WCRYPTO_DIGEST_HMAC:
            raise ValueError("only set key for HMAC mode")
        cdef unsigned char *ckey = <unsigned char*> key
        for i in range(len(key)):
            ckey[i] = key[i]
        return cwd_digest.wcrypto_set_digest_key(self.ctx, ckey, key_len)

    cpdef void set_opdata(self, bytes text, int dsize):

        '''set digest data(to be hashed)
        params:
            text: digest data
            dsize: digest data length
        '''

        self.opdata.in_ = <unsigned char*>cwd_bmm.wd_alloc_blk(self.pool)
        if self.opdata.in_ == NULL:
            raise MemoryError("wd_alloc_blk failed")
        cdef unsigned char *c_text = <unsigned char*>text
        memcpy(self.opdata.in_, c_text, len(text))
        self.opdata.in_bytes = len(text)

        self.opdata.out_ = cwd_bmm.wd_alloc_blk(self.pool)
        if self.opdata.out_ == NULL:
            raise MemoryError("alloc output buffer failed")
        self.opdata.out_bytes = dsize
        self.opdata.priv = NULL

    cpdef void tag_setup(self, int cnt, int thread_id):

        """setup a fixed tag
        cnt: user set (0?)
        thread_id:  acquired from python
        """

        if self.async_mode == 1:
            self.tag = <wcrypto_digest_tag*>malloc(sizeof(wcrypto_digest_tag))
            self.tag.ctx = self.ctx
            self.tag.cnt = cnt
            self.tag.thread_id = thread_id
        else:
            print("sync mode no need to setup tag")

    cpdef int wcrypto_do_digest(self):
        '''do digest
        '''
        if self.async_mode == 1:
            if self.tag == NULL:
                raise ValueError("tag must not be None in async mode")
            return cwd_digest.wcrypto_do_digest(self.ctx, self.opdata, self.tag)
        else:
            return cwd_digest.wcrypto_do_digest(self.ctx, self.opdata, NULL)

    cpdef int wcrypto_digest_poll(self, num: int):
        '''digest poll
        '''
        if (num < 1):
            raise ValueError("num must be greater than 0")
        if self.async_mode == 0:
            raise ValueError("sync mode not support poll")
        return cwd_digest.wcrypto_digest_poll(self.queue, num)

    cpdef void wcrypto_del_digest_ctx(self):
        cwd_digest.wcrypto_del_digest_ctx(self.ctx)

    # cdef int wcrypto_burst_digest(self, num):
    #     cdef cwd_digest.wcrypto_digest_op_data **opdata_ptr = &self.opdata
    #     return cwd_digest.wcrypto_burst_digest(self.ctx, opdata_ptr, NULL, num)

    cdef int sync_do_digest(self):
        cdef int data_len = self.opdata.in_bytes
        while (1):
            if data_len > 256:
                self.opdata.in_bytes = 256
                data_len -= 256
            else:
                self.opdata.in_bytes = data_len
                break
            self.opdata.has_next = (data_len >= 256)
            ret = cwd_digest.wcrypto_do_digest(self.ctx, self.opdata, NULL)
            if ret < 0:
                raise Exception("digest failed")
        return 0

    cpdef bytes get_digest(self):
        cdef unsigned char *digest =\
            <unsigned char*>malloc(self.opdata.out_bytes*sizeof(unsigned char))
        memcpy(digest, self.opdata.out_, self.opdata.out_bytes)
        return bytes(digest)

    def __dealloc__(self):

        """free all resources
        """

        if self.opdata.in_ is not NULL and self.pool is not NULL:
            cwd_bmm.wd_free_blk(self.pool, self.opdata.in_)

        if self.opdata.out_ is not NULL and self.pool is not NULL:
            cwd_bmm.wd_free_blk(self.pool, self.opdata.out_)

        cwd_digest.wcrypto_del_digest_ctx(self.ctx)

        if self.queue is not NULL and self.queue.qinfo is not NULL:
            cwd.wd_release_queue(self.queue)

        cwd_bmm.wd_blkpool_destroy(self.pool)
