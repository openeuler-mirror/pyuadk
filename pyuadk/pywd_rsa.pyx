cimport cwd_rsa
cimport  cwd
cimport cwd_bmm
from pyuadk.pywd cimport *
from libc.string cimport memset, memcpy
from libc.stdlib cimport malloc, free
from enum import Enum


class RSA_OP_TYPE(Enum):
    RSA_INVALID = 0
    SIGN = 1
    VERIFY = 2
    GENKEY = 3


cdef void callback(void *message, void *tag):
    print("rsa callback")

cdef struct wcrypto_rsa_tag:
    void *ctx
    int thread_id
    int cnt

cdef class RSA(Wd):

    cdef cwd_rsa.wcrypto_rsa_ctx_setup *setup 
    cdef cwd_rsa.wcrypto_rsa_op_data *opdata
    cdef wcrypto_rsa_tag *tag
    cdef bint async_mode

    cdef cwd_rsa.wcrypto_rsa_kg_in *kg_in
    cdef cwd_rsa.wcrypto_rsa_kg_out *kg_out

    cdef cwd_rsa.wcrypto_rsa_pubkey *pubk
    cdef cwd_rsa.wcrypto_rsa_prikey *prik


    cdef cwd.wd_dtb *n
    cdef cwd.wd_dtb *e
    cdef cwd.wd_dtb *d
    cdef cwd.wd_dtb *p
    cdef cwd.wd_dtb *q
    cdef cwd.wd_dtb *dp
    cdef cwd.wd_dtb *dq
    cdef cwd.wd_dtb *qinv
    cdef int key_bits

    def __cinit__(
        self,
        dev_path: str=None,
        node_mask: int=None,
        async_mode: int=0
    ):
        self.setup = <cwd_rsa.wcrypto_rsa_ctx_setup*> malloc (sizeof(cwd_rsa.wcrypto_rsa_ctx_setup))
        self.opdata = <cwd_rsa.wcrypto_rsa_op_data*> malloc (sizeof(cwd_rsa.wcrypto_rsa_op_data))
        self.tag = NULL
        self.async_mode = async_mode
        self.capa.alg = "rsa"
        cdef void *capa_ptr = &self.queue.capa
        memcpy(capa_ptr, self.capa, sizeof(cwd.wd_capa))

        self.n = <cwd.wd_dtb*> malloc (sizeof(cwd.wd_dtb))
        self.e = <cwd.wd_dtb*> malloc (sizeof(cwd.wd_dtb))
        self.d = <cwd.wd_dtb*> malloc (sizeof(cwd.wd_dtb))
        self.p = <cwd.wd_dtb*> malloc (sizeof(cwd.wd_dtb))
        self.q = <cwd.wd_dtb*> malloc (sizeof(cwd.wd_dtb))
        self.dp = <cwd.wd_dtb*> malloc (sizeof(cwd.wd_dtb))
        self.dq = <cwd.wd_dtb*> malloc (sizeof(cwd.wd_dtb))
        self.qinv = <cwd.wd_dtb*> malloc (sizeof(cwd.wd_dtb))
    
    cpdef void pool_setup(self, int block_num, int key_bits):
        
        '''setup and createpool
        params:
            key_bits: int
            block_num: int
        '''

        self.key_bits = key_bits
        self.wsetup.block_size = (self.key_bits >> 3)*7
        self.wsetup.block_num = block_num
        self.wsetup.align_size = 64
        self.pool = <cwd_bmm.wd_blkpool*> cwd_bmm.wd_blkpool_create(self.queue, self.wsetup)
        if self.pool == NULL:
            raise MemoryError("create pool failed")

    
    cpdef void ctx_setup(self, bint is_crt):

        '''init ctx_setup
        params:
            is_crt: bool
        '''
        if self.async_mode == 1:
            self.setup.cb = <cwd.wcrypto_cb>callback
        else:
            self.setup.cb = NULL
        self.setup.is_crt = is_crt
        self.setup.key_bits = self.key_bits
        self.setup.br.alloc = <cwd.wd_alloc>cwd_bmm.wd_alloc_blk
        self.setup.br.free = <cwd.wd_free>cwd_bmm.wd_free_blk
        self.setup.br.iova_map = <cwd.wd_map>cwd_bmm.wd_blk_iova_map
        self.setup.br.iova_unmap = <cwd.wd_unmap>cwd_bmm.wd_blk_iova_unmap
        self.setup.br.get_bufsize =  <cwd.wd_bufsize>cwd_bmm.wd_blksize 
        self.setup.br.usr = self.pool


    cpdef void set_opdata(self, op_type: RSA_OP_TYPE, data=None):

        '''set opdata before do rsa
        params:
            op_type: key_gen, sign, verify
            data: invalid in genkey
        status: assign value in do_rsa()
        in_: pointer, return from wcrypto_new_kg_in(GENKEY) or wd_alloc_blk(else).
        out: pointer, return from wcrypto_new_kg_out(GENKEY) or wd_alloc_blk(else)
        in_bytes: int  (key_size, for example)
        out_bytes: int
        '''
        
        cdef unsigned char *in_data
        
        if op_type == RSA_OP_TYPE.GENKEY:

            self.opdata.op_type = cwd_rsa.wcrypto_rsa_op_type.WCRYPTO_RSA_GENKEY
            if self.kg_in is not NULL and self.kg_out is not NULL:
                self.opdata.in_ = self.kg_in
                self.opdata.out = self.kg_out
            else:
                print("please create kg_in and kg_out")
                return
            self.opdata.in_bytes = self.key_bits >> 3
            self.opdata.out_bytes = self.key_bits >> 3
        
        else:
            if data == None:
                raise ValueError("data is None")
            
            self.opdata.in_ = cwd_bmm.wd_alloc_blk(self.pool)
            self.opdata.out = cwd_bmm.wd_alloc_blk(self.pool)
            
            if self.opdata.in_ is NULL or self.opdata.out is NULL:
                raise MemoryError("alloc blk failed")
            
            in_data = <unsigned char*>malloc(len(data)*sizeof(unsigned char))
            for i in range(len(data)):
                in_data[i] = data[i]
            memcpy(self.opdata.in_, in_data, len(data))
            self.opdata.in_bytes = len(data)
            self.opdata.out_bytes = len(data)
            
            
            if op_type == RSA_OP_TYPE.SIGN:
                # if msg == None:
                #     raise ValueError("msg is None")
                self.opdata.op_type = cwd_rsa.wcrypto_rsa_op_type.WCRYPTO_RSA_SIGN
                
            elif op_type == RSA_OP_TYPE.VERIFY:
                # if sig == None:
                #     raise ValueError("sig is None")
                self.opdata.op_type = cwd_rsa.wcrypto_rsa_op_type.WCRYPTO_RSA_VERIFY
            
            else:
                print("op_type error")
                return
    
    # cdef int wcrypto_rsa_key_bits(self):
    # 
    #    """
    #    get key_bits from ctx
    #    """
    #
    #     return cwd_rsa.wcrypto_rsa_key_bits(self.ctx)

    
    cpdef void create_rsa_ctx(self):

        """create ctx
        create ctx after init setup
        """
        self.ctx =  cwd_rsa.wcrypto_create_rsa_ctx(self.queue, self.setup)

    
    cpdef void wcrypto_get_rsa_pubkey(self):

        """
        link self.pubk to ctx->pubkey
        code: *pubkey = ((struct wcrypto_rsa_ctx *)ctx)->pubkey;
        """

        cwd_rsa.wcrypto_get_rsa_pubkey(self.ctx, &self.pubk)
    
    cpdef void wcrypto_get_rsa_prikey(self):

        """
        link self.prik to ctx->prikey
        code: *prikey = ((struct wcrypto_rsa_ctx *)ctx)->prikey;
        """

        cwd_rsa.wcrypto_get_rsa_prikey(self.ctx, &self.prik)

    

    cpdef void wcrypto_get_rsa_pubkey_params(self):

        """
        link self.e, self.n to self.pubk->e, self.pubk->n
        code:
            *e = &pbk->e;
            *n = &pbk->n;
        e, n is not necessary to be malloced
        """

        cwd_rsa.wcrypto_get_rsa_pubkey_params(self.pubk, &self.e, &self.n)

    cpdef void wcrypto_get_rsa_prikey_params(self):

        """
        link self.d, self.n to self.prik->d, self.prik->n
        code:
            *d = &pkey1->d;
            *n = &pkey1->n;
        d, n is not necessary to be malloced
        """

        cwd_rsa.wcrypto_get_rsa_prikey_params(self.prik, &self.d, &self.n)

    cpdef void wcrypto_set_rsa_pubkey_params(self, bytes e, bytes n):

        """
        data copy rather than link
        copy data from e, n to self.ctx->pubkey->e, self.ctx->pubkey->n
        code:
            memcpy(c->prik->pkey1->e.data, e->data, e->dsize);
            memcpy(c->prik->pkey1->n.data, n->data, n->dsize);
        """

        cdef cwd.wd_dtb *ce = <cwd.wd_dtb*> malloc (sizeof(cwd.wd_dtb))
        cdef cwd.wd_dtb *cn = <cwd.wd_dtb*> malloc (sizeof(cwd.wd_dtb))
        ce.dsize = len(e)
        cn.dsize = len(n)
        ce.data = <char*>malloc(ce.dsize)
        cn.data = <char*>malloc(cn.dsize)
        self.__set_wd_dtb(ce, e)
        self.__set_wd_dtb(cn, n)
        cwd_rsa.wcrypto_set_rsa_pubkey_params(self.ctx, ce, cn)

    cpdef void wcrypto_set_rsa_prikey_params(self, bytes d, bytes n):
            
        """
        data copy rather than link
        copy data from d, n to self.ctx->prikey->pkey1->d, self.ctx->prikey->pkey1->n
        code:
            memcpy(c->prikey->d.data, d->data, d->dsize);
            memcpy(c->prikey->n.data, n->data, n->dsize);
        """

        cdef cwd.wd_dtb *cd = <cwd.wd_dtb*> malloc (sizeof(cwd.wd_dtb))
        cdef cwd.wd_dtb *cn = <cwd.wd_dtb*> malloc (sizeof(cwd.wd_dtb))
        cd.dsize = len(d)
        cn.dsize = len(n)
        cd.data = <char*>malloc(cd.dsize)
        cn.data = <char*>malloc(cn.dsize)
        self.__set_wd_dtb(cd, d)
        self.__set_wd_dtb(cn, n)
        cwd_rsa.wcrypto_set_rsa_prikey_params(self.ctx, cd, cn)

    
    cpdef void wcrypto_set_rsa_crt_prikey_params(self, bytes dq, bytes dp, bytes qinv, bytes q, bytes p):

        """
        data copy
        copy data from dq, dp, qinv, p, q to self.ctx->prikey->pkey2->*
        """
        cdef cwd.wd_dtb *cdq = <cwd.wd_dtb*> malloc (sizeof(cwd.wd_dtb))
        cdef cwd.wd_dtb *cdp = <cwd.wd_dtb*> malloc (sizeof(cwd.wd_dtb))
        cdef cwd.wd_dtb *cqinv = <cwd.wd_dtb*> malloc (sizeof(cwd.wd_dtb))
        cdef cwd.wd_dtb *cq = <cwd.wd_dtb*> malloc (sizeof(cwd.wd_dtb))
        cdef cwd.wd_dtb *cp = <cwd.wd_dtb*> malloc (sizeof(cwd.wd_dtb))
        cdq.dsize = len(dq)
        cdp.dsize = len(dp)
        cqinv.dsize = len(qinv)
        cq.dsize = len(q)
        cp.dsize = len(p)
        cdq.data = <char*>malloc(cdq.dsize)
        cdp.data = <char*>malloc(cdp.dsize)
        cqinv.data = <char*>malloc(cqinv.dsize)
        cq.data = <char*>malloc(cq.dsize)
        cp.data = <char*>malloc(cp.dsize)
        self.__set_wd_dtb(cdq, dq)
        self.__set_wd_dtb(cdp, dp)
        self.__set_wd_dtb(cqinv, qinv)
        self.__set_wd_dtb(cq, q)
        self.__set_wd_dtb(cp, p)
        cwd_rsa.wcrypto_set_rsa_crt_prikey_params(self.ctx, cdq, cdp, cqinv, cq, cp)

    # get d, n (wd_dtb) from rsa_prikey->pkey1
    cpdef get_prikey(self):
        """
        return d, n in bytes format
        """
        # struct.unsigned char -> wd_dtb
        cwd_rsa.wcrypto_get_rsa_prikey_params(self.prik, &self.d, &self.n)
        d = self.__get_wd_dtb(self.d)
        n = self.__get_wd_dtb(self.n)
        return d, n
    

    # get dp, dq,q qinv ... from rsa_prik->pkey2
    cpdef get_crt_prikey(self):
        """
        return dp, dq, qinv, q, p in bytes format
        """
        if not self.wcrypto_rsa_is_crt():
            raise ValueError("not crt mode")
        cwd_rsa.wcrypto_get_rsa_crt_prikey_params(self.prik, &self.dq, &self.dp, &self.qinv, &self.q, &self.p)
        dp = self.__get_wd_dtb(self.dp)
        dq = self.__get_wd_dtb(self.dq)
        qinv = self.__get_wd_dtb(self.qinv)
        q = self.__get_wd_dtb(self.q)
        p = self.__get_wd_dtb(self.p)
        return dp, dq, qinv, q, p


    cpdef void wcrypto_new_kg_in(self, e: bytes, p: bytes, q: bytes):
        '''
        用现有的 e, p, q 构建一个 kg_in 结构体
        肯定是不能直接返回结构体指针的，那这样看也是作为一个成员出现比较合适
        这里有一个要注意的点是要给 wd_dtb 的 data 指针分配内存
        '''
        cdef cwd.wd_dtb *ce = <cwd.wd_dtb*>malloc(sizeof(cwd.wd_dtb))
        ce.dsize = len(e)
        ce.data = <char*>malloc(ce.dsize)
        if ce.data == NULL:
            raise MemoryError("malloc failed")
        self.__set_wd_dtb(ce, e)
        
        cdef cwd.wd_dtb *cp = <cwd.wd_dtb*>malloc(sizeof(cwd.wd_dtb))
        cp.dsize = len(p)
        cp.data = <char*>malloc(cp.dsize)
        if cp.data == NULL:
            raise MemoryError("malloc failed")
        self.__set_wd_dtb(cp, p)
        
        cdef cwd.wd_dtb *cq = <cwd.wd_dtb*>malloc(sizeof(cwd.wd_dtb))
        cq.dsize = len(q)
        cq.data = <char*>malloc(cq.dsize)
        if cq.data == NULL:
            raise MemoryError("malloc failed")
        self.__set_wd_dtb(cq, q)
        
        # print(self.ctx==NULL, ce==NULL, cp==NULL, cq==NULL)

        self.kg_in =  cwd_rsa.wcrypto_new_kg_in(self.ctx, ce, cp, cq)
        free(ce.data)
        free(ce)
        free(cp.data)
        free(cp)
        free(cq.data)
        free(cq)

    
    cdef void wcrypto_del_kg_in(self):
        cwd_rsa.wcrypto_del_kg_in(self.ctx, self.kg_in)

    cpdef void wcrypto_new_kg_out(self):
        """
        create a kg_out struct contains:
            d, n
            dp, dq, qinv (if setup.crt is True)
        return pointer of this struct
        """
        self.kg_out = cwd_rsa.wcrypto_new_kg_out(self.ctx)

    cdef void wcrypto_del_kg_out(self):
        cwd_rsa.wcrypto_del_kg_out(self.ctx, self.kg_out)

    cpdef void wcrypto_get_rsa_kg_out_params(self):
        """
        get d, n from kg_out
        """
        cwd_rsa.wcrypto_get_rsa_kg_out_params(self.kg_out, self.d, self.n)

    cdef void wcrypto_get_rsa_kg_out_crt_params(self):
        """
        get dp, dq, qinv from kg_out
        """
        cwd_rsa.wcrypto_get_rsa_kg_out_crt_params(self.kg_out, self.qinv, self.dq, self.dp)

    cpdef void tag_setup(self, int cnt, int thread_id):

        """setup a fixed tag
        cnt: user set (0?)
        thread_id:  acquired from python
        """

        if self.async_mode == 1:
            self.tag = <wcrypto_rsa_tag*>malloc(sizeof(wcrypto_rsa_tag))
            self.tag.ctx = self.ctx
            self.tag.cnt = cnt
            self.tag.thread_id = thread_id
        else:
            print("sync mode no need to setup tag")
    
    cpdef int wcrypto_do_rsa(self):
        return cwd_rsa.wcrypto_do_rsa(self.ctx, self.opdata, NULL)

    cpdef int wcrypto_rsa_poll(self, num:int):
        if num < 1:
            raise ValueError("num must be greater than 0")
        if self.async_mode == 0:
            raise ValueError("sync mode not support poll")
        return cwd_rsa.wcrypto_rsa_poll(self.queue, num)
    
    cdef void wcrypto_del_rsa_ctx(self):
        cwd_rsa.wcrypto_del_rsa_ctx(self.ctx)

    cpdef get_kg_out(self):
        self.wcrypto_get_rsa_kg_out_params()
        d = self.__get_wd_dtb(self.d)
        n = self.__get_wd_dtb(self.n)
        return d, n

    cpdef get_kg_out_crt(self):
        # cwd_rsa.wcrypto_get_rsa_kg_out_crt_params(self.kg_out, self.qinv, self.dq, self.dp)
        self.wcrypto_get_rsa_kg_out_crt_params()
        dq = self.__get_wd_dtb(self.dq)
        dp = self.__get_wd_dtb(self.dp)
        qinv = self.__get_wd_dtb(self.qinv)
        return dq, dp, qinv

    cpdef get_opdata_out(self):
        # memcpy self.opdata.out to a u8 array
        cdef char *out = <char*>malloc(self.opdata.out_bytes)
        memcpy(out, self.opdata.out, self.opdata.out_bytes)
        return bytes(out[:self.opdata.out_bytes])
          
    cdef __set_wd_dtb(self, cwd.wd_dtb *dtb, data: bytes):
        dtb.dsize = len(data)
        # print(dtb.dsize)
        for i in range(dtb.dsize):
            dtb.data[i] = data[i]

    cdef __get_wd_dtb(self, cwd.wd_dtb *dtb):
        return bytes(dtb.data[:dtb.dsize])


    def __dealloc__(self):
        # free queue
        if self.queue is not NULL:
            cwd.wd_release_queue(self.queue)
        # self.wcrypto_del_kg_in()
        # self.wcrypto_del_kg_out()
        # self.wcrypto_del_rsa_ctx()
