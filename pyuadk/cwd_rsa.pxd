ctypedef unsigned char __u8
ctypedef unsigned short __u16
ctypedef unsigned int __u32
ctypedef unsigned long long __u64

cimport  cwd

cdef extern from "../uadk/v1/wd_rsa.h":
    # 这种声明方式只能使用指针
    cdef struct wcrypto_rsa_kg_in:
        pass
    
    cdef struct wcrypto_rsa_kg_out:
        pass
 

    cdef struct wcrypto_rsa_pubkey:
        pass
    cdef struct wcrypto_rsa_prikey:
        pass

    # RSA operational types
    cdef enum wcrypto_rsa_op_type:
        WCRYPTO_RSA_INVALID, # invalid rsa operation
        WCRYPTO_RSA_SIGN, # RSA sign
        WCRYPTO_RSA_VERIFY, # RSA verify
        WCRYPTO_RSA_GENKEY, # RSA key generation

    #RSA key types
    cdef enum wcrypto_rsa_key_type:
        WCRYPTO_RSA_INVALID_KEY, # invalid rsa key type
        WCRYPTO_RSA_PUBKEY, # rsa public key type
        WCRYPTO_RSA_PRIKEY1, # invalid rsa private common key type
        WCRYPTO_RSA_PRIKEY2, # invalid rsa private CRT key type

    # RSA context setting up input parameters from user
    cdef struct wcrypto_rsa_ctx_setup:
        cwd.wcrypto_cb cb # call back function from user
        __u16 data_fmt # data format denoted by enum wd_buff_type
        __u16 key_bits # RSA key bits
        bint is_crt # CRT mode or not
        cwd.wd_mm_br br # memory operations from user

    cdef struct wcrypto_rsa_op_data:
        wcrypto_rsa_op_type op_type # rsa operation type
        int status # rsa operation status
        void *in_ 'in' # rsa operation input address, should be DMA-able
        void *out # rsa operation output address, should be DMA-able
        int in_bytes # rsa operation input bytes
        int out_bytes # rsa operation output bytes

    # RSA message format of Warpdrive
    cdef struct wcrypto_rsa_msg:
        __u8 alg_type # Denoted by enum wcrypto_type
        __u8 op_type # Denoted by enum wcrypto_rsa_op_type
        __u8 key_type # Denoted by enum wcrypto_rsa_key_type
        __u8 data_fmt # Data format, denoted by enum wd_buff_type
        __u8 result # Data format, denoted by WD error code
        __u16 in_bytes # Input data bytes
        __u16 out_bytes # Output data bytes
        __u16 key_bytes # Input key bytes
        __u8 *in_ # Input data VA, buf should be DMA buffer.
        __u8 *out # Output data VA pointer, should be DMA buffer
        __u8 *key # Input key VA pointer, should be DMA buffer 

        # '''
        # * Input user tag, used for identify data stream/user:
        #* struct wcrypto_cb_tag
        # '''
        __u64 usr_data


    cdef bint wcrypto_rsa_is_crt(const void *ctx)
    cdef int wcrypto_rsa_key_bits(const void *ctx)
    cdef void *wcrypto_create_rsa_ctx(cwd.wd_queue *q, wcrypto_rsa_ctx_setup *setup)
    cdef void wcrypto_get_rsa_pubkey(void *ctx, wcrypto_rsa_pubkey **pubkey)
    cdef void wcrypto_get_rsa_prikey(void *ctx, wcrypto_rsa_prikey **prikey)
    cdef int wcrypto_set_rsa_pubkey_params(void *ctx, cwd.wd_dtb *e, cwd.wd_dtb *n)
    cdef void wcrypto_get_rsa_pubkey_params(wcrypto_rsa_pubkey *pbk, cwd.wd_dtb **e, cwd.wd_dtb **n)
    cdef int wcrypto_set_rsa_prikey_params(void *ctx, cwd.wd_dtb *d, cwd.wd_dtb *n)
    cdef void wcrypto_get_rsa_prikey_params(wcrypto_rsa_prikey *pvk, cwd.wd_dtb **d, cwd.wd_dtb **n)
    cdef int wcrypto_set_rsa_crt_prikey_params(void *ctx, cwd.wd_dtb *dq,
                cwd.wd_dtb *dp,
                cwd.wd_dtb *qinv,
                cwd.wd_dtb *q,
                cwd.wd_dtb *p)
    cdef void wcrypto_get_rsa_crt_prikey_params(wcrypto_rsa_prikey *pvk,
                cwd.wd_dtb **dq, cwd.wd_dtb **dp,
                cwd.wd_dtb **qinv, cwd.wd_dtb **q,
                cwd.wd_dtb **p)

    # APIs For RSA key generate
    # new_kg_in 和 get_kg_in_params 是相反的过程，前者是将p、q、e赋值给ki，后者是将ki中的p、q、e赋值给p、q、e
    cdef wcrypto_rsa_kg_in *wcrypto_new_kg_in(void *ctx, cwd.wd_dtb *e,
                cwd.wd_dtb *p, cwd.wd_dtb *q)
    cdef void wcrypto_del_kg_in(void *ctx, wcrypto_rsa_kg_in *ki)
    cdef void wcrypto_get_rsa_kg_in_params(wcrypto_rsa_kg_in *kin, cwd.wd_dtb *e, cwd.wd_dtb *q, cwd.wd_dtb *p)

    cdef wcrypto_rsa_kg_out *wcrypto_new_kg_out(void *ctx)
    cdef void wcrypto_del_kg_out(void *ctx, wcrypto_rsa_kg_out *kout)
    cdef void wcrypto_get_rsa_kg_out_params(wcrypto_rsa_kg_out *kout,
                cwd.wd_dtb *d,
                cwd.wd_dtb *n)
    cdef void wcrypto_get_rsa_kg_out_crt_params(wcrypto_rsa_kg_out *kout,
                cwd.wd_dtb *qinv,
                cwd.wd_dtb *dq, cwd.wd_dtb *dp)

    cdef int wcrypto_rsa_kg_in_data(wcrypto_rsa_kg_in *ki, char **data)
    cdef int wcrypto_rsa_kg_out_data(wcrypto_rsa_kg_out *ko, char **data)
    cdef void wcrypto_set_rsa_kg_out_crt_psz(wcrypto_rsa_kg_out *kout,
                        size_t qinv_sz,
                        size_t dq_sz,
                        size_t dp_sz)
    cdef void wcrypto_set_rsa_kg_out_psz(wcrypto_rsa_kg_out *kout,
                    size_t d_sz,
                    size_t n_sz)

    # '''
    # * This is a pair of asynchronous mode RSA API as tag is not NULL,
    # * or it is synchronous mode
    # '''
    cdef int wcrypto_do_rsa(void *ctx, wcrypto_rsa_op_data *opdata, void *tag)
    cdef int wcrypto_rsa_poll(cwd.wd_queue *q, __u32 num)
    cdef void wcrypto_del_rsa_ctx(void *ctx)

    
