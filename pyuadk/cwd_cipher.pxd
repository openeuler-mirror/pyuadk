cimport cwd

ctypedef unsigned char __u8
ctypedef unsigned short __u16
ctypedef unsigned int __u32
ctypedef unsigned long long __u64

cdef extern from "../uadk/v1/wd_cipher.h":
    cdef enum wcrypto_cipher_op_type:
        WCRYPTO_CIPHER_ENCRYPTION
        WCRYPTO_CIPHER_DECRYPTION
    ctypedef wcrypto_cipher_op_type wcrypto_cipher_op_type_t

    cdef enum wcrypto_cipher_alg:
        WCRYPTO_CIPHER_SM4
        WCRYPTO_CIPHER_AES
        WCRYPTO_CIPHER_DES
        WCRYPTO_CIPHER_3DES
    ctypedef wcrypto_cipher_alg wcrypto_cipher_alg_t

    cdef enum wcrypto_cipher_mode:
        WCRYPTO_CIPHER_ECB
        WCRYPTO_CIPHER_CBC
        WCRYPTO_CIPHER_CTR
        WCRYPTO_CIPHER_XTS
        WCRYPTO_CIPHER_OFB
        WCRYPTO_CIPHER_CFB
        WCRYPTO_CIPHER_CCM
        WCRYPTO_CIPHER_GCM
    ctypedef wcrypto_cipher_mode wcrypto_cipher_mode_t

    cdef struct wcrypto_cipher_ctx_setup:
        cwd.wcrypto_cb cb
        wcrypto_cipher_alg alg
        wcrypto_cipher_mode mode
        cwd.wd_mm_br br
        __u16 data_fmt
    ctypedef wcrypto_cipher_ctx_setup wcrypto_cipher_ctx_setup_t

    cdef struct wcrypto_cipher_op_data:
        wcrypto_cipher_op_type op_type
        int status
        void *in_ "in",
        void *out_ "out",
        void *iv,
        __u32 in_bytes,
        __u32 out_bytes,
        __u32 iv_bytes,
        void* priv
    ctypedef wcrypto_cipher_op_data wcrypto_cipher_op_data_t

    cdef struct wcrypto_cipher_msg:
        __u8 algo_type,
        __u8 alg,
        __u8 op_type,
        __u8 mode,
        __u8 data_fmt,
        __u8 result,

        __u16 key_bytes,
        __u16 iv_bytes,
        __u32 in_bytes,
        __u32 out_bytes,

        __u8 *key,
        __u8 *iv,
        __u8 *in_,
        __u8 *out_,
        __u64 usr_data
    ctypedef wcrypto_cipher_msg wcrypto_cipher_msg_t

    cdef struct wcrypto_cipher_tag:
        void *ctx
        int thread_id
        int cnt

    cdef void *wcrypto_create_cipher_ctx(cwd.wd_queue *q, wcrypto_cipher_ctx_setup *setup)
    cdef int wcrypto_set_cipher_key(void *ctx, __u8 *key, __u16 key_len)
    cdef int wcrypto_do_cipher(void *ctx, wcrypto_cipher_op_data *opdata, void *tag)
    cdef int wcrypto_cipher_poll(cwd.wd_queue *q, __u32 num)
    cdef void wcrypto_del_cipher_ctx(void *ctx)
    cdef int wcrypto_burst_cipher(void* ctx, wcrypto_cipher_op_data **opdata, void **tag, __u32 num)
