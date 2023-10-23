ctypedef unsigned int __u32
ctypedef unsigned short __u16
ctypedef unsigned char __u8
ctypedef unsigned long long __u64

cimport cwd
cdef extern from "../uadk/v1/wd_digest.h":

    cdef enum wcrypto_digest_alg:
        WCRYPTO_SM3
        WCRYPTO_MD5
    ctypedef wcrypto_digest_alg wcrypto_digest_alg_t

    cdef enum wd_digest_mac_len:
        WD_DIGEST_SM3_LEN
        WD_DIGEST_MD5_LEN
    ctypedef wd_digest_mac_len wd_digest_mac_len_t

    cdef enum wcrypto_digest_mode:
        WCRYPTO_DIGEST_NORMAL
        WCRYPTO_DIGEST_HMAC
    ctypedef wcrypto_digest_mode wcrypto_digest_mode_t

    cdef struct wcrypto_digest_ctx_setup:
        cwd.wcrypto_cb cb
        wcrypto_digest_alg alg
        wcrypto_digest_mode mode
        cwd.wd_mm_br br
        __u16 data_fmt
    ctypedef wcrypto_digest_ctx_setup wcrypto_digest_ctx_setup_t

    cdef struct wcrypto_digest_op_data:
        void *in_ "in",
        void *out_ "out",
        __u32 in_bytes,
        __u32 out_bytes,
        void *priv,
        int status
        bint has_next
    ctypedef wcrypto_digest_op_data wcrypto_digest_op_data_t

    cdef struct wcrypto_digest_msg:
        __u8 alg_type
        __u8 alg
        __u8 has_next
        __u8 mode
        __u8 data_fmt
        __u8 result
        __u16 key_bytes
        __u16 iv_bytes

        __u8 *key
        __u8 *iv
        __u8 *in_
        __u8 *out_
        __u32 in_bytes
        __u32 out_bytes
        __u64 usr_data
    ctypedef wcrypto_digest_msg wcrypto_digest_msg_t

    cdef void *wcrypto_create_digest_ctx(
        cwd.wd_queue *q,
        wcrypto_digest_ctx_setup *setup
    )

    cdef int wcrypto_set_digest_key(void *ctx, __u8 *key, __u16 key_len)

    cdef int wcrypto_do_digest(void *ctx, wcrypto_digest_op_data *opdata, void *tag)

    cdef int wcrypto_digest_poll(cwd.wd_queue *q, __u32 num)

    cdef void wcrypto_del_digest_ctx(void *ctx)
