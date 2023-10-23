

ctypedef unsigned int __u32
ctypedef unsigned int __u8

cdef extern from "../uadk/v1/wd.h":

    ctypedef void (*wcrypto_cb)(const void *msg, void *tag);

    ctypedef void (*wd_log)(const char *formatt, ...);

    # memory APIs for Algorithm Layer
    ctypedef void *(*wd_alloc)(void *usr, size_t size);
    ctypedef void (*wd_free)(void *usr, void *va);

    # memory VA to DMA address map
    ctypedef void *(*wd_map)(void *usr, void *va, size_t sz);
    ctypedef void (*wd_unmap)(void *usr, void *va, void *dma, size_t sz);
    ctypedef __u32 (*wd_bufsize)(void *usr);

    cdef wd_log log_out

    cdef struct wcrypto_cb_tag:
        pass
    ctypedef wcrypto_cb_tag wcrypto_cb_tag_t

    cdef struct wcrypto_oaras:
        pass
    ctypedef wcrypto_oaras wcrypto_oaras_t

    # a enum have 2 value
    cdef enum wd_buff_type:
        WD_FLAT_BUF = 0,
        WD_SGL_BUF = 1
    ctypedef wd_buff_type wd_buff_type_t

    cdef struct wcrypto_paras:
        __u8 direction,
        __u8 is_poll

    cdef enum wcrypto_type:
        WCRYPTO_RSA = 0,
        WCRYPTO_CIPHER = 1,
        WCRYPTO_DIGEST = 2,
    ctypedef wcrypto_type wcrypto_type_t

    cdef struct wd_dtb:
        char *data # data buffer start address
        __u32 dsize # data size
        __u32 bsize # buffer size   
    ctypedef wd_dtb wd_dtb_t

    # Memory from user, it is given at ctx creating.
    cdef struct wd_mm_br:
        wd_alloc alloc # emory allocation
        wd_free free # Memory free
        wd_map iova_map # get iova from user space VA

        # destroy the mapping between the PA of VA and iova
        wd_unmap iova_unmap;
        void *usr;
        # data for the above operations
        wd_bufsize get_bufsize # optional
    ctypedef wd_mm_br wd_mm_br_t

    # capabilities
    cdef struct wd_capa:
        const char *alg
        int throughput
        int latency
        __u32 flags
        wcrypto_paras priv

    ctypedef wd_capa wd_capa_t

    cdef struct wd_queue:
        wd_capa capa
        char *dev_path
        __u32 node_mask
        void *qinfo
    ctypedef wd_queue wd_queue_t

    int wd_request_queue(wd_queue *q)
    void wd_release_queue(wd_queue *q)
    int wd_send(wd_queue *q, void *req)
    int wd_recv(wd_queue *q, void **resp)
    int wd_wait(wd_queue *q, short ms)
    int wd_recv_sync(wd_queue *q, void **resp, short ms)
    void * wd_reserve_memory(wd_queue *q, size_t size)
    int wd_share_reserved_memory(wd_queue *q, wd_queue *target_q)
    int wd_get_available_dev_num(const char *alg_name)
    int wd_get_node_id(wd_queue *q)
    void * wd_iova_map(wd_queue *q, void *va, size_t sz)
    void wd_iova_unmap(wd_queue *q, void *va, void *dma, size_t sz)
    void * wd_dma_to_va(wd_queue *q, void *dma)
    int wd_register_log(wd_log log)
