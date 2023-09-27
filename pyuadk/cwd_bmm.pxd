cimport  cwd

ctypedef unsigned int __u32

cdef extern from "../uadk/v1/wd_bmm.h":
    # Memory pool creating parameters
    cdef struct wd_blkpool_setup:
        __u32 block_size # Block buffer size
        __u32 block_num # Block buffer number
        __u32 align_size # Block buffer starting address align size
        cwd.wd_mm_br br # memory from user if don't use WD memory
    ctypedef wd_blkpool_setup wd_blkpool_setup_t

    cdef struct wd_blkpool:
        pass

    cdef void *wd_blkpool_create(cwd.wd_queue *q,
                       wd_blkpool_setup *setup)
    cdef void wd_blkpool_destroy(void *pool)
    cdef void *wd_alloc_blk(void *pool)
    cdef void wd_free_blk(void *pool, void *blk)
    cdef int wd_get_free_blk_num(void *pool, __u32 *free_num)
    cdef int wd_blk_alloc_failures(void *pool, __u32 *fail_num)
    cdef void *wd_blk_iova_map(void *pool, void *blk)
    cdef void wd_blk_iova_unmap(void *pool, void *blk_dma, void *blk)
    cdef __u32 wd_blksize(void *pool)
