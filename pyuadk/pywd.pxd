cimport cwd
cimport cwd_bmm


cdef cwd.wd_alloc wd_alloc_func
cdef cwd.wd_free wd_free_func
cdef cwd.wd_map wd_map_func
cdef cwd.wd_unmap wd_unmap_func
cdef cwd.wd_bufsize wd_bufsize_func


cdef class Wd:
    cdef cwd.wd_queue *queue
    cdef cwd.wd_capa *capa

    cdef cwd_bmm.wd_blkpool_setup *wsetup
    cdef void *ctx
    cdef cwd_bmm.wd_blkpool *pool

    cpdef int request_queue(self)

    cpdef int wd_get_available_dev_num(self)
    
