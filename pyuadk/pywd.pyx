cimport cwd
cimport cwd_bmm
from libc.stdlib cimport malloc
from libc.string cimport memset, strcpy


cdef class Wd(object):

    def __cinit__(
            self,
            dev_path: str = None,
            node_mask: int = None,
            async_mode: int = 1
    ):
        self.queue = <cwd.wd_queue*> malloc (sizeof(cwd.wd_queue))
        self.capa = <cwd.wd_capa*> malloc (sizeof(cwd.wd_capa))
        self.wsetup =\
            <cwd_bmm.wd_blkpool_setup*> malloc (sizeof(cwd_bmm.wd_blkpool_setup))
        self.pool = NULL
        self.ctx = NULL

        cdef bytes cdev_path
        if dev_path is not None:
            cdev_path = dev_path.encode()
            strcpy(self.queue.dev_path, cdev_path)
        if node_mask is not None:
            self.queue.node_mask = node_mask

        memset(self.queue, 0, sizeof(cwd.wd_queue))
        memset(self.capa, 0, sizeof(cwd.wd_capa))
        memset(self.wsetup, 0, sizeof(cwd_bmm.wd_blkpool_setup))

    cpdef int request_queue(self):
        ret = cwd.wd_request_queue(self.queue)
        if ret != 0 or self.queue == NULL:
            raise MemoryError("request_queue failed")
        return 0

    cpdef int wd_get_available_dev_num(self):
        return cwd.wd_get_available_dev_num(self.capa.alg)

    
