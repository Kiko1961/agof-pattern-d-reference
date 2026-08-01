// Real io_uring openat primitive — NO direct openat syscall is ever issued.
// Proves that a syscall-level filter trapping openat() does NOT see file opens
// submitted via io_uring. Exposes iouring_openat() for in-process ctypes use.
#define _GNU_SOURCE
#include <linux/io_uring.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <fcntl.h>

static int io_uring_setup(unsigned entries, struct io_uring_params *p) {
    return (int)syscall(__NR_io_uring_setup, entries, p);
}
static int io_uring_enter(int fd, unsigned to_submit, unsigned min_complete,
                          unsigned flags) {
    return (int)syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags, NULL, 0);
}

// Returns the opened fd (>=0) on success, or -errno on failure.
// If io_uring_setup itself is blocked (e.g. by seccomp -> EPERM), returns -EPERM
// and NO file is created: the bypass is closed at the ring-creation gate.
int iouring_openat(const char *path, int flags, int mode) {
    struct io_uring_params p;
    memset(&p, 0, sizeof(p));
    int ring = io_uring_setup(8, &p);
    if (ring < 0) return -errno;            // ring creation denied -> bypass blocked

    size_t sring_sz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
    size_t cring_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    if (p.features & IORING_FEAT_SINGLE_MMAP) {
        if (cring_sz > sring_sz) sring_sz = cring_sz;
        cring_sz = sring_sz;
    }
    void *sq = mmap(0, sring_sz, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE,
                    ring, IORING_OFF_SQ_RING);
    if (sq == MAP_FAILED) return -errno;
    void *cq = sq;
    if (!(p.features & IORING_FEAT_SINGLE_MMAP)) {
        cq = mmap(0, cring_sz, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE,
                  ring, IORING_OFF_CQ_RING);
        if (cq == MAP_FAILED) return -errno;
    }
    struct io_uring_sqe *sqes = mmap(0, p.sq_entries * sizeof(struct io_uring_sqe),
                    PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, ring, IORING_OFF_SQES);
    if (sqes == MAP_FAILED) return -errno;

    unsigned *sq_tail   = (unsigned*)((char*)sq + p.sq_off.tail);
    unsigned *sq_ring_mask = (unsigned*)((char*)sq + p.sq_off.ring_mask);
    unsigned *sq_array  = (unsigned*)((char*)sq + p.sq_off.array);
    unsigned *cq_head   = (unsigned*)((char*)cq + p.cq_off.head);
    unsigned *cq_tail   = (unsigned*)((char*)cq + p.cq_off.tail);
    unsigned *cq_ring_mask = (unsigned*)((char*)cq + p.cq_off.ring_mask);
    struct io_uring_cqe *cqes = (struct io_uring_cqe*)((char*)cq + p.cq_off.cqes);

    unsigned tail = *sq_tail;
    unsigned index = tail & *sq_ring_mask;
    struct io_uring_sqe *sqe = &sqes[index];
    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_OPENAT;
    sqe->fd = AT_FDCWD;
    sqe->addr = (uint64_t)(uintptr_t)path;
    sqe->len = mode;
    sqe->open_flags = flags;
    sq_array[index] = index;
    atomic_store_explicit((_Atomic unsigned*)sq_tail, tail + 1, memory_order_release);

    int r = io_uring_enter(ring, 1, 1, IORING_ENTER_GETEVENTS);
    if (r < 0) return -errno;

    unsigned chead = *cq_head;
    // busy-wait briefly for the completion
    for (int i = 0; i < 100000 && chead == *cq_tail; i++) { /* spin */ }
    if (chead == *cq_tail) return -EAGAIN;
    struct io_uring_cqe *cqe = &cqes[chead & *cq_ring_mask];
    int res = cqe->res;
    atomic_store_explicit((_Atomic unsigned*)cq_head, chead + 1, memory_order_release);
    return res;   // >=0: fd (open succeeded via io_uring); <0: -errno
}
