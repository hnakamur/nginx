
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_SLAB_PAGE_MASK   3
#define NGX_SLAB_PAGE        0
#define NGX_SLAB_BIG         1
#define NGX_SLAB_EXACT       2
#define NGX_SLAB_SMALL       3

#if (NGX_PTR_SIZE == 4)

#define NGX_SLAB_PAGE_FREE   0
#define NGX_SLAB_PAGE_BUSY   0xffffffff
#define NGX_SLAB_PAGE_START  0x80000000

#define NGX_SLAB_SHIFT_MASK  0x0000000f
#define NGX_SLAB_MAP_MASK    0xffff0000
#define NGX_SLAB_MAP_SHIFT   16

#define NGX_SLAB_BUSY        0xffffffff

#else /* (NGX_PTR_SIZE == 8) */

#define NGX_SLAB_PAGE_FREE   0
#define NGX_SLAB_PAGE_BUSY   0xffffffffffffffff
#define NGX_SLAB_PAGE_START  0x8000000000000000

#define NGX_SLAB_SHIFT_MASK  0x000000000000000f
#define NGX_SLAB_MAP_MASK    0xffffffff00000000
#define NGX_SLAB_MAP_SHIFT   32

#define NGX_SLAB_BUSY        0xffffffffffffffff

#endif


#define ngx_slab_slots(pool)                                                  \
    (ngx_slab_page_t *) ((u_char *) (pool) + sizeof(ngx_slab_pool_t))

#define ngx_slab_page_type(page)   ((page)->prev & NGX_SLAB_PAGE_MASK)

#define ngx_slab_page_prev(page)                                              \
    (ngx_slab_page_t *) ((page)->prev & ~NGX_SLAB_PAGE_MASK)

#define ngx_slab_page_addr(pool, page)                                        \
    ((((page) - (pool)->pages) << ngx_pagesize_shift)                         \
     + (uintptr_t) (pool)->start)


#if (NGX_DEBUG_MALLOC)

#define ngx_slab_junk(p, size)     ngx_memset(p, 0xA5, size)

#elif (NGX_HAVE_DEBUG_MALLOC)

#define ngx_slab_junk(p, size)                                                \
    if (ngx_debug_malloc)          ngx_memset(p, 0xA5, size)

#else

#define ngx_slab_junk(p, size)

#endif

static ngx_slab_page_t *ngx_slab_alloc_pages(ngx_slab_pool_t *pool,
    ngx_uint_t pages);
static void ngx_slab_free_pages(ngx_slab_pool_t *pool, ngx_slab_page_t *page,
    ngx_uint_t pages);
static void ngx_slab_error(ngx_slab_pool_t *pool, ngx_uint_t level,
    char *text);


static ngx_uint_t  ngx_slab_max_size;
static ngx_uint_t  ngx_slab_exact_size;
static ngx_uint_t  ngx_slab_exact_shift;


void
ngx_slab_sizes_init(void)
{
    ngx_uint_t  n;

    ngx_slab_max_size = ngx_pagesize / 2;
    ngx_slab_exact_size = ngx_pagesize / (8 * sizeof(uintptr_t));
    for (n = ngx_slab_exact_size; n >>= 1; ngx_slab_exact_shift++) {
        /* void */
    }
}

#ifdef LIBNGINX
size_t
ngx_slab_size_for_alloc(ngx_slab_pool_t *pool, size_t size)
{
    size_t            s;
    ngx_uint_t        shift;

    if (size > ngx_slab_max_size) {
        return ngx_pagesize * ((size >> ngx_pagesize_shift)
                               + ((size % ngx_pagesize) ? 1 : 0));
    }

    if (size > pool->min_size) {
        shift = 1;
        for (s = size - 1; s >>= 1; shift++) { /* void */ }

    } else {
        shift = pool->min_shift;
    }

    return 1 << shift;
}
#endif /*LIBNGINX */

void
ngx_slab_init(ngx_slab_pool_t *pool)
{
    u_char           *p;
    size_t            size;
    ngx_int_t         m;
    ngx_uint_t        i, n, pages;
    ngx_slab_page_t  *slots, *page;

    pool->min_size = (size_t) 1 << pool->min_shift;
    ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
        "ngx_slab_init#1, pool=%p, &pool->free=%p",
        pool, &pool->free);

    slots = ngx_slab_slots(pool);

    p = (u_char *) slots;
    size = pool->end - p;

    ngx_slab_junk(p, size);

    n = ngx_pagesize_shift - pool->min_shift;

    for (i = 0; i < n; i++) {
        /* only "next" is used in list head */
        slots[i].slab = 0;
        slots[i].next = &slots[i];
        slots[i].prev = 0;
        ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
            "ngx_slab_init#2, &slots[%d]=%p",
            i, &slots[i]);
    }

    p += n * sizeof(ngx_slab_page_t);

    pool->stats = (ngx_slab_stat_t *) p;
    ngx_memzero(pool->stats, n * sizeof(ngx_slab_stat_t));

    p += n * sizeof(ngx_slab_stat_t);

    size -= n * (sizeof(ngx_slab_page_t) + sizeof(ngx_slab_stat_t));

    pages = (ngx_uint_t) (size / (ngx_pagesize + sizeof(ngx_slab_page_t)));

    pool->pages = (ngx_slab_page_t *) p;
    ngx_memzero(pool->pages, pages * sizeof(ngx_slab_page_t));

    page = pool->pages;

    /* only "next" is used in list head */
    pool->free.slab = 0;
    pool->free.next = page;
    pool->free.prev = 0;

    page->slab = pages;
    page->next = &pool->free;
    page->prev = (uintptr_t) &pool->free;

    pool->start = ngx_align_ptr(p + pages * sizeof(ngx_slab_page_t),
                                ngx_pagesize);

    m = pages - (pool->end - pool->start) / ngx_pagesize;
    if (m > 0) {
        pages -= m;
        page->slab = pages;
    }

    pool->last = pool->pages + pages;
    pool->pfree = pages;
    ngx_log_debug7(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
        "ngx_slab_init#3, page=%p, "
        "page->slab=%016XL, page->prev=%p, page->next=%p, "
        "pool->start=%p, pool->last=%p, pool->pfree=%d",
        page,
        page->slab, page->prev, page->next,
        pool->start, pool->last, pool->pfree);

    pool->log_nomem = 1;
    pool->log_ctx = &pool->zero;
    pool->zero = '\0';
}


void *
ngx_slab_alloc(ngx_slab_pool_t *pool, size_t size)
{
    void  *p;

    ngx_shmtx_lock(&pool->mutex);

    p = ngx_slab_alloc_locked(pool, size);

    ngx_shmtx_unlock(&pool->mutex);

    return p;
}


void *
ngx_slab_alloc_locked(ngx_slab_pool_t *pool, size_t size)
{
    size_t            s;
    uintptr_t         p, m, mask, *bitmap;
    ngx_uint_t        i, n, slot, shift, map;
    ngx_slab_page_t  *page, *prev, *slots;

    if (size > ngx_slab_max_size) {

        ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                       "slab alloc: %uz", size);

        page = ngx_slab_alloc_pages(pool, (size >> ngx_pagesize_shift)
                                          + ((size % ngx_pagesize) ? 1 : 0));
        if (page) {
            p = ngx_slab_page_addr(pool, page);

        } else {
            p = 0;
        }

        goto done;
    }

    if (size > pool->min_size) {
        shift = 1;
        for (s = size - 1; s >>= 1; shift++) { /* void */ }
        slot = shift - pool->min_shift;

    } else {
        shift = pool->min_shift;
        slot = 0;
    }

    pool->stats[slot].reqs++;

    ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                   "slab alloc: %uz slot: %ui", size, slot);

    slots = ngx_slab_slots(pool);
    page = slots[slot].next;
    ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
        "slab_alloc#1 page=%p, page->next=%p", page, page->next);

    if (page->next != page) {

        if (shift < ngx_slab_exact_shift) {

            bitmap = (uintptr_t *) ngx_slab_page_addr(pool, page);

            map = (ngx_pagesize >> shift) / (8 * sizeof(uintptr_t));
            ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                "slab_alloc#2 bitmap=%p, map=%d", bitmap, map);

            for (n = 0; n < map; n++) {

                if (bitmap[n] != NGX_SLAB_BUSY) {

                    for (m = 1, i = 0; m; m <<= 1, i++) {
                        ngx_log_debug4(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                            "slab_alloc#3 m=%016XU, i=%d, bitmap[n]=%016XU, "
                            "bitmap[n]&m=%016XU",
                            m, i, bitmap[n], bitmap[n] & m);
                        if (bitmap[n] & m) {
                            continue;
                        }

                        bitmap[n] |= m;
                        ngx_log_debug3(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                            "slab_alloc#4 n=%d, m=%016XL, bitmap[n]=%016XL",
                            n, m, bitmap[n]);

                        i = (n * 8 * sizeof(uintptr_t) + i) << shift;

                        p = (uintptr_t) bitmap + i;

                        pool->stats[slot].used++;

                        if (bitmap[n] == NGX_SLAB_BUSY) {
                            for (n = n + 1; n < map; n++) {
                                if (bitmap[n] != NGX_SLAB_BUSY) {
                                    goto done;
                                }
                            }

                            prev = ngx_slab_page_prev(page);
                            prev->next = page->next;
                            page->next->prev = page->prev;

                            page->next = NULL;
                            page->prev = NGX_SLAB_SMALL;
                            ngx_log_debug3(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log,
                                0,
                                "slab_alloc#5 prev=%p, prev->next=%p, "
                                "prev->next->prev=%p, page->next=NULL, "
                                "page->prev=SLAB_SMALL",
                                prev, prev->next, prev->next->prev);
                        }

                        goto done;
                    }
                }
            }

        } else if (shift == ngx_slab_exact_shift) {

            for (m = 1, i = 0; m; m <<= 1, i++) {
                ngx_log_debug4(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                    "slab_alloc#6 m=%016XU, i=%d, page->slab=%016XU, "
                    "page->slab&m=%016XU",
                    m, i, page->slab, page->slab & m);
                if (page->slab & m) {
                    continue;
                }

                page->slab |= m;
                ngx_log_debug3(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                    "slab_alloc#7 page=%p, m=%016XL, page->slab=%016XL",
                    page, m, page->slab);

                if (page->slab == NGX_SLAB_BUSY) {
                    prev = ngx_slab_page_prev(page);
                    prev->next = page->next;
                    page->next->prev = page->prev;

                    page->next = NULL;
                    page->prev = NGX_SLAB_EXACT;
                    ngx_log_debug3(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                        "slab_alloc#8 prev=%p, prev->next=%p, "
                        "prev->next->prev=%p, page->next=NULL, "
                        "page->prev=SLAB_EXACT",
                        prev, prev->next, prev->next->prev);
                }

                p = ngx_slab_page_addr(pool, page) + (i << shift);

                pool->stats[slot].used++;

                goto done;
            }

        } else { /* shift > ngx_slab_exact_shift */

            mask = ((uintptr_t) 1 << (ngx_pagesize >> shift)) - 1;
            mask <<= NGX_SLAB_MAP_SHIFT;

            for (m = (uintptr_t) 1 << NGX_SLAB_MAP_SHIFT, i = 0;
                 m & mask;
                 m <<= 1, i++)
            {
                ngx_log_debug5(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                    "slab_alloc#9 mask=%016XU, m=%016XU, i=%d, "
                    "page->slab=%016XU, page->slab&m=%016XU",
                    mask, m, i, page->slab, page->slab & m);
                if (page->slab & m) {
                    continue;
                }

                page->slab |= m;
                ngx_log_debug3(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                    "slab_alloc#10 page=%p, m=%016XL, page->slab=%016XL",
                    page, m, page->slab);

                if ((page->slab & NGX_SLAB_MAP_MASK) == mask) {
                    prev = ngx_slab_page_prev(page);
                    prev->next = page->next;
                    page->next->prev = page->prev;

                    page->next = NULL;
                    page->prev = NGX_SLAB_BIG;
                    ngx_log_debug3(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                        "slab_alloc#11 prev=%p, prev->next=%p, "
                        "prev->next->prev=%p, page->next=NULL, "
                        "page->prev=SLAB_BIG",
                        prev, prev->next, prev->next->prev);
                }

                p = ngx_slab_page_addr(pool, page) + (i << shift);

                pool->stats[slot].used++;

                goto done;
            }
        }

        ngx_slab_error(pool, NGX_LOG_ALERT, "ngx_slab_alloc(): page is busy");
        ngx_debug_point();
    }

    page = ngx_slab_alloc_pages(pool, 1);

    if (page) {
        ngx_log_debug3(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
            "slab_alloc#12 page=%p, shift=%d, ngx_slab_exact_shift=%d",
            page, shift, ngx_slab_exact_shift);
        if (shift < ngx_slab_exact_shift) {
            bitmap = (uintptr_t *) ngx_slab_page_addr(pool, page);

            n = (ngx_pagesize >> shift) / ((1 << shift) * 8);

            if (n == 0) {
                n = 1;
            }
            ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                "slab_alloc#13 n=%d", n);

            /* "n" elements for bitmap, plus one requested */

            for (i = 0; i < (n + 1) / (8 * sizeof(uintptr_t)); i++) {
                bitmap[i] = NGX_SLAB_BUSY;
            }

            m = ((uintptr_t) 1 << ((n + 1) % (8 * sizeof(uintptr_t)))) - 1;
            bitmap[i] = m;
            ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                "slab_alloc#14 i=%d, bitmap[i]=%016XL",
                i, bitmap[i]);

            map = (ngx_pagesize >> shift) / (8 * sizeof(uintptr_t));

            for (i = i + 1; i < map; i++) {
                bitmap[i] = 0;
            }

            page->slab = shift;
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_SMALL;
            ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                "slab_alloc#15 page=%p, page->slab=shift=%d, SLAB_SMALL",
                page, shift);

            slots[slot].next = page;

            pool->stats[slot].total += (ngx_pagesize >> shift) - n;

            p = ngx_slab_page_addr(pool, page) + (n << shift);

            pool->stats[slot].used++;

            goto done;

        } else if (shift == ngx_slab_exact_shift) {

            page->slab = 1;
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_EXACT;
            ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                "slab_alloc#16 page=%p, page->slab=shift=%d, SLAB_EXACT",
                page, shift);

            slots[slot].next = page;

            pool->stats[slot].total += 8 * sizeof(uintptr_t);

            p = ngx_slab_page_addr(pool, page);

            pool->stats[slot].used++;

            goto done;

        } else { /* shift > ngx_slab_exact_shift */

            page->slab = ((uintptr_t) 1 << NGX_SLAB_MAP_SHIFT) | shift;
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_BIG;
            ngx_log_debug3(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                "slab_alloc#17 page=%p, page->slab=%016XL, shift=%d, SLAB_BIG",
                page, page->slab, shift);

            slots[slot].next = page;

            pool->stats[slot].total += ngx_pagesize >> shift;

            p = ngx_slab_page_addr(pool, page);

            pool->stats[slot].used++;

            goto done;
        }
    }

    p = 0;

    pool->stats[slot].fails++;

done:

    ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                   "slab alloc: %p", (void *) p);

    return (void *) p;
}


void *
ngx_slab_calloc(ngx_slab_pool_t *pool, size_t size)
{
    void  *p;

    ngx_shmtx_lock(&pool->mutex);

    p = ngx_slab_calloc_locked(pool, size);

    ngx_shmtx_unlock(&pool->mutex);

    return p;
}


void *
ngx_slab_calloc_locked(ngx_slab_pool_t *pool, size_t size)
{
    void  *p;

    p = ngx_slab_alloc_locked(pool, size);
    if (p) {
        ngx_memzero(p, size);
    }

    return p;
}


void
ngx_slab_free(ngx_slab_pool_t *pool, void *p)
{
    ngx_shmtx_lock(&pool->mutex);

    ngx_slab_free_locked(pool, p);

    ngx_shmtx_unlock(&pool->mutex);
}


void
ngx_slab_free_locked(ngx_slab_pool_t *pool, void *p)
{
    size_t            size;
    uintptr_t         slab, m, *bitmap;
    ngx_uint_t        i, n, type, slot, shift, map;
    ngx_slab_page_t  *slots, *page;

    ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0, "slab free: %p", p);

    if ((u_char *) p < pool->start || (u_char *) p > pool->end) {
        ngx_slab_error(pool, NGX_LOG_ALERT, "ngx_slab_free(): outside of pool");
        goto fail;
    }

    n = ((u_char *) p - pool->start) >> ngx_pagesize_shift;
    page = &pool->pages[n];
    slab = page->slab;
    type = ngx_slab_page_type(page);
    ngx_log_debug3(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
        "slab_free#2 page=%p, slab=%016XL, type=%d",
        page, slab, type);

    switch (type) {

    case NGX_SLAB_SMALL:

        shift = slab & NGX_SLAB_SHIFT_MASK;
        size = (size_t) 1 << shift;
        ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
            "slab_free#3 SMALLL shift=%d, size=%d",
            shift, size);

        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        n = ((uintptr_t) p & (ngx_pagesize - 1)) >> shift;
        m = (uintptr_t) 1 << (n % (8 * sizeof(uintptr_t)));
        n /= 8 * sizeof(uintptr_t);
        bitmap = (uintptr_t *)
                             ((uintptr_t) p & ~((uintptr_t) ngx_pagesize - 1));
        ngx_log_debug3(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
            "slab_free#4 n=%d, bitmap[n]=%016XL, m=%016XL",
            n, bitmap[n], m);

        if (bitmap[n] & m) {
            slot = shift - pool->min_shift;
            ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                "slab_free#5 slot=%d", slot);

            if (page->next == NULL) {
                slots = ngx_slab_slots(pool);

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_SMALL;
                page->next->prev = (uintptr_t) page | NGX_SLAB_SMALL;
                ngx_log_debug4(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                    "slab_free#6 page->next=%p, slots[slot].next=%p, "
                    "page->prev=%016XL, page->next->prev=%016XL",
                    page->next, slots[slot].next,
                    page->prev, page->next->prev);
            }

            bitmap[n] &= ~m;

            n = (ngx_pagesize >> shift) / ((1 << shift) * 8);

            if (n == 0) {
                n = 1;
            }

            i = n / (8 * sizeof(uintptr_t));
            m = ((uintptr_t) 1 << (n % (8 * sizeof(uintptr_t)))) - 1;
            ngx_log_debug3(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                "slab_free#7 i=%d, bitmap[i]=%016XL, m=%016XL",
                i, bitmap[i], m);

            if (bitmap[i] & ~m) {
                goto done;
            }

            map = (ngx_pagesize >> shift) / (8 * sizeof(uintptr_t));

            for (i = i + 1; i < map; i++) {
                ngx_log_debug3(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                    "slab_free#8 i=%d, bitmap[i]=%016XL, map=%d",
                    i, bitmap[i], map);
                if (bitmap[i]) {
                    goto done;
                }
            }

            ngx_slab_free_pages(pool, page, 1);

            pool->stats[slot].total -= (ngx_pagesize >> shift) - n;

            goto done;
        }

        goto chunk_already_free;

    case NGX_SLAB_EXACT:

        m = (uintptr_t) 1 <<
                (((uintptr_t) p & (ngx_pagesize - 1)) >> ngx_slab_exact_shift);
        size = ngx_slab_exact_size;
        ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
            "slab_free#9 EXACT m=%d, size=%d",
            m, size);

        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        if (slab & m) {
            slot = ngx_slab_exact_shift - pool->min_shift;
            ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                "slab_free#10 slot=%d", slot);

            if (slab == NGX_SLAB_BUSY) {
                slots = ngx_slab_slots(pool);

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_EXACT;
                page->next->prev = (uintptr_t) page | NGX_SLAB_EXACT;
                ngx_log_debug4(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                    "slab_free#11 page->next=%p, slots[slot].next=%p, "
                    "page->prev=%016XL, page->next->prev=%016XL",
                    page->next, slots[slot].next,
                    page->prev, page->next->prev);
            }

            page->slab &= ~m;
            ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                "slab_free#12 page->slab=%016XL, m=%016XL", page->slab, m);

            if (page->slab) {
                goto done;
            }

            ngx_slab_free_pages(pool, page, 1);

            pool->stats[slot].total -= 8 * sizeof(uintptr_t);

            goto done;
        }

        goto chunk_already_free;

    case NGX_SLAB_BIG:

        shift = slab & NGX_SLAB_SHIFT_MASK;
        size = (size_t) 1 << shift;
        ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
            "slab_free#13 BIG shift=%d, size=%d",
            shift, size);

        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        m = (uintptr_t) 1 << ((((uintptr_t) p & (ngx_pagesize - 1)) >> shift)
                              + NGX_SLAB_MAP_SHIFT);
        ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
            "slab_free#14 slab=%016XL, m=%016XL", slab, m);

        if (slab & m) {
            slot = shift - pool->min_shift;
            ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                "slab_free#15 slot=%d", slot);

            if (page->next == NULL) {
                slots = ngx_slab_slots(pool);

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_BIG;
                page->next->prev = (uintptr_t) page | NGX_SLAB_BIG;
                ngx_log_debug4(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                    "slab_free#16 page->next=%p, slots[slot].next=%p, "
                    "page->prev=%016XL, page->next->prev=%016XL",
                    page->next, slots[slot].next,
                    page->prev, page->next->prev);
            }

            page->slab &= ~m;
            ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                "slab_free#17 page->slab=%016XL, page->slab&MAP_MASK=%016XL",
                page->slab, page->slab & NGX_SLAB_MAP_MASK);

            if (page->slab & NGX_SLAB_MAP_MASK) {
                goto done;
            }

            ngx_slab_free_pages(pool, page, 1);

            pool->stats[slot].total -= ngx_pagesize >> shift;

            goto done;
        }

        goto chunk_already_free;

    case NGX_SLAB_PAGE:

        if ((uintptr_t) p & (ngx_pagesize - 1)) {
            goto wrong_chunk;
        }

        if (!(slab & NGX_SLAB_PAGE_START)) {
            ngx_slab_error(pool, NGX_LOG_ALERT,
                           "ngx_slab_free(): page is already free");
            goto fail;
        }

        if (slab == NGX_SLAB_PAGE_BUSY) {
            ngx_slab_error(pool, NGX_LOG_ALERT,
                           "ngx_slab_free(): pointer to wrong page");
            goto fail;
        }

        size = slab & ~NGX_SLAB_PAGE_START;

        ngx_slab_free_pages(pool, page, size);

        ngx_slab_junk(p, size << ngx_pagesize_shift);

        return;
    }

    /* not reached */

    return;

done:

    pool->stats[slot].used--;

    ngx_slab_junk(p, size);

    return;

wrong_chunk:

    ngx_slab_error(pool, NGX_LOG_ALERT,
                   "ngx_slab_free(): pointer to wrong chunk");

    goto fail;

chunk_already_free:

    ngx_slab_error(pool, NGX_LOG_ALERT,
                   "ngx_slab_free(): chunk is already free");

fail:

    return;
}


static ngx_slab_page_t *
ngx_slab_alloc_pages(ngx_slab_pool_t *pool, ngx_uint_t pages)
{
    ngx_slab_page_t  *page, *p;

    for (page = pool->free.next; page != &pool->free; page = page->next) {

        if (page->slab >= pages) {

            if (page->slab > pages) {
                page[page->slab - 1].prev = (uintptr_t) &page[pages];

                page[pages].slab = page->slab - pages;
                page[pages].next = page->next;
                page[pages].prev = page->prev;
                ngx_log_debug7(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                    "slab_alloc_pages#1 page=%p, page->slab=%016XL > pages=%d, "
                    "pages[page->slab - 1].prev=%016XL, "
                    "page[pages].slab=%016XL, "
                    "page[pages].next=%p, "
                    "page[pages].prev=%016XL, ",
                    page, page->slab, pages,
                    page[page->slab - 1].prev,
                    page[pages].slab,
                    page[pages].next,
                    page[pages].prev);

                p = (ngx_slab_page_t *) page->prev;
                p->next = &page[pages];
                page->next->prev = (uintptr_t) &page[pages];
                ngx_log_debug4(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                    "slab_alloc_pages#2 p=page->prev=%p, "
                    "p->next=%p, "
                    "page->next=%p, "
                    "page->next->prev=%p",
                    p,
                    p->next,
                    page->next,
                    page->next->prev);

            } else {
                p = (ngx_slab_page_t *) page->prev;
                p->next = page->next;
                page->next->prev = page->prev;
                ngx_log_debug7(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                    "slab_alloc_pages#3 page=%p, "
                    "page->slab=%016XL == pages=%d, "
                    "p=page->prev=%p, "
                    "p->next=%p, "
                    "page->next=%p, "
                    "page->next->prev=%p",
                    page, page->slab, pages,
                    p,
                    p->next,
                    page->next,
                    page->next->prev);
            }

            page->slab = pages | NGX_SLAB_PAGE_START;
            page->next = NULL;
            page->prev = NGX_SLAB_PAGE;

            pool->pfree -= pages;
            ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                "slab_alloc_pages#4 page->slab=%016XL, page->next=NULL, "
                "page->prev=SLAB_PAGE, pool->pfree=%d",
                page->slab, pool->pfree);

            if (--pages == 0) {
                return page;
            }

            for (p = page + 1; pages; pages--) {
                p->slab = NGX_SLAB_PAGE_BUSY;
                p->next = NULL;
                p->prev = NGX_SLAB_PAGE;
                ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                    "slab_alloc_pages#5 p=%p, p->slab=PAGE_BUSY, "
                    "p->next=NULL, p->prev=SLAB_PAGE",
                    p);
                p++;
            }

            return page;
        }
    }

    if (pool->log_nomem) {
        ngx_slab_error(pool, NGX_LOG_CRIT,
                       "ngx_slab_alloc() failed: no memory");
    }

    return NULL;
}


static void
ngx_slab_free_pages(ngx_slab_pool_t *pool, ngx_slab_page_t *page,
    ngx_uint_t pages)
{
    ngx_slab_page_t  *prev, *join;

    pool->pfree += pages;

    page->slab = pages--;
    ngx_log_debug5(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
        "slab_free_pages#1 page=%p, pages=%d, pfree=%d, page->slab=%016XL, "
        "page->next=%p",
        page, pages, pool->pfree, page->slab, page->next);

    if (pages) {
        ngx_memzero(&page[1], pages * sizeof(ngx_slab_page_t));
    }

    if (page->next) {
        prev = ngx_slab_page_prev(page);
        prev->next = page->next;
        page->next->prev = page->prev;
        ngx_log_debug3(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
            "slab_free_pages#2 prev=%p, prev->next=%p, prev->next->prev=%016XL",
            prev, prev->next, page->next->prev);
    }

    join = page + page->slab;
    ngx_log_debug3(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
        "slab_free_pages#3 join=%p, pool->last=%p, join < pool->last=%d",
        join, pool->last, join < pool->last);

    if (join < pool->last) {

        if (ngx_slab_page_type(join) == NGX_SLAB_PAGE) {

            if (join->next != NULL) {
                pages += join->slab;
                page->slab += join->slab;
                ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                    "slab_free_pages#4 pages=%d, page->slab=%016XL",
                    pages, page->slab);

                prev = ngx_slab_page_prev(join);
                prev->next = join->next;
                join->next->prev = join->prev;
                ngx_log_debug3(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                    "slab_free_pages#5 prev=%p, prev->next=%p, "
                    "join->next->prev=%016XL",
                    prev, prev->next, join->next->prev);

                join->slab = NGX_SLAB_PAGE_FREE;
                join->next = NULL;
                join->prev = NGX_SLAB_PAGE;
            }
        }
    }

    if (page > pool->pages) {
        join = page - 1;
        ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
            "slab_free_pages#6 join=%p, join page type=%d",
            join, ngx_slab_page_type(join));

        if (ngx_slab_page_type(join) == NGX_SLAB_PAGE) {

            if (join->slab == NGX_SLAB_PAGE_FREE) {
                join = ngx_slab_page_prev(join);
                ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                    "slab_free_pages#7 join=%p", join);
            }

            if (join->next != NULL) {
                pages += join->slab;
                join->slab += page->slab;
                ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                    "slab_free_pages#8 pages=%d, join->slab=%016XL",
                    pages, join->slab);

                prev = ngx_slab_page_prev(join);
                prev->next = join->next;
                join->next->prev = join->prev;
                ngx_log_debug3(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                    "slab_free_pages#9 prev=%p, prev->next=%p, "
                    "join->next->prev=%016XL",
                    prev, prev->next, join->next->prev);

                page->slab = NGX_SLAB_PAGE_FREE;
                page->next = NULL;
                page->prev = NGX_SLAB_PAGE;

                page = join;
            }
        }
    }

    if (pages) {
        page[pages].prev = (uintptr_t) page;
        ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
            "slab_free_pages#10 pages=%d, page[pages].prev=%016XL",
            pages, page[pages].prev);
    }

    page->prev = (uintptr_t) &pool->free;
    page->next = pool->free.next;

    page->next->prev = (uintptr_t) page;

    pool->free.next = page;
    ngx_log_debug5(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
        "slab_free_pages#11 page=%p, page->prev=%016XL, page->next=%p, "
        "page->next->prev=%016XL, pool->free.next=%p",
        page, page->prev, page->next,
        page->next->prev, pool->free.next);
}


static void
ngx_slab_error(ngx_slab_pool_t *pool, ngx_uint_t level, char *text)
{
    ngx_log_error(level, ngx_cycle->log, 0, "%s%s", text, pool->log_ctx);
}
