
/*
 * Copyright (C) Hiroaki Nakamura
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <nginx.h>

#ifdef LIBNGINX

/* Copied from src/core/ngx_cycle.c */
volatile ngx_cycle_t  *ngx_cycle;

/* Copied from src/os/unix/ngx_process_cycle.c */
ngx_pid_t     ngx_pid;
ngx_pid_t     ngx_parent;

ngx_int_t     libnginx_debug_points = NGX_DEBUG_POINTS_STOP;

ngx_cycle_t   init_cycle;

int libnginx_init(const char *prefix, const char *error_log, unsigned log_level, ngx_uint_t use_stderr)
{
    int               ret;
    ngx_log_t        *log;

    ngx_debug_init();
    ret = ngx_strerror_init();
    if (ret != NGX_OK) {
        return ret;
    }

    ngx_time_init();

    ngx_pid = ngx_getpid();
    ngx_parent = ngx_getppid();

    log = ngx_log_init((u_char *) prefix, (u_char *) error_log);
    log->log_level = log_level;
    ngx_use_stderr = use_stderr;

    ngx_memzero(&init_cycle, sizeof(ngx_cycle_t));
    init_cycle.log = log;
    ngx_cycle = &init_cycle;

    ret = ngx_os_init(log);
    if (ret != NGX_OK) {
        return ret;
    }

    /*
     * ngx_crc32_table_init() requires ngx_cacheline_size set in ngx_os_init()
     */

    if (ngx_crc32_table_init() != NGX_OK) {
        return 1;
    }

    ngx_slab_sizes_init();

    return NGX_OK;
}

ngx_int_t
libnginx_init_shm_pool(ngx_cycle_t *cycle, ngx_shm_t *shm)
{
    u_char           *file;
    ngx_slab_pool_t  *sp;

    sp = (ngx_slab_pool_t *) shm->addr;

    if (shm->exists) {

        if (sp == sp->addr) {
            return NGX_OK;
        }

#if (NGX_WIN32)

        /* remap at the required address */

        if (ngx_shm_remap(&zn->shm, sp->addr) != NGX_OK) {
            return NGX_ERROR;
        }

        sp = (ngx_slab_pool_t *) shm->addr;

        if (sp == sp->addr) {
            return NGX_OK;
        }

#endif

        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "shared zone \"%V\" has no equal addresses: %p vs %p",
                      &shm->name, sp->addr, sp);
        return NGX_ERROR;
    }

    sp->end = shm->addr + shm->size;
    sp->min_shift = 3;
    sp->addr = shm->addr;

#if (NGX_HAVE_ATOMIC_OPS)

    file = NULL;

#else

    file = ngx_pnalloc(cycle->pool,
                       cycle->lock_file.len + shm->name.len + 1);
    if (file == NULL) {
        return NGX_ERROR;
    }

    (void) ngx_sprintf(file, "%V%V%Z", &cycle->lock_file, &shm->name);

#endif

    if (ngx_shmtx_create(&sp->mutex, &sp->lock, file) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_slab_init(sp);

    return NGX_OK;
}

int
libnginx_slab_init_size(ngx_slab_pool_t *pool, size_t pool_size)
{
    pool->end = (u_char *) pool + pool_size;
    pool->min_shift = 3;
    pool->addr = pool;
    if (ngx_shmtx_create(&pool->mutex, &pool->lock, NULL) != NGX_OK) {
        return NGX_ERROR;
    }
    ngx_slab_init(pool);
    return NGX_OK;
}

/* ngx_debug_point copied from src/os/unix/ngx_process.c and modified. */
void
ngx_debug_point(void)
{
    switch (libnginx_debug_points) {

    case NGX_DEBUG_POINTS_STOP:
        raise(SIGSTOP);
        break;

    case NGX_DEBUG_POINTS_ABORT:
        ngx_abort();
    }
}
#endif
