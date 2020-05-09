
/*
 * Copyright (C) Hiroaki Nakamura
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <nginx.h>

#ifdef LIBNGINX

int libnginx_init(const char *log_filename, unsigned log_level, ngx_uint_t use_stderr)
{
    ngx_debug_init();
    int ret = ngx_strerror_init();
    if (ret != NGX_OK) {
        return ret;
    }
    ngx_time_init();

    ngx_pid = ngx_getpid();
    ngx_parent = ngx_getppid();

    ngx_log_t *log = ngx_log_init_name((u_char *) log_filename);
    log->log_level = log_level;
    ngx_use_stderr = use_stderr;

    ngx_cycle_t init_cycle;
    ngx_memzero(&init_cycle, sizeof(ngx_cycle_t));
    init_cycle.log = log;
    ngx_cycle = &init_cycle;

    ret = ngx_os_init(log);
    if (ret != NGX_OK) {
        return ret;
    }
    ngx_slab_sizes_init();

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

#endif
