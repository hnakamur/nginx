
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
