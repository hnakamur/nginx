
/*
 * Copyright (C) Hiroaki Nakamura
 */


#ifndef _LIBNGINX_H_INCLUDED_
#define _LIBNGINX_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#ifdef LIBNGINX

extern ngx_int_t     libnginx_debug_points;

int libnginx_init(const char *prefix, const char *error_log,
                  unsigned log_level, ngx_uint_t use_stderr,
                  ngx_cycle_t **cycle);
ngx_int_t libnginx_init_shm_pool(ngx_cycle_t *cycle, ngx_shm_t *shm);
int libnginx_slab_init_size(ngx_slab_pool_t *pool, size_t pool_size);

#endif


#endif /* _LIBNGINX_H_INCLUDED_ */
