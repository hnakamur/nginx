
/*
 * Copyright (C) Hiroaki Nakamura
 */


#ifndef _LIBNGINX_H_INCLUDED_
#define _LIBNGINX_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#ifdef LIBNGINX

int libnginx_init(const char *log_filename, unsigned log_level, ngx_uint_t use_stderr);
int libnginx_slab_init_size(ngx_slab_pool_t *pool, size_t pool_size);

#endif


#endif /* _LIBNGINX_H_INCLUDED_ */
