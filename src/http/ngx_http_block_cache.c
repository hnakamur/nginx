
/*
 * Copyright (C) Hiroaki Nakamura
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static void ngx_http_block_cache_calc_segments(ngx_http_block_cache_t *cache);

static ngx_int_t
ngx_http_block_cache_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_block_cache_t  *ocache = data;

    size_t                   len;
    ngx_http_block_cache_t  *cache;

    cache = shm_zone->data;

    ngx_log_error(NGX_LOG_NOTICE, shm_zone->shm.log, 0,
                          "block cache \"%V\" current cache path:\"%V\" "
                          "ocache=%p",
                          &shm_zone->shm.name, &cache->path->name,
                          ocache);

    if (ocache) {
        if (ngx_strcmp(cache->path->name.data, ocache->path->name.data) != 0) {
            ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                          "block cache \"%V\" uses the \"%V\" cache path "
                          "while previously it used the \"%V\" cache path",
                          &shm_zone->shm.name, &cache->path->name,
                          &ocache->path->name);

            return NGX_ERROR;
        }

        cache->shpool = ocache->shpool;

        return NGX_OK;
    }

    cache->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        return NGX_OK;
    }

    len = sizeof(" in block cache keys zone \"\"") + shm_zone->shm.name.len;

    cache->shpool->log_ctx = ngx_slab_alloc(cache->shpool, len);
    if (cache->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(cache->shpool->log_ctx, " in block cache keys zone \"%V\"%Z",
                &shm_zone->shm.name);

    cache->shpool->log_nomem = 0;

    return NGX_OK;
}

char *
ngx_http_block_cache_set_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *confp = conf;

    off_t                    zone_size, storage_size, min_average_object_size,
                             storage_skip, block_size;
    u_char                  *p;
    ngx_str_t                s, zone_name, *value;
    ngx_uint_t               i;
    ngx_array_t             *block_caches;
    ngx_http_block_cache_t  *cache, **ce;

    /*
     * We use notice log here since ngx_log_debugX does not seem to work here.
     * Maybe it is not initialized yet.
     */
    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                   "ngx_http_block_cache_set_slot start");

    cache = ngx_pcalloc(cf->pool, sizeof(ngx_http_block_cache_t));
    if (cache == NULL) {
        return NGX_CONF_ERROR;
    }

    cache->path = ngx_pcalloc(cf->pool, sizeof(ngx_path_t));
    if (cache->path == NULL) {
        return NGX_CONF_ERROR;
    }

    storage_size = 0;
    storage_skip = 0;
    min_average_object_size = 8000;
    block_size = 4 * 1024 * 1024;
    zone_size = 0;

    value = cf->args->elts;

    cache->path->name = value[1];

    if (cache->path->name.data[cache->path->name.len - 1] == '/') {
        cache->path->name.len--;
    }

    if (ngx_conf_full_name(cf->cycle, &cache->path->name, 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "storage_size=", 13) == 0) {

            s.len = value[i].len - 13;
            s.data = value[i].data + 13;

            storage_size = ngx_parse_offset(&s);
            if (storage_size <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid storage_size value \"%V\"",
                                   &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "min_average_object_size=", 24) == 0) {

            s.len = value[i].len - 24;
            s.data = value[i].data + 24;

            min_average_object_size = ngx_parse_offset(&s);
            if (min_average_object_size <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid min_average_object_size value"
                                   " \"%V\"",
                                   &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "storage_skip=", 13) == 0) {

            s.len = value[i].len - 13;
            s.data = value[i].data + 13;

            storage_skip = ngx_parse_offset(&s);
            if (storage_skip < 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid storage_skip value \"%V\"",
                                   &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "block_size=", 11) == 0) {

            s.len = value[i].len - 11;
            s.data = value[i].data + 11;

            block_size = ngx_parse_offset(&s);
            if (block_size <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid block_size value \"%V\"",
                                   &value[i]);
                return NGX_CONF_ERROR;
            }

            if (block_size % ngx_pagesize != 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid block_size value \"%V\""
                                   ", must be multiple of page size %i",
                                   &value[i], ngx_pagesize);
                return NGX_CONF_ERROR;
            }

            if (ngx_align(1, block_size) != block_size) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid block_size value \"%V\""
                                   ", must be power of two",
                                   &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {

            zone_name.data = value[i].data + 5;

            p = (u_char *) ngx_strchr(zone_name.data, ':');

            if (p == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            zone_name.len = p - zone_name.data;

            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;

            zone_size = ngx_parse_offset(&s);

            if (zone_size <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

    }

    if (zone_name.len == 0 || zone_size == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                  "block cache \"%V\", storage_size:%O"
                  ", min_average_object_size:%O, storage_skip:%O"
                  ", block_size:%O, zone_size:%O",
                  &zone_name, storage_size,
                  min_average_object_size, storage_skip,
                  block_size, zone_size);

    if (storage_size == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"storage_size\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    cache->storage_size = storage_size;
    cache->storage_start = cache->storage_skip = storage_skip;
    cache->min_average_object_size = min_average_object_size;
    cache->block_size = block_size;

    ngx_http_block_cache_calc_segments(cache);

    cache->path->data = cache;
    cache->path->conf_file = cf->conf_file->file.name.data;
    cache->path->line = cf->conf_file->line;

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                  "http block cache: %V",
                  &cache->path->name);

    if (ngx_add_path(cf, &cache->path) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    cache->shm_zone = ngx_shared_memory_add(cf, &zone_name, zone_size,
                                            cmd->post);
    if (cache->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (cache->shm_zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate zone \"%V\"", &zone_name);
        return NGX_CONF_ERROR;
    }


    cache->shm_zone->init = ngx_http_block_cache_init;
    cache->shm_zone->data = cache;

    block_caches = (ngx_array_t *) (confp + cmd->offset);

    ce = ngx_array_push(block_caches);
    if (ce == NULL) {
        return NGX_CONF_ERROR;
    }

    *ce = cache;

    return NGX_CONF_OK;
}

static off_t
ngx_http_block_cache_calc_dir_size(ngx_http_block_cache_t *cache) {
    return ngx_align(cache->segments * NGX_HTTP_BLOCK_CACHE_SEGMENT_SIZE,
                     cache->block_size);
}

#define ngx_roundup(d, a)  (((d) + ((a) - 1)) / (a))

static void
ngx_http_block_cache_calc_segments_one_step(ngx_http_block_cache_t *cache) {
    ngx_uint_t  total_entries;

    total_entries = (cache->storage_size - cache->storage_start)
                    / cache->min_average_object_size;
    cache->segments = ngx_roundup(total_entries,
                                  NGX_HTTP_BLOCK_CACHE_ENTRIES_IN_SEGMENT);
    cache->storage_start = cache->storage_skip
                           + 2 * ngx_http_block_cache_calc_dir_size(cache);
    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                  "http block cache: %V, calc one step, segments:%i"
                  ", storage_start:%O",
                  &cache->path->name, cache->segments, cache->storage_start);
}

static void
ngx_http_block_cache_calc_segments(ngx_http_block_cache_t *cache) {
    ngx_http_block_cache_calc_segments_one_step(cache);
    ngx_http_block_cache_calc_segments_one_step(cache);
    ngx_http_block_cache_calc_segments_one_step(cache);
}
