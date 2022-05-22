
/*
 * Copyright (C) Hiroaki Nakamura
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static off_t ngx_http_block_cache_calc_dir_size(
    const ngx_http_block_cache_t *cache);
static void ngx_http_block_cache_calc_segments(ngx_http_block_cache_t *cache);
static void ngx_http_block_cache_dir_init(ngx_http_block_cache_dir_t *dir);
static ngx_inline ngx_http_block_cache_segment_t *
    ngx_http_block_cache_dir_segment(const ngx_http_block_cache_dir_t *dir,
        ngx_uint_t i);
static ngx_inline ngx_uint_t ngx_http_block_cache_dir_key_hash_segment(
    const ngx_http_block_cache_dir_t *dir,
    const ngx_http_block_cache_key_hash_t *h);
static void ngx_http_block_cache_segment_init(
    ngx_http_block_cache_segment_t *seg);
static void ngx_http_block_segment_free_entry(
    ngx_http_block_cache_segment_t *seg,
    ngx_http_block_cache_entry_id_t ei);
static void ngx_http_block_segment_unlink_from_freelist(
    ngx_http_block_cache_segment_t *seg, ngx_http_block_cache_entry_id_t ei);
static ngx_http_block_cache_entry_id_t ngx_http_block_segment_delete_entry(
    ngx_http_block_cache_segment_t *seg, ngx_http_block_cache_entry_id_t ei,
    ngx_http_block_cache_entry_id_t pi);
static void ngx_http_block_segment_clean(ngx_http_block_cache_segment_t *seg);
static void ngx_http_block_segment_clean_bucket(
    ngx_http_block_cache_segment_t *seg, ngx_uint_t bi);
static void ngx_http_block_segment_clean_freelist(
    ngx_http_block_cache_segment_t *seg);
static ngx_http_block_cache_entry_id_t
    ngx_http_block_segment_pop_freelist(ngx_http_block_cache_segment_t *seg);
static ngx_inline ngx_uint_t ngx_http_block_cache_key_hash_bucket(
    const ngx_http_block_cache_key_hash_t *h);
static ngx_inline ngx_http_block_cache_tag_t
    ngx_http_block_cache_key_hash_tag(const ngx_http_block_cache_key_hash_t *h);
static ngx_inline ngx_http_block_cache_page_id_t
    ngx_http_block_cache_entry_page(const ngx_http_block_cache_entry_t *e);
static ngx_inline void ngx_http_block_cache_entry_set_page(
    ngx_http_block_cache_entry_t *e, ngx_http_block_cache_page_id_t page);
static ngx_inline ngx_flag_t ngx_http_block_cache_entry_is_empty(
    const ngx_http_block_cache_entry_t *e);
static ngx_inline void ngx_http_block_cache_entry_set_empty(
    ngx_http_block_cache_entry_t *e);
static ngx_inline ngx_flag_t ngx_http_block_cache_entry_is_head(
    const ngx_http_block_cache_entry_t *e);
static ngx_inline void ngx_http_block_cache_entry_set_head(
    ngx_http_block_cache_entry_t *e, ngx_flag_t head);
static ngx_inline ngx_http_block_cache_tag_t
    ngx_http_block_cache_entry_tag(const ngx_http_block_cache_entry_t *e);
static ngx_inline void ngx_http_block_cache_entry_set_tag(
    ngx_http_block_cache_entry_t *e, ngx_http_block_cache_tag_t tag);
static ngx_inline ngx_http_block_cache_entry_id_t
    ngx_http_block_cache_entry_next(const ngx_http_block_cache_entry_t *e);
static ngx_inline void ngx_http_block_cache_entry_set_next(
    ngx_http_block_cache_entry_t *e, ngx_http_block_cache_entry_id_t ei);
static ngx_inline ngx_http_block_cache_entry_id_t
    ngx_http_block_cache_entry_prev(const ngx_http_block_cache_entry_t *e);
static ngx_inline void ngx_http_block_cache_entry_set_prev(
    ngx_http_block_cache_entry_t *e, ngx_http_block_cache_entry_id_t ei);
static ngx_inline void ngx_http_block_cache_entry_copy_data_from(
    ngx_http_block_cache_entry_t *dst, const ngx_http_block_cache_entry_t *src);
static ngx_inline void ngx_http_block_cache_entry_copy_from(
    ngx_http_block_cache_entry_t *dst, const ngx_http_block_cache_entry_t *src);
static ngx_inline void ngx_http_block_cache_entry_clear(
    ngx_http_block_cache_entry_t *e);
static ngx_inline ngx_flag_t ngx_http_block_cache_entry_equal(
    const ngx_http_block_cache_entry_t *e,
    const ngx_http_block_cache_entry_t *other);


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

    cache->sh = ngx_slab_alloc(cache->shpool, sizeof(ngx_http_block_cache_sh_t));
    if (cache->sh == NULL) {
        return NGX_ERROR;
    }

    cache->shpool->data = cache->sh;

    cache->sh->dir.segments = cache->segments;
    cache->sh->dir.size = ngx_http_block_cache_calc_dir_size(cache);
    cache->sh->dir.bytes = ngx_slab_alloc(cache->shpool, cache->sh->dir.size);
    if (cache->sh->dir.bytes == NULL) {
        return NGX_ERROR;
    }

    ngx_http_block_cache_dir_init(&cache->sh->dir);

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

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                  "http block cache calc final: %V, segments:%i"
                  ", storage_start:%O, dir_size:%O",
                  &cache->path->name, cache->segments, cache->storage_start,
                  ngx_http_block_cache_calc_dir_size(cache));

    cache->path->data = cache;
    cache->path->conf_file = cf->conf_file->file.name.data;
    cache->path->line = cf->conf_file->line;

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
ngx_http_block_cache_calc_dir_size(const ngx_http_block_cache_t *cache)
{
    return ngx_align(cache->segments * NGX_HTTP_BLOCK_CACHE_SEGMENT_SIZE,
                     cache->block_size);
}


#define ngx_roundup(d, a)  (((d) + ((a) - 1)) / (a))


static void
ngx_http_block_cache_calc_segments_one_step(ngx_http_block_cache_t *cache)
{
    ngx_uint_t  total_entries;

    total_entries = (cache->storage_size - cache->storage_start)
                    / cache->min_average_object_size;
    cache->segments = ngx_roundup(total_entries,
                                  NGX_HTTP_BLOCK_CACHE_ENTRIES_IN_SEGMENT);
    cache->storage_start = cache->storage_skip
                           + 2 * ngx_http_block_cache_calc_dir_size(cache);
    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                  "http block cache calc one step: %V, segments:%i"
                  ", storage_start:%O",
                  &cache->path->name, cache->segments, cache->storage_start);
}


static void
ngx_http_block_cache_calc_segments(ngx_http_block_cache_t *cache)
{
    ngx_http_block_cache_calc_segments_one_step(cache);
    ngx_http_block_cache_calc_segments_one_step(cache);
    ngx_http_block_cache_calc_segments_one_step(cache);
}


static void
ngx_http_block_cache_dir_init(ngx_http_block_cache_dir_t *dir)
{
    ngx_uint_t                       i;
    ngx_http_block_cache_segment_t  *seg;

    for (i = 0; i < dir->segments; i++) {
        seg = ngx_http_block_cache_dir_segment(dir, i);
        ngx_http_block_cache_segment_init(seg);
    }
}


void
ngx_http_block_cache_dir_insert_entry(ngx_http_block_cache_dir_t *dir,
    const ngx_http_block_cache_key_hash_t *key,
    const ngx_http_block_cache_entry_t *to_part)
{
    ngx_http_block_cache_segment_t   *seg;
    ngx_uint_t                        si, bi, lvl;
    ngx_http_block_cache_entry_id_t   bei, ei;
    ngx_http_block_cache_entry_t     *e, *be;

    si = ngx_http_block_cache_dir_key_hash_segment(dir, key);
    seg = ngx_http_block_cache_dir_segment(dir, si);
    bi = ngx_http_block_cache_key_hash_bucket(key);
    bei = bi * NGX_HTTP_BLOCK_CACHE_ENTRIES_IN_BUCKET;

again:

    ei = bei;
    e = &seg->entries[ei];
    if (ngx_http_block_cache_entry_is_empty(e)) {
        goto fill;
    }
    for (lvl = 1; lvl < NGX_HTTP_BLOCK_CACHE_ENTRIES_IN_BUCKET; lvl++) {
        ei = bei + lvl;
        e = &seg->entries[ei];
        if (ngx_http_block_cache_entry_is_empty(e)) {
            ngx_http_block_segment_unlink_from_freelist(seg, ei);
            goto link;
        }
    }
    ei = ngx_http_block_segment_pop_freelist(seg);
    if (e == NGX_HTTP_BLOCK_CACHE_EMPTY_ENTRY_ID) {
        goto again;
    }

link:

    be = &seg->entries[bei];
    ngx_http_block_cache_entry_set_next(e, ngx_http_block_cache_entry_next(be));
    ngx_http_block_cache_entry_set_next(be, ei);

fill:

    ngx_http_block_cache_entry_copy_data_from(e, to_part);
    ngx_http_block_cache_entry_set_tag(e,
                                       ngx_http_block_cache_key_hash_tag(key));
    dir->dirty = 1;
}


ngx_flag_t
ngx_http_block_cache_dir_overwrite_entry(ngx_http_block_cache_dir_t *dir,
    const ngx_http_block_cache_key_hash_t *key,
    const ngx_http_block_cache_entry_t *new,
    const ngx_http_block_cache_entry_t *old,
    ngx_flag_t must_overwrite)
{
    ngx_http_block_cache_segment_t   *seg;
    ngx_uint_t                        si, bi, lvl;
    ngx_http_block_cache_entry_id_t   bei, ei;
    ngx_http_block_cache_entry_t     *e, *be;
    ngx_http_block_cache_tag_t        tag;
    ngx_http_block_cache_page_id_t    old_page;
    ngx_flag_t                        res;

    res = 1;
    si = ngx_http_block_cache_dir_key_hash_segment(dir, key);
    seg = ngx_http_block_cache_dir_segment(dir, si);
    bi = ngx_http_block_cache_key_hash_bucket(key);
    bei = bi * NGX_HTTP_BLOCK_CACHE_ENTRIES_IN_BUCKET;
    tag = ngx_http_block_cache_key_hash_tag(key);
    old_page = ngx_http_block_cache_entry_page(old);

again:

    ei = bei;
    e = &seg->entries[ei];
    if (!ngx_http_block_cache_entry_is_empty(e)) {
        for ( ;; ) {
            if (ngx_http_block_cache_entry_tag(e) == tag
                && ngx_http_block_cache_entry_page(e) == old_page)
            {
                goto fill;
            }
            ei = ngx_http_block_cache_entry_next(e);
            if (ei == NGX_HTTP_BLOCK_CACHE_EMPTY_ENTRY_ID) {
                break;
            }
            e = &seg->entries[ei];
        }
    }
    if (must_overwrite) {
        return 0;
    }
    res = 0;
    ei = bei;
    e = &seg->entries[ei];
    if (ngx_http_block_cache_entry_is_empty(e)) {
        goto fill;
    }
    for (lvl = 1; lvl < NGX_HTTP_BLOCK_CACHE_ENTRIES_IN_BUCKET; lvl++) {
        ei = bei + lvl;
        e = &seg->entries[ei];
        if (ngx_http_block_cache_entry_is_empty(e)) {
            goto link;
        }
    }
    ei = ngx_http_block_segment_pop_freelist(seg);
    if (e == NGX_HTTP_BLOCK_CACHE_EMPTY_ENTRY_ID) {
        goto again;
    }

link:

    be = &seg->entries[bei];
    ngx_http_block_cache_entry_set_next(e, ngx_http_block_cache_entry_next(be));
    ngx_http_block_cache_entry_set_next(be, ei);

fill:

    ngx_http_block_cache_entry_copy_data_from(e, new);
    ngx_http_block_cache_entry_set_tag(e, tag);
    dir->dirty = 1;
    return res;
}


ngx_flag_t
ngx_http_block_cache_dir_delete_entry(ngx_http_block_cache_dir_t *dir,
    const ngx_http_block_cache_key_hash_t *key,
    const ngx_http_block_cache_entry_t *del)
{
    ngx_http_block_cache_segment_t   *seg;
    ngx_uint_t                        si, bi;
    ngx_http_block_cache_entry_id_t   ei, pi;
    ngx_http_block_cache_entry_t     *e;
    ngx_http_block_cache_tag_t        tag;
    ngx_http_block_cache_page_id_t    page;

    si = ngx_http_block_cache_dir_key_hash_segment(dir, key);
    seg = ngx_http_block_cache_dir_segment(dir, si);
    bi = ngx_http_block_cache_key_hash_bucket(key);
    tag = ngx_http_block_cache_key_hash_tag(key);
    page = ngx_http_block_cache_entry_page(del);
    pi = NGX_HTTP_BLOCK_CACHE_EMPTY_ENTRY_ID;

    ei = bi * NGX_HTTP_BLOCK_CACHE_ENTRIES_IN_BUCKET;
    e = &seg->entries[ei];
    if (!ngx_http_block_cache_entry_is_empty(e)) {
        for ( ;; ) {
            if (ngx_http_block_cache_entry_tag(e) == tag
                && ngx_http_block_cache_entry_page(e) == page)
            {
                ngx_http_block_segment_delete_entry(seg, ei, pi);
                return 1;
            }
            pi = ei;
            ei = ngx_http_block_cache_entry_next(e);
            if (ei == NGX_HTTP_BLOCK_CACHE_EMPTY_ENTRY_ID) {
                break;
            }
            e = &seg->entries[ei];
        }
    }
    return 0;
}


static ngx_inline ngx_http_block_cache_segment_t *
ngx_http_block_cache_dir_segment(const ngx_http_block_cache_dir_t *dir,
    ngx_uint_t si)
{
    return (ngx_http_block_cache_segment_t *)
           (dir->bytes + si * NGX_HTTP_BLOCK_CACHE_SEGMENT_SIZE);
}


static ngx_inline ngx_uint_t
ngx_http_block_cache_dir_key_hash_segment(const ngx_http_block_cache_dir_t *dir,
    const ngx_http_block_cache_key_hash_t *key)
{
    return key->u32[0] % dir->segments;
}


static void
ngx_http_block_cache_segment_init(ngx_http_block_cache_segment_t *seg)
{
    ngx_uint_t                        lvl, bi;
    ngx_http_block_cache_entry_id_t   ei;

    for (lvl = 1; lvl < NGX_HTTP_BLOCK_CACHE_ENTRIES_IN_BUCKET; lvl++) {
        for (bi = 0; bi < NGX_HTTP_BLOCK_CACHE_BUCKETS_IN_SEGMENT; bi++) {
            ei = bi * NGX_HTTP_BLOCK_CACHE_BUCKETS_IN_SEGMENT + lvl;
            ngx_http_block_segment_free_entry(seg, ei);
        }
    }
}


static void
ngx_http_block_segment_free_entry(ngx_http_block_cache_segment_t *seg,
    ngx_http_block_cache_entry_id_t ei)
{
    ngx_http_block_cache_entry_t     *e;
    ngx_http_block_cache_entry_id_t   fi;

    e = &seg->entries[ei];
    fi = seg->freelist;
    ngx_http_block_cache_entry_set_next(e, fi);
    if (fi != NGX_HTTP_BLOCK_CACHE_EMPTY_ENTRY_ID) {
        ngx_http_block_cache_entry_set_prev(&seg->entries[fi], ei);
    }
    seg->freelist = ei;
}


static void
ngx_http_block_segment_unlink_from_freelist(ngx_http_block_cache_segment_t *seg,
    ngx_http_block_cache_entry_id_t ei)
{
    ngx_http_block_cache_entry_t     *e;
    ngx_http_block_cache_entry_id_t   ni, pi;

    e = &seg->entries[ei];
    ni = ngx_http_block_cache_entry_next(e);
    pi = ngx_http_block_cache_entry_prev(e);
    if (pi != NGX_HTTP_BLOCK_CACHE_EMPTY_ENTRY_ID) {
        ngx_http_block_cache_entry_set_next(&seg->entries[pi], ni);
    } else {
        seg->freelist = ni;
    }
    if (ni != NGX_HTTP_BLOCK_CACHE_EMPTY_ENTRY_ID) {
        ngx_http_block_cache_entry_set_prev(&seg->entries[ni], pi);
    }
}


/*
 * take entry index and previous index, delete the entry, and returns the
 * next entry index.
 */
static ngx_http_block_cache_entry_id_t
ngx_http_block_segment_delete_entry(ngx_http_block_cache_segment_t *seg,
    ngx_http_block_cache_entry_id_t ei, ngx_http_block_cache_entry_id_t pi)
{
    ngx_http_block_cache_entry_t     *e, *p;
    ngx_http_block_cache_entry_id_t   ni, fi;

    e = &seg->entries[ei];
    ni = ngx_http_block_cache_entry_next(e);
    if (pi != NGX_HTTP_BLOCK_CACHE_EMPTY_ENTRY_ID) {
        p = &seg->entries[pi];
        ngx_http_block_cache_entry_clear(e);
        ngx_http_block_cache_entry_set_next(p, ni);
        fi = seg->freelist;
        ngx_http_block_cache_entry_set_next(e, fi);
        if (fi != NGX_HTTP_BLOCK_CACHE_EMPTY_ENTRY_ID) {
            ngx_http_block_cache_entry_set_prev(&seg->entries[fi], ei);
        }
        seg->freelist = ei;
        return ni;
    }

    if (ni != NGX_HTTP_BLOCK_CACHE_EMPTY_ENTRY_ID) {
        ngx_http_block_cache_entry_copy_from(e, &seg->entries[ni]);
        ngx_http_block_segment_delete_entry(seg, ni, ei);
        return ei;
    }

    ngx_http_block_cache_entry_clear(e);
    return NGX_HTTP_BLOCK_CACHE_EMPTY_ENTRY_ID;
}


static void
ngx_http_block_segment_clean(ngx_http_block_cache_segment_t *seg)
{
    ngx_uint_t  bi;

    for (bi = 0; bi < NGX_HTTP_BLOCK_CACHE_BUCKETS_IN_SEGMENT; bi++) {
        ngx_http_block_segment_clean_bucket(seg, bi);
    }
}


static void
ngx_http_block_segment_clean_bucket(ngx_http_block_cache_segment_t *seg,
    ngx_uint_t bi)
{
    ngx_http_block_cache_entry_t     *e;
    ngx_http_block_cache_entry_id_t   ei, pi;

    pi = NGX_HTTP_BLOCK_CACHE_EMPTY_ENTRY_ID;
    ei = bi * NGX_HTTP_BLOCK_CACHE_ENTRIES_IN_BUCKET;
    do {
        e = &seg->entries[ei];
        if (ngx_http_block_cache_entry_is_empty(e)) {
            ei = ngx_http_block_segment_delete_entry(seg, ei, pi);
            continue;
        }
        pi = ei;
        ei = ngx_http_block_cache_entry_next(e);
    } while (ei != NGX_HTTP_BLOCK_CACHE_EMPTY_ENTRY_ID);
}


static void
ngx_http_block_segment_clean_freelist(ngx_http_block_cache_segment_t *seg)
{
    ngx_http_block_cache_entry_id_t   ei;
    ngx_http_block_cache_entry_t     *e;
    ngx_uint_t                        n, bi, lvl;

    ngx_http_block_segment_clean(seg);
    if (seg->freelist != NGX_HTTP_BLOCK_CACHE_EMPTY_ENTRY_ID) {
        return;
    }

    n = 0;
    for (bi = 0; bi < NGX_HTTP_BLOCK_CACHE_BUCKETS_IN_SEGMENT; bi++) {
        for (lvl = 0; lvl < NGX_HTTP_BLOCK_CACHE_ENTRIES_IN_BUCKET; lvl++) {
            ei = bi * NGX_HTTP_BLOCK_CACHE_ENTRIES_IN_BUCKET + lvl;
            e = &seg->entries[ei];
            if (ngx_http_block_cache_entry_is_head(e) && (n++ % 10 == 0)) {
                ngx_http_block_cache_entry_set_empty(e);
            }
        }
    }

    ngx_http_block_segment_clean(seg);
}


static ngx_http_block_cache_entry_id_t
ngx_http_block_segment_pop_freelist(ngx_http_block_cache_segment_t *seg)
{
    ngx_http_block_cache_entry_id_t   ei, ni;
    ngx_http_block_cache_entry_t     *e;

    ei = seg->freelist;
    if (ei == NGX_HTTP_BLOCK_CACHE_EMPTY_ENTRY_ID) {
        ngx_http_block_segment_clean_freelist(seg);
        return NGX_HTTP_BLOCK_CACHE_EMPTY_ENTRY_ID;
    }

    e = &seg->entries[ei];
    ni = ngx_http_block_cache_entry_next(e);
    seg->freelist = ni;
    if (ngx_http_block_cache_entry_is_empty(e)) {
        if (ni != NGX_HTTP_BLOCK_CACHE_EMPTY_ENTRY_ID) {
            ngx_http_block_cache_entry_set_prev(&seg->entries[ni], 0);
        }
        return ei;
    }

    ngx_http_block_cache_segment_init(seg);
    return NGX_HTTP_BLOCK_CACHE_EMPTY_ENTRY_ID;
}


static ngx_inline ngx_uint_t
ngx_http_block_cache_key_hash_bucket(const ngx_http_block_cache_key_hash_t *h)
{
    return h->u32[1] % NGX_HTTP_BLOCK_CACHE_BUCKETS_IN_SEGMENT;
}


static ngx_inline ngx_http_block_cache_tag_t
ngx_http_block_cache_key_hash_tag(const ngx_http_block_cache_key_hash_t *h)
{
    return (ngx_http_block_cache_tag_t)
           (h->u32[2] & NGX_HTTP_BLOCK_CACHE_TAG_MASK);
}


static ngx_inline ngx_http_block_cache_page_id_t
ngx_http_block_cache_entry_page(const ngx_http_block_cache_entry_t *e)
{
    return (ngx_http_block_cache_page_id_t) e->u32[0];
}


static ngx_inline void
ngx_http_block_cache_entry_set_page(ngx_http_block_cache_entry_t *e,
    ngx_http_block_cache_page_id_t page)
{
    e->u32[0] = page;
}


static ngx_inline ngx_flag_t
ngx_http_block_cache_entry_is_empty(const ngx_http_block_cache_entry_t *e)
{
    return ngx_http_block_cache_entry_page(e)
           == NGX_HTTP_BLOCK_CACHE_EMPTY_PAGE_ID;
}


static ngx_inline void
ngx_http_block_cache_entry_set_empty(ngx_http_block_cache_entry_t *e)
{
    ngx_http_block_cache_entry_set_page(e, NGX_HTTP_BLOCK_CACHE_EMPTY_PAGE_ID);
}


static ngx_inline ngx_flag_t
ngx_http_block_cache_entry_is_head(const ngx_http_block_cache_entry_t *e)
{
    return (e->u16[2] & 0x8000) != 0;
}


static ngx_inline void
ngx_http_block_cache_entry_set_head(ngx_http_block_cache_entry_t *e,
    ngx_flag_t head)
{
    if (head) {
        e->u16[2] |= 0x8000;
    } else {
        e->u16[2] &= ~0x8000;
    }
}


static ngx_inline ngx_http_block_cache_tag_t
ngx_http_block_cache_entry_tag(const ngx_http_block_cache_entry_t *e)
{
    return (ngx_http_block_cache_tag_t)
           (e->u16[2] & NGX_HTTP_BLOCK_CACHE_TAG_MASK);
}


static ngx_inline void
ngx_http_block_cache_entry_set_tag(ngx_http_block_cache_entry_t *e,
    ngx_http_block_cache_tag_t tag)
{
    e->u16[2] = (e->u16[2] & ~NGX_HTTP_BLOCK_CACHE_TAG_MASK)
                | (tag & NGX_HTTP_BLOCK_CACHE_TAG_MASK);
}


static ngx_inline ngx_http_block_cache_entry_id_t
ngx_http_block_cache_entry_next(const ngx_http_block_cache_entry_t *e)
{
    return e->u16[3];
}


static ngx_inline void
ngx_http_block_cache_entry_set_next(ngx_http_block_cache_entry_t *e,
    ngx_http_block_cache_entry_id_t ei)
{
    e->u16[3] = ei;
}


static ngx_inline ngx_http_block_cache_entry_id_t
ngx_http_block_cache_entry_prev(const ngx_http_block_cache_entry_t *e)
{
    return e->u16[2];
}


static ngx_inline void
ngx_http_block_cache_entry_set_prev(ngx_http_block_cache_entry_t *e,
    ngx_http_block_cache_entry_id_t ei)
{
    e->u16[2] = ei;
}


static ngx_inline void
ngx_http_block_cache_entry_copy_data_from(ngx_http_block_cache_entry_t *dst,
    const ngx_http_block_cache_entry_t *src)
{
    dst->u32[0] = src->u32[0];
    dst->u16[3] = src->u16[3];
}


static ngx_inline void
ngx_http_block_cache_entry_copy_from(ngx_http_block_cache_entry_t *dst,
    const ngx_http_block_cache_entry_t *src)
{
    dst->u64[0] = src->u64[0];
}


static ngx_inline void
ngx_http_block_cache_entry_clear(ngx_http_block_cache_entry_t *e)
{
    e->u64[0] = 0;
}


static ngx_inline ngx_flag_t
ngx_http_block_cache_entry_equal(const ngx_http_block_cache_entry_t *e,
    const ngx_http_block_cache_entry_t *other)
{
    return e->u64[0] == other->u64[0];
}
