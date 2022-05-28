my-proxy-cache-memo
===================

nginx [Development guide](http://nginx.org/en/docs/dev/development_guide.html)

## proxy_buffers

[proxy_buffers](http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_buffers)

ngx_http_proxy_commands 内の定義

[modules/ngx_http_proxy_module.c#L472-L477](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/modules/ngx_http_proxy_module.c#L472-L477)

[ngx_http_upstream_conf_t の ngx_bufs_t bufs](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.h#L169) に対応
[ngx_bufs_t](https://github.com/nginx/nginx/blob/release-1.22.0/src/core/ngx_buf.h#L65-L68) はバッファの数とサイズの設定値を保持するだけの構造体。

## u->buffer (ngx_http_upstream_t の ngx_buf_t buffer フィールド)

* [ngx_http_upstream_process_header](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L2352-L2506) 関数
    * [ngx_http_upstream.c#L2376-L2389](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L2376-L2389) でアロケートし temporary = 1 に設定。
    * [ngx_http_upstream.c#L2420](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L2420) の `n = c->recv(c, u->buffer.last, u->buffer.end - u->buffer.last)` で読み込み。
* [ngx_http_proxy_process_status_line(ngx_http_request_t *r)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/modules/ngx_http_proxy_module.c#L1799-L1875) 
    * [ngx_http_proxy_module.c#L1815](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/modules/ngx_http_proxy_module.c#L1815) の `rc = ngx_http_parse_status_line(r, &u->buffer, &ctx->status)` でレスポンスのステータス行をパース。
* [ngx_http_proxy_non_buffered_copy_filter(void *data, ssize_t bytes)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/modules/ngx_http_proxy_module.c#L2325-L2388) 
    * [ngx_http_proxy_module.c#L2344-L2356](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/modules/ngx_http_proxy_module.c#L2344-L2356) で `u->out_bufs` の最後に `cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs)` で取得したバッファを追加。 `c->buf` の `flush` と `memory` を 1 に設定。
    * [ngx_http_proxy_module.c#L2355-L2363](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/modules/ngx_http_proxy_module.c#L2355-L2363) で `b = &u->buffer` の `b->last` から 引数 `bytes` 分を `ngx_chain_t *cl` の `cl->buf->pos` から `cl->buf->last` で参照。
    * [ngx_http_proxy_non_buffered_copy_filter(void *data, ssize_t bytes)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/modules/ngx_http_proxy_module.c#L2325-L2388) は [ngx_http_proxy_handler(ngx_http_request_t *r)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/modules/ngx_http_proxy_module.c#L932-L1028) で `u->input_filter`、 [ngx_http_proxy_reinit_request(ngx_http_request_t *r)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/modules/ngx_http_proxy_module.c#L1606-L1629) で `r->upstream->input_filter` に設定され、どちらか経由で呼ばれる。
* [ngx_http_proxy_non_buffered_chunked_filter(void *data, ssize_t bytes)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/modules/ngx_http_proxy_module.c#L2391-L2489)
    * [ngx_http_proxy_module.c#L2408-L2412](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/modules/ngx_http_proxy_module.c#L2408-L2412) で `u->buffer` の `pos` を `last` にして `last` を引数 `bytes` 分進める。
    * [ngx_http_proxy_module.c#L2420](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/modules/ngx_http_proxy_module.c#L2420) で `rc = ngx_http_parse_chunked(r, buf, &ctx->chunked)` を実行して `Transfer-Encoding: chunked` のレスポンスコンテントをパース。

## u->input_filter

[ngx_int_t (*input_filter_init)(void *data);](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.h#L355)

* 上記の通り ngx_http_proxy_module.c 内では [ngx_http_proxy_non_buffered_copy_filter(void *data, ssize_t bytes)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/modules/ngx_http_proxy_module.c#L2325-L2388) がセットされる。
    * 他に `ngx_http_grpc_module.c` など他のモジュールでもセットされる。
* [ngx_http_upstream_send_response(ngx_http_request_t *r, ngx_http_upstream_t *u)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L2970-L3310)
    * [ngx_http_upstream.c#L3039-L3043](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L3039-L3043) で `u->input_filter` が `NULL` の場合は `ngx_http_upstream_non_buffered_filter` に設定。
    * [http/ngx_http_upstream.c#L3062-L3069](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L3062-L3069) で `n = u->buffer.last - u->buffer.pos` が 0 以外の場合 `u->input_filter(u->input_filter_ctx, n)` で呼ばれる。
* [ngx_http_upstream_process_non_buffered_request(ngx_http_request_t *r, ngx_uint_t do_write)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L3642-L3772)
    * [ngx_http_upstream.c#L3712-L3722](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L3712-L3722) で `n = upstream->recv(upstream, b->last, size)` の結果 `n > 0` の場合に `u->input_filter(u->input_filter_ctx, n)` で呼ばれる。


## [ngx_http_output_filter(ngx_http_request_t *r, ngx_chain_t *in)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_core_module.c#L1852-L1871)

* [ngx_http_output_body_filter_pt ngx_http_top_body_filter](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http.c#L75) を呼び出す。
* ngx_http_upstream.c 内の呼び出し箇所
    * [ngx_http_upstream_output_filter(void *data, ngx_chain_t *chain)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L3962-L3977) 内の [rc = ngx_http_output_filter(r, chain)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L3972)
        * [ngx_http_upstream_send_response(ngx_http_request_t *r, ngx_http_upstream_t *u)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L2970-L3310) 内の [p = u->pipe](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L3185) に対して [p->output_filter = ngx_http_upstream_output_filter](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L3187) で設定。
            * `p->output_filter` は [ngx_event_pipe_write_to_downstream(ngx_event_pipe_t *p)](https://github.com/nginx/nginx/blob/release-1.22.0/src/event/ngx_event_pipe.c#L501-L734) 内の3箇所で呼ばれる。
                * [ngx_event_pipe_write_to_downstream(ngx_event_pipe_t *p)](https://github.com/nginx/nginx/blob/release-1.22.0/src/event/ngx_event_pipe.c#L501-L734) は [ngx_event_pipe(ngx_event_pipe_t *p, ngx_int_t do_write)](https://github.com/nginx/nginx/blob/release-1.22.0/src/event/ngx_event_pipe.c#L22-L98) で `do_write != 0` の場合に呼ばれる。
    * [ngx_http_upstream_process_non_buffered_request(ngx_http_request_t *r, ngx_uint_t do_write)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L3642-L3772) 内の [rc = ngx_http_output_filter(r, u->out_bufs)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L3668)
        * [ngx_http_upstream_process_non_buffered_downstream(ngx_http_request_t *r)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L3592-L3616) 内で [ngx_http_upstream_process_non_buffered_request(r, 1)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L3615) で呼ばれる。
            * [ngx_http_upstream_send_response(ngx_http_request_t *r, ngx_http_upstream_t *u)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L2970-L3310) 内で [r->write_event_handler = ngx_http_upstream_process_non_buffered_downstream](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L3046-L3047) でセットされ [n = u->buffer.last - u->buffer.po](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L3062) が 0 以外の場合に [ngx_http_upstream_process_non_buffered_downstream(r)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L3074) で呼ばれる。
        * [ngx_http_upstream_process_non_buffered_upstream(ngx_http_request_t *r, ngx_http_upstream_t *u)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L3619-L3639) 内で [ngx_http_upstream_process_non_buffered_request(r, 0)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L3638) で呼ばれる。
            * [ngx_http_upstream_send_response(ngx_http_request_t *r, ngx_http_upstream_t *u)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L2970-L3310) 内で [u->read_event_handler = ngx_http_upstream_process_non_buffered_upstream](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L3045) でセットされ [n = u->buffer.last - u->buffer.po](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L3062) が 0 の場合に [ngx_http_upstream_process_non_buffered_upstream(r, u)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L3085) で呼ばれる。

## [ngx_http_upstream_handler(ngx_event_t *ev)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L1269-L1300)

* `ev->write` の場合 `u->write_event_handler(r, u)` を呼ぶ
* `ev->write` でない場合 `u->read_event_handler(r, u)` を呼ぶ
* 呼ばれる箇所
    * [ngx_http_upstream_connect(ngx_http_request_t *r, ngx_http_upstream_t *u)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L1511-L1663) と [ngx_http_upstream_ssl_handshake(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_connection_t *c)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L1768-L1815) 内で `c->write->handler` と `c->read->handler` にセットされる。

## c->write->handler の呼び出し箇所

```
~/ghq/github.com/nginx/nginx-1.22.0$ vgrep 'c->write->handler('
Index File                                   Line Content
    0 src/event/ngx_event_openssl.c          3129 c->write->handler(c->write);
    1 src/http/ngx_http_copy_filter_module.c  315 c->write->handler(c->write);
    2 src/http/ngx_http_upstream.c           3951 c->write->handler(c->write);
```

* [ngx_ssl_read_handler(ngx_event_t *rev)](https://github.com/nginx/nginx/blob/release-1.22.0/src/event/ngx_event_openssl.c#L3120-L3130) 内の [ngx_event_openssl.c#L3129](https://github.com/nginx/nginx/blob/release-1.22.0/src/event/ngx_event_openssl.c#L3129)
* [ngx_http_copy_thread_event_handler(ngx_event_t *ev)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_copy_filter_module.c#L277-L321) 内の [ngx_http_copy_filter_module.c#L315](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_copy_filter_module.c#L315)
    * [ngx_http_copy_thread_handler(ngx_thread_task_t *task, ngx_file_t *file)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_copy_filter_module.c#L208-L321)　内で [task->event.handler = ngx_http_copy_thread_event_handler](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_copy_filter_module.c#L261) でセットされる
        * [ngx_http_copy_filter(ngx_http_request_t *r, ngx_chain_t *in)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_copy_filter_module.c#L82-L158) 内で[ctx->thread_handler = ngx_http_copy_thread_handler](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_copy_filter_module.c#L132) でセットされる
            * [ngx_http_copy_filter_init(ngx_conf_t *cf)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_copy_filter_module.c#L354-L361) 内で `ngx_http_top_body_filter = ngx_http_copy_filter` でセットされる
                * [ngx_http_module_t  ngx_http_copy_filter_module_ctx](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_copy_filter_module.c#L48-L60) で [ngx_http_module_t](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_config.h#L24-L36) の `ngx_int_t   (*postconfiguration)(ngx_conf_t *cf)` にセットされる
* [ngx_http_upstream_thread_event_handler(ngx_event_t *ev)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L3913-L3957) 内の [ngx_http_upstream.c#L3951](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L3951)
    * [ngx_http_upstream_thread_handler(ngx_thread_task_t *task, ngx_file_t *file)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L3845-L3910) 内で [task->event.handler = ngx_http_upstream_thread_event_handler](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L3899) でセットされる。

## c->read->handler の呼び出し箇所

```
~/ghq/github.com/nginx/nginx-1.22.0$ vgrep 'c->read->handler('
Index File                          Line Content
    0 src/core/ngx_connection.c     1331 c->read->handler(c->read);
    1 src/core/ngx_connection.c     1346 c->read->handler(c->read);
    2 src/event/ngx_event_openssl.c 2515 c->read->handler(c->read);
    3 src/mail/ngx_mail_handler.c    802 c->read->handler(c->read);
```

* [ngx_drain_connections(ngx_cycle_t *cycle)](https://github.com/nginx/nginx/blob/release-1.22.0/src/core/ngx_connection.c#L1294-L1348) 内の
[ngx_connection.c#L1331](https://github.com/nginx/nginx/blob/release-1.22.0/src/core/ngx_connection.c#L1331) と [ngx_connection.c#L1346](https://github.com/nginx/nginx/blob/release-1.22.0/src/core/ngx_connection.c#L1346) で呼ばれる
    * [ngx_get_connection(ngx_socket_t s, ngx_log_t *log)](https://github.com/nginx/nginx/blob/release-1.22.0/src/core/ngx_connection.c#L1096-L1159) 内で [ngx_drain_connections((ngx_cycle_t *) ngx_cycle)](https://github.com/nginx/nginx/blob/release-1.22.0/src/core/ngx_connection.c#L1113) で呼ばれる
* [ngx_ssl_write_handler(ngx_event_t *wev)](https://github.com/nginx/nginx/blob/release-1.22.0/src/event/ngx_event_openssl.c#L2506-L2516) 内の [ngx_event_openssl.c#L2515](https://github.com/nginx/nginx/blob/release-1.22.0/src/event/ngx_event_openssl.c#L2515) で呼ばれる
    * [ngx_ssl_handle_recv(ngx_connection_t *c, int n)](https://github.com/nginx/nginx/blob/release-1.22.0/src/event/ngx_event_openssl.c#L2393-L2503) 内で [c->write->handler = ngx_ssl_write_handler](https://github.com/nginx/nginx/blob/release-1.22.0/src/event/ngx_event_openssl.c#L2485) でセットされる


## ngx_event_pipe_t の ngx_chain_t *preread_bufs フィールド

* 設定箇所: [ngx_http_upstream_send_response](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L2970-L3310) 内の [src/http/ngx_http_upstream.c#L3238-L3246](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L3238-L3246)
    * u->buffer を参照。u->buffer の recyled を 1 に設定。
* 参照箇所: [ngx_event_pipe_read_upstream](https://github.com/nginx/nginx/blob/release-1.22.0/src/event/ngx_event_pipe.c#L101-L498) 内の [ngx_event_pipe.c#L145-L162](https://github.com/nginx/nginx/blob/release-1.22.0/src/event/ngx_event_pipe.c#L145-L162)
    * ローカル変数の chain にムーブして p->prearead_bufs は NULL クリア。


## ngx_http_upstream.c


## ngx_http_proxy_module.c


## ngx_event_pipe.h


## ngx_event_pipe.c

```
ngx_int_t
ngx_event_pipe(ngx_event_pipe_t *p, ngx_int_t do_write)
```
