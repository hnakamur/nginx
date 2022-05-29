upstream->input_filter and output_filter
========================================


## ngx_http_upstream_connect call graph

```mermaid
flowchart TB
  U_connect --> U_send_request
  U_send_request --> U_send_request_body
  U_send_request --> U_process_header
  U_process_header --> U_send_response
  U_send_response --> U_process_upstream
  U_process_upstream --> U_process_request
  U_process_request --> ngx_event_pipe
  U_process_request --> ngx_http_file_cache_update

  U_process_header --> U_test_next
  U_test_next --> U_cache_send
  U_test_next --> ngx_http_file_cache_update
```

## c->write->handler & c->read->handler

* ngx_http_upstream_connect

```
c->write->handler = ngx_http_upstream_handler;
c->read->handler = ngx_http_upstream_handler;
```

* ngx_http_upstream_ssl_handshake

```
c->write->handler = ngx_http_upstream_handler;
c->read->handler = ngx_http_upstream_handler;
```

## read_event_handler & write_event_handler

* ngx_http_upstream_init_request

```
if (r->aio) {
    return;
}
...(snip)...
if (u->conf->cache) {
    rc = ngx_http_upstream_cache(r, u);
    if (rc == NGX_BUSY) {
        r->write_event_handler = ngx_http_upstream_init_request;
        return;
    }
    r->write_event_handler = ngx_http_request_empty_handler;
...(snip)...
}
...(snip)...
if (!u->store && !r->post_action && !u->conf->ignore_client_abort) {
    r->read_event_handler = ngx_http_upstream_rd_check_broken_connection;
    r->write_event_handler = ngx_http_upstream_wr_check_broken_connection;
```

* ngx_http_upstream_connect

```
u->write_event_handler = ngx_http_upstream_send_request_handler;
u->read_event_handler = ngx_http_upstream_process_header;
```

* ngx_http_upstream_send_request

```
if (!u->conf->preserve_output) {
    u->write_event_handler = ngx_http_upstream_dummy_handler;
}
```

* ngx_http_upstream_send_request_handler

```
if (u->header_sent && !u->conf->preserve_output) {
    u->write_event_handler = ngx_http_upstream_dummy_handler;
```

* ngx_http_upstream_send_request_body

```
if (!u->request_sent) {
...(snip)...
    r->read_event_handler = ngx_http_upstream_read_request_handler;
...(snip)...
}
...(snip)...
if (!r->reading_body) {
    if (!u->store && !r->post_action && !u->conf->ignore_client_abort) {
        r->read_event_handler = ngx_http_upstream_rd_check_broken_connection;
    }
}
```

* ngx_http_upstream_send_response

```
if (!u->buffering) {
...(snip)...
    u->read_event_handler = ngx_http_upstream_process_non_buffered_upstream;
    r->write_event_handler = ngx_http_upstream_process_non_buffered_downstream;
...(snip)...
}
...(snip)...

u->read_event_handler = ngx_http_upstream_process_upstream;
r->write_event_handler = ngx_http_upstream_process_downstream;
ngx_http_upstream_process_upstream(r, u);
```

* ngx_http_upstream_upgrade

```
u->read_event_handler = ngx_http_upstream_upgraded_read_upstream;
u->write_event_handler = ngx_http_upstream_upgraded_write_upstream;
r->read_event_handler = ngx_http_upstream_upgraded_read_downstream;
r->write_event_handler = ngx_http_upstream_upgraded_write_downstream;
```

* ngx_http_upstream_finalize_request

```
r->read_event_handler = ngx_http_block_reading;
```

## c->write->handler call graph

```mermaid
flowchart TB
  c_writer_handler[c->write->handler]
  task_event_handler[task->event.handler]
  output_chain_ctx_thread_handler[ngx_output_chain_ctx_t *ctx->thread_handler]

  c_read_handler[c->read->handler] --> ngx_ssl_read_handler
  ngx_ssl_read_handler --> c_writer_handler

  output_chain_ctx_thread_handler --> ngx_http_copy_thread_handler
  ngx_http_copy_thread_handler --> ngx_thread_task_post
  ngx_thread_task_post --> task_event_handler
  task_event_handler --> ngx_http_copy_thread_event_handler
  ngx_http_copy_thread_event_handler --> c_writer_handler

  temp_file_thread_handler[p->temp_file->file.thread_handler] --> pipe_thread_handler
  pipe_thread_handler[ngx_event_pipe_t *p->thread_handler] --> U_thread_handler
  U_thread_handler --> ngx_thread_task_post2[ngx_thread_task_post]
  ngx_thread_task_post2 --> task_event_handler2[task->event.handler]
  task_event_handler2 --> U_thread_event_handler
  U_thread_event_handler --> c_writer_handler
```

## c->read->handler call graph

```mermaid
flowchart TB
  ngx_get_connection --> ngx_drain_connections
  ngx_drain_connections --> c_read_handler[c->read->handler]

  c_writer_handler[c->write->handler] --> ngx_ssl_write_handler
  ngx_ssl_write_handler --> c_read_handler
```


## ngx_http_upstream_handler call graph

```mermaid
flowchart TB
  c_writer_handler[c->write->handler]
  c_read_handler[c->read->handler]
  u_read_event_handler[u->read_event_handler]
  u_write_event_handler[u->write_event_handler]

  c_writer_handler --> ngx_http_upstream_handler
  c_read_handler --> ngx_http_upstream_handler
  ngx_http_upstream_handler --> u_write_event_handler
  ngx_http_upstream_handler --> u_read_event_handler
```

## ngx_event_pipe call graph

```mermaid
flowchart TB
  u_read_event_handler[u->read_event_handler]
  u_read_event_handler --> U_process_upstream
  req_write_event_handler[r->write_event_handler]
  req_write_event_handler --> U_process_downstream
  U_process_downstream --> ngx_event_pipe
  U_process_upstream --> ngx_event_pipe
  U_process_downstream --> U_process_request
  U_process_upstream --> U_process_request
  U_process_request --> ngx_event_pipe
```

## ngx_http_upstream_connect call graph
```mermaid
flowchart TB
ngx_http_upstream_init_request --> ngx_http_upstream_connect
ngx_http_upstream_init_request --> ngx_resolve_name
ngx_resolve_name --> ctx_handler
ctx_handler[ngx_resolver_ctx_t *ctx->handler] --> ngx_http_upstream_resolve_handler
ngx_http_upstream_resolve_handler --> ngx_http_upstream_connect
```

## ngx_http_top_request_body_filter call graph

```mermaid
flowchart TB
clcf_handler[ngx_http_core_loc_conf_t *clcf->handler] --> ngx_http_proxy_handler
ngx_http_proxy_handler --> ngx_http_read_client_request_body
ngx_http_read_client_request_body --> ngx_http_do_read_client_request_body

ngx_http_upstream_connect --> ngx_http_upstream_send_request
u_write_event_handler[u->write_event_handler] --> ngx_http_upstream_send_request_handler
ngx_http_upstream_send_request_handler --> ngx_http_upstream_send_request
ngx_http_upstream_send_request --> ngx_http_upstream_send_request_body
ngx_http_upstream_send_request_body --> ngx_http_read_unbuffered_request_body
ngx_http_read_unbuffered_request_body --> ngx_http_do_read_client_request_body
req_read_event_handler[r->read_event_handler] --> ngx_http_read_client_request_body_handler
ngx_http_read_client_request_body_handler --> ngx_http_do_read_client_request_body

ngx_http_do_read_client_request_body --> ngx_http_request_body_filter
ngx_http_request_body_filter --> ngx_http_request_body_chunked_filter
ngx_http_request_body_filter --> ngx_http_request_body_length_filter

ngx_http_request_body_length_filter --> ngx_http_top_request_body_filter
ngx_http_request_body_chunked_filter --> ngx_http_top_request_body_filter
```


## p->temp_file->file.thread_handler call graph

```mermaid
flowchart TB
ngx_thread_read --> temp_file_thread_handler[p->temp_file->file.thread_handler]

ngx_http_top_request_body_filter --> ngx_http_request_body_save_filter
ngx_http_request_body_save_filter --> ngx_http_write_request_body
ngx_http_write_request_body --> ngx_write_chain_to_temp_file

ngx_event_pipe --> ngx_event_pipe_write_to_downstream
ngx_event_pipe --> ngx_event_pipe_read_upstream
ngx_event_pipe_read_upstream --> ngx_event_pipe_write_chain_to_temp_file
ngx_event_pipe_write_to_downstream --> ngx_event_pipe_write_chain_to_temp_file
ngx_event_pipe_write_chain_to_temp_file --> ngx_write_chain_to_temp_file
ngx_write_chain_to_temp_file --> ngx_thread_write_chain_to_file
ngx_thread_write_chain_to_file --> temp_file_thread_handler
ngx_linux_sendfile_thread --> temp_file_thread_handler
```

## pipe->output_filter call graph

```mermaid
flowchart TB
  ngx_event_pipe --> ngx_event_pipe_write_to_downstream
  ngx_event_pipe_write_to_downstream --> p_output_filter
  p_output_filter[p->output_filter]
  p_output_filter --> ngx_http_upstream_output_filter
  ngx_http_upstream_output_filter --> ngx_http_output_filter
  ngx_http_output_filter --> ngx_http_top_body_filter
```

## ngx_http_top_body_filter

```mermaid
flowchart TB
  ngx_http_top_body_filter --> ngx_http_trailers_filter
```

## ngx_http_upstream_process_headers call graph

```mermaid
flowchart TB
  U_cache_send --> U_process_headers
  U_process_header --> U_process_headers
```

## upstream->input_filter

### 定義箇所
[struct ngx_http_upstream_s](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.h#L323-L404) 内の [ngx_int_t (*input_filter_init)(void *data);](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.h#L355)

### 設定箇所
[ngx_http_proxy_non_buffered_copy_filter(void *data, ssize_t bytes)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/modules/ngx_http_proxy_module.c#L2325-L2388) が [ngx_http_proxy_handler(ngx_http_request_t *r)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/modules/ngx_http_proxy_module.c#L932-L1028) で `u->input_filter`、 [ngx_http_proxy_reinit_request(ngx_http_request_t *r)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/modules/ngx_http_proxy_module.c#L1606-L1629) で `r->upstream->input_filter` に設定される。

### 呼び出し
* [ngx_http_upstream_send_response(ngx_http_request_t *r, ngx_http_upstream_t *u)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L2970-L3310)
    * [http/ngx_http_upstream.c#L3062-L3069](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L3062-L3069) で `n = u->buffer.last - u->buffer.pos` が 0 以外の場合 `u->input_filter(u->input_filter_ctx, n)` で呼ばれる。
* [ngx_http_upstream_process_non_buffered_request(ngx_http_request_t *r, ngx_uint_t do_write)](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L3642-L3772)
    * [ngx_http_upstream.c#L3712-L3722](https://github.com/nginx/nginx/blob/release-1.22.0/src/http/ngx_http_upstream.c#L3712-L3722) で `n = upstream->recv(upstream, b->last, size)` の結果 `n > 0` の場合に `u->input_filter(u->input_filter_ctx, n)` で呼ばれる。

```mermaid
flowchart TB
    U_send_response --> U_process_non_buffered_downstream
    U_send_response --> U_process_non_buffered_upstream
    U_send_response --> U_input_filter
    U_process_non_buffered_downstream --> U_process_non_buffered_request
    U_process_non_buffered_upstream --> U_process_non_buffered_request
    U_process_non_buffered_request --> U_input_filter
    U_input_filter[upstream->input_filter]
    U_input_filter --> P_non_buffered_copy_filter

    subgraph comment
        comment1[U_ = ngx_http_upstream_\nP_ = ngx_http_proxy_]
        class comment1 comment
        classDef comment fill:#736f01;
    end
```

```mermaid
flowchart TB
    U_thread_handler --> ngx_thread_task_post
    ngx_thread_task_post --> task_event_handler[task->event.handler]
    task_event_handler --> U_thread_event_handler
    U_thread_event_handler --> req_write_event_handler[r->write_event_handler]
    req_write_event_handler --> U_process_non_buffered_downstream
```