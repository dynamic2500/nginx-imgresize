
/*
 * Copyright (C) Timothy Elliott
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <jpeglib.h>
#include <jerror.h>
#include <setjmp.h>

#include "resample.h"


#define STATE_SETUP 0
#define STATE_READ_HEADER 1
#define STATE_READ_IMAGE 2

#define OUT_BUF_SIZE 32768


typedef struct {
    ngx_uint_t                   width;
    ngx_uint_t                   height;
    ngx_http_complex_value_t    *wcv;
    ngx_http_complex_value_t    *hcv;
} imgresize_conf_t;


struct jpeg_ngx_error_mgr {
    struct jpeg_error_mgr pub;
    jmp_buf setjmp_buffer;
};


struct jpeg_ngx_source_mgr {
    struct jpeg_source_mgr pub;
    ngx_chain_t chain;
};


struct jpeg_ngx_destination_mgr {
    struct jpeg_destination_mgr pub;
    ngx_chain_t *chain_first;
    ngx_chain_t *chain_last;
    uint8_t *out_data;
    ngx_http_request_t *r;
    size_t len;
};


struct imgresize_ctx {
    struct jpeg_decompress_struct dinfo;
    struct jpeg_compress_struct cinfo;
    struct jpeg_ngx_error_mgr jerr;
    ngx_uint_t state;
    uint8_t *out_buf;
    uint32_t out_width;
    uint32_t out_height;
    uint32_t out_pos;
    struct xscaler xs;
    struct yscaler ys;
    uint8_t *jpeg_out_buf;
    uint8_t *yscaler_next;
    unsigned long jpeg_out_len;
    ngx_chain_t *out_chain;
};


static ngx_int_t imgresize_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t imgresize_header_filter(ngx_http_request_t *r);
static char *conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t imgresize_init(ngx_conf_t *cf);
static void *imgresize_create_conf(ngx_conf_t *cf);
static char *imgresize_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_uint_t get_value_helper(ngx_http_request_t *r,
    ngx_http_complex_value_t *cv, ngx_uint_t v);
static void imgresize_cleanup(void *data);
static struct jpeg_error_mgr *jpeg_ngx_error(struct jpeg_ngx_error_mgr *err);
static void jpeg_ngx_src(j_decompress_ptr dinfo);
static void jpeg_ngx_src_add_chain(j_decompress_ptr dinfo, ngx_chain_t *chain);
static void jpeg_ngx_dest(j_compress_ptr cinfo, ngx_http_request_t *r);
static ngx_chain_t *jpeg_ngx_dest_chain(j_compress_ptr cinfo);
static ngx_int_t imgresize_send(ngx_http_request_t *r);


static ngx_command_t  imgresize_commands[] = {

    { ngx_string("imgresize"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  imgresize_ctx = {
    NULL,
    imgresize_init,

    NULL,
    NULL,

    NULL,
    NULL,

    imgresize_create_conf,
    imgresize_merge_conf
};


ngx_module_t  imgresize = {
    NGX_MODULE_V1,
    &imgresize_ctx,
    imgresize_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;


/* If the input jpeg prematurely ends, we give this to libjpeg. */
static unsigned char jpeg_end[2];


static ngx_int_t
imgresize_header_filter(ngx_http_request_t *r)
{
    imgresize_conf_t *conf;
    struct imgresize_ctx *ctx;
    ngx_uint_t width, height;

    /* If upstream is responding with not-modified, do nothing. */
    if (r->headers_out.status == NGX_HTTP_NOT_MODIFIED) {
        return ngx_http_next_header_filter(r);
    }

    /* Check if the current location is configured for imgresize. */
    conf = ngx_http_get_module_loc_conf(r, imgresize);

    width = get_value_helper(r, conf->wcv, conf->width);
    height = get_value_helper(r, conf->hcv, conf->height);

    if (!width || !height) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(struct imgresize_ctx));
    if (ctx == NULL) {
       return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, imgresize);

    /* Stash configuration values so we don't have to do this again later. */
    ctx->out_width = width;
    ctx->out_height = height;

    if (r == r->main) {
        ngx_http_clear_content_length(r);
    }

    r->filter_need_in_memory = 1;
    return ngx_http_next_header_filter(r);
}


static ngx_int_t
imgresize_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    struct imgresize_ctx *ctx;
    ngx_int_t i, rc, cmp;
    uint32_t width_out;
    uint8_t *pos0;
    struct jpeg_decompress_struct *dinfo;
    struct jpeg_compress_struct *cinfo;
    ngx_pool_cleanup_t *cln;
    jpeg_saved_marker_ptr marker;

    if (!in) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, imgresize);

    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    dinfo = &ctx->dinfo;
    cinfo = &ctx->cinfo;
    jpeg_ngx_src_add_chain(dinfo, in);

    if (setjmp(ctx->jerr.setjmp_buffer)) {
        jpeg_abort_compress(&ctx->cinfo);
        jpeg_abort_decompress(&ctx->dinfo);
        return NGX_ERROR;
    }

    switch (ctx->state) {
    case STATE_SETUP:
        cln = ngx_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            imgresize_send(r);
            return NGX_ERROR;
        }
        cln->handler = imgresize_cleanup;
        cln->data = ctx;

        dinfo->err = cinfo->err = jpeg_ngx_error(&ctx->jerr);

        jpeg_create_compress(cinfo);
        jpeg_create_decompress(dinfo);
        jpeg_ngx_src(dinfo);
        jpeg_ngx_src_add_chain(dinfo, in);

        /* Save custom headers for the compressor, but ignore APP0 & APP14 so
         * libjpeg can handle them.
         */
        jpeg_save_markers(dinfo, JPEG_COM, 0xFFFF);
        for (i=1; i<14; i++) {
            jpeg_save_markers(dinfo, JPEG_APP0+i, 0xFFFF);
        }
        jpeg_save_markers(dinfo, JPEG_APP0+15, 0xFFFF);

        ctx->state = STATE_READ_HEADER;

        // fall through
    case STATE_READ_HEADER:
        rc = jpeg_read_header(dinfo, TRUE);
        if (rc == JPEG_SUSPENDED) {
            return NGX_OK;
        }

#ifdef JCS_EXTENSIONS
        if (dinfo->out_color_space == JCS_RGB) {
            dinfo->out_color_space = JCS_EXT_RGBX;
        }
#endif

        fix_ratio(dinfo->image_width, dinfo->image_height, &ctx->out_width,
            &ctx->out_height);
        width_out = ctx->out_width;

        dinfo->scale_denom = cubic_scale_denom(dinfo->image_width, width_out);

        jpeg_start_decompress(dinfo);
        cmp = dinfo->output_components;

        xscaler_init(&ctx->xs, dinfo->output_width, width_out, cmp, 1);
        yscaler_init(&ctx->ys, dinfo->output_height, ctx->out_height,
            (size_t)width_out * cmp);
        ctx->out_buf = ngx_pnalloc(r->pool, (size_t)width_out * cmp);

        cinfo->image_width = width_out;
        cinfo->image_height = ctx->out_height;
        cinfo->input_components = cmp;
        cinfo->in_color_space = dinfo->out_color_space;

        /* set up destination manager */
        jpeg_ngx_dest(cinfo, r);

        jpeg_set_defaults(cinfo);
        jpeg_set_quality(cinfo, 85, FALSE);
        jpeg_start_compress(cinfo, TRUE);

        /* Write custom headers */
        for (marker=dinfo->marker_list; marker; marker=marker->next) {
            jpeg_write_marker(cinfo, marker->marker, marker->data,
                marker->data_length);
        }

        ctx->state = STATE_READ_IMAGE;

        // fall through
    case STATE_READ_IMAGE:
        pos0 = xscaler_psl_pos0(&ctx->xs);
        while(ctx->out_pos<ctx->out_height) {
            // check in case of previous suspend while trying to read scanlines
            if (!ctx->yscaler_next) {
                ctx->yscaler_next = yscaler_next(&ctx->ys);
            }
            while (ctx->yscaler_next) {
                rc = jpeg_read_scanlines(dinfo, &pos0, 1);
                if (rc == 0) {
                    imgresize_send(r);
                    return NGX_OK;
                }
                xscaler_scale(&ctx->xs, ctx->yscaler_next);
                ctx->yscaler_next = yscaler_next(&ctx->ys);
            }
            yscaler_scale(&ctx->ys, ctx->out_buf, ctx->out_pos,
                dinfo->output_components, 1);
            jpeg_write_scanlines(cinfo, &ctx->out_buf, 1);
            ctx->out_pos++;
        }

        jpeg_finish_compress(cinfo);
        jpeg_finish_decompress(dinfo);
    }

    return imgresize_send(r);
}


static ngx_int_t
imgresize_send(ngx_http_request_t *r)
{
    struct imgresize_ctx *ctx;
    ngx_chain_t *chain_start;
    struct jpeg_compress_struct *cinfo;

    ctx = ngx_http_get_module_ctx(r, imgresize);

    if (ctx->out_chain) {
        chain_start = ctx->out_chain->next;
    } else {
        cinfo = &ctx->cinfo;
        chain_start = ctx->out_chain = jpeg_ngx_dest_chain(cinfo);
    }

    if (!chain_start) {
        return NGX_OK;
    }

    while(ctx->out_chain->next) {
        ctx->out_chain = ctx->out_chain->next;
    }

    return ngx_http_next_body_filter(r, chain_start);
}


static ngx_int_t
imgresize_init(ngx_conf_t *cf)
{
    jpeg_end[0] = 0xFF;
    jpeg_end[1] = JPEG_EOI;

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = imgresize_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = imgresize_body_filter;
    return NGX_OK;
}


static ngx_uint_t
value_helper(ngx_str_t *value)
{
    ngx_int_t  n;
    n = ngx_atoi(value->data, value->len);
    return n > 0 ? (ngx_uint_t)n : 0;
}


static char *
conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    imgresize_conf_t *imcf = conf;

    ngx_str_t                         *value;
    ngx_http_complex_value_t           cv;
    ngx_http_compile_complex_value_t   ccv;

    if (cf->args->nelts != 3) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
      return NGX_CONF_ERROR;
    }
    if (cv.lengths) {
        imcf->wcv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (imcf->wcv == NULL) {
            return NGX_CONF_ERROR;
        }
        *imcf->wcv = cv;
    } else { // not a complex value
        imcf->width = value_helper(&value[1]);
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &cv;
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
      return NGX_CONF_ERROR;
    }
    if (cv.lengths) {
        imcf->hcv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (imcf->hcv == NULL) {
            return NGX_CONF_ERROR;
        }
        *imcf->hcv = cv;
    } else { // not a complex value
        imcf->height = value_helper(&value[2]);
    }

    return NGX_CONF_OK;
}


static void *
imgresize_create_conf(ngx_conf_t *cf)
{
    return ngx_pcalloc(cf->pool, sizeof(imgresize_conf_t));
}


static char *
imgresize_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    return NGX_CONF_OK;
}


static ngx_uint_t
get_value_helper(ngx_http_request_t *r, ngx_http_complex_value_t *cv,
    ngx_uint_t v)
{
    ngx_str_t  val;

    if (cv == NULL) {
        return v;
    }

    if (ngx_http_complex_value(r, cv, &val) != NGX_OK) {
        return 0;
    }

    return value_helper(&val);
}


/* jpeg_ngx_error_mgr */


static void
output_message(j_common_ptr cinfo)
{
	char buffer[JMSG_LENGTH_MAX];
    (*cinfo->err->format_message)(cinfo, buffer);
    fprintf(stderr, "%s\n", buffer);
}


static
void error_exit(j_common_ptr dinfo)
{
    struct jpeg_ngx_error_mgr *err;
    err = (struct jpeg_ngx_error_mgr *)dinfo->err;
	output_message(dinfo);
	longjmp(err->setjmp_buffer, 1);
}


static struct jpeg_error_mgr *
jpeg_ngx_error(struct jpeg_ngx_error_mgr *err)
{
    struct jpeg_error_mgr *pub;
    pub = &err->pub;
    jpeg_std_error(pub);
    pub->error_exit = error_exit;
    pub->output_message = output_message;
    return pub;
}


/* jpeg_ngx_src */


static void
jpeg_ngx_src_use_chain(struct jpeg_ngx_source_mgr *src, ngx_chain_t *chain)
{
    ngx_buf_t *buf;
    buf = src->chain.buf = chain->buf;
    src->chain.next = chain->next;
    src->pub.bytes_in_buffer = buf->last - buf->pos;
    src->pub.next_input_byte = buf->pos;
}


static void
init_source(j_decompress_ptr dinfo)
{
}


static boolean
fill_input_buffer(j_decompress_ptr dinfo)
{
    struct jpeg_ngx_source_mgr *src;
    ngx_buf_t *buf;

    src = (struct jpeg_ngx_source_mgr *)dinfo->src;
    buf = src->chain.buf;

    /* Tell nginx that we're done with this buffer. Common case. */
    buf->pos = buf->last;

    /* This was the end of the response and libjpeg wants more - give it a dummy
     * eof. This is per the recommendation in the libjpeg docs.
     */
    if (buf->last_buf) {
        src->pub.bytes_in_buffer = 2;
        src->pub.next_input_byte = jpeg_end;
        return TRUE;
    }

    /* No buffers left - tell nginx we're not done with this buffer and suspend.
     */
    if (!src->chain.next) {
        buf->pos = (u_char *)src->pub.next_input_byte;
        return FALSE;
    }

    /* There is another buffer in the chain. pass it to libjpeg. */
    jpeg_ngx_src_use_chain(src, src->chain.next);
    return TRUE;
}


static void
skip_input_data(j_decompress_ptr dinfo, long num_bytes)
{
    struct jpeg_ngx_source_mgr *src;
    boolean ret;

    src = (struct jpeg_ngx_source_mgr *)dinfo->src;

    if (num_bytes < 1) {
        return;
    }

    while ((size_t)num_bytes > src->pub.bytes_in_buffer) {
        num_bytes -= src->pub.bytes_in_buffer;
        ret = src->pub.fill_input_buffer(dinfo);
        if (ret == FALSE) {
            /* FIXME: Here we should remember the number of remaining skipped
            * and recall this number from the ctx next time, and call this
            * method with the remainder.
            *
            * The scenario is when we skip a header that is larger than our
            * buffer.
            */
            return;
        }
    }
    src->pub.next_input_byte += (size_t)num_bytes;
    src->pub.bytes_in_buffer -= (size_t)num_bytes;
}


static void
term_source(j_decompress_ptr cinfo)
{
}


static void
jpeg_ngx_src(j_decompress_ptr dinfo)
{
    struct jpeg_source_mgr *pub;
    struct jpeg_ngx_source_mgr *src;

    pub = (struct jpeg_source_mgr *)
        (*dinfo->mem->alloc_small) ((j_common_ptr)dinfo, JPOOL_PERMANENT,
        sizeof(struct jpeg_ngx_source_mgr));
    src = (struct jpeg_ngx_source_mgr *)pub;
    memset(src, 0, sizeof(struct jpeg_ngx_source_mgr));

    dinfo->src = pub;
    pub->init_source = init_source;
    pub->fill_input_buffer = fill_input_buffer;
    pub->skip_input_data = skip_input_data;
    pub->resync_to_restart = jpeg_resync_to_restart;
    pub->term_source = term_source;
}


static void
jpeg_ngx_src_add_chain(j_decompress_ptr dinfo, ngx_chain_t *chain)
{
    struct jpeg_ngx_source_mgr *src;

    if (!dinfo->src) {
        return;
    }
    src = (struct jpeg_ngx_source_mgr *)dinfo->src;

    /* If there are bytes_in_buffer we are resuming a suspended read. Otherwise,
     * we just use the given buffer. */
    if (src->pub.bytes_in_buffer) {
            src->chain.next = chain;
    } else {
            jpeg_ngx_src_use_chain(src, chain);
    }

}


/* jpeg_ngx_dest */


static void
jpeg_ngx_dest_add_buf_to_chain(j_compress_ptr cinfo, size_t buf_len)
{
    struct jpeg_ngx_destination_mgr *dest;
    ngx_chain_t *new_chain;
    ngx_buf_t *b;

    dest = (struct jpeg_ngx_destination_mgr *)cinfo->dest;

    dest->len += buf_len;

    new_chain = ngx_alloc_chain_link(dest->r->pool);
    if (!new_chain) {
        ERREXIT1(cinfo, JERR_OUT_OF_MEMORY, 10);
    }

    new_chain->buf = ngx_calloc_buf(dest->r->pool);
    if (new_chain->buf == NULL) {
        ERREXIT1(cinfo, JERR_OUT_OF_MEMORY, 10);
    }

    new_chain->next = NULL;

    b = new_chain->buf;
    b->memory = 1;
    b->pos = dest->out_data;
    b->last = b->pos + buf_len;

    if (dest->chain_last) {
        dest->chain_last->next = new_chain;
    }
    if (!dest->chain_first) {
        dest->chain_first = new_chain;
    }

    dest->chain_last = new_chain;
}


static void
jpeg_ngx_dest_next_buf(j_compress_ptr cinfo, size_t buf_len)
{
    struct jpeg_ngx_destination_mgr *dest;
    dest = (struct jpeg_ngx_destination_mgr *)cinfo->dest;
    dest->out_data = ngx_pnalloc(dest->r->pool, buf_len);
    dest->pub.next_output_byte = dest->out_data;
    dest->pub.free_in_buffer = buf_len;
}


static void
init_destination(j_compress_ptr cinfo)
{
    jpeg_ngx_dest_next_buf(cinfo, OUT_BUF_SIZE);
}


static boolean
empty_output_buffer(j_compress_ptr cinfo)
{
    jpeg_ngx_dest_add_buf_to_chain(cinfo, OUT_BUF_SIZE);
    jpeg_ngx_dest_next_buf(cinfo, OUT_BUF_SIZE);
    return TRUE;
}


static void
term_destination(j_compress_ptr cinfo)
{
    struct jpeg_ngx_destination_mgr *dest;
    dest = (struct jpeg_ngx_destination_mgr *)cinfo->dest;
    jpeg_ngx_dest_add_buf_to_chain(cinfo, OUT_BUF_SIZE - dest->pub.free_in_buffer);
    dest->chain_last->buf->last_buf = 1;
}


static void
jpeg_ngx_dest(j_compress_ptr cinfo, ngx_http_request_t *r)
{
    struct jpeg_destination_mgr *pub;
    struct jpeg_ngx_destination_mgr *dest;

    pub = (struct jpeg_destination_mgr *)
        (*cinfo->mem->alloc_small) ((j_common_ptr)cinfo, JPOOL_PERMANENT,
        sizeof(struct jpeg_ngx_destination_mgr));
    dest = (struct jpeg_ngx_destination_mgr *)pub;
    memset(dest, 0, sizeof(struct jpeg_ngx_destination_mgr));

    dest->r = r;
    cinfo->dest = pub;
    pub->init_destination = init_destination;
    pub->empty_output_buffer = empty_output_buffer;
    pub->term_destination = term_destination;
}


static ngx_chain_t *
jpeg_ngx_dest_chain(j_compress_ptr cinfo)
{
    struct jpeg_ngx_destination_mgr *dest;
    dest = (struct jpeg_ngx_destination_mgr *)cinfo->dest;
    return dest->chain_first;
}


static void
imgresize_cleanup(void *data)
{
    struct imgresize_ctx *ctx;

    ctx = (struct imgresize_ctx *)data;
    jpeg_destroy_compress(&ctx->cinfo);
    jpeg_destroy_decompress(&ctx->dinfo);
    xscaler_free(&ctx->xs);
    yscaler_free(&ctx->ys);
    free(ctx->jpeg_out_buf);
}
