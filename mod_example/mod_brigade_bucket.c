#include <httpd.h>
#include <http_protocol.h>
#include <http_config.h>
#include <http_log.h>
#include <stdbool.h>
#include <util_filter.h>

#define FOURK 4096
static int readFromClient(request_rec *r, void *blb, int *len)
{
    apr_bucket          *b; 
    apr_bucket_brigade  *bb;
    apr_status_t        status;
    int                 rc; 
    bool                end = false;
    int                 count=0;
    const char          *buf;
    apr_uint64_t        bytes;

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    if(bb == NULL) { 
        ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "Error in apr_brigade_create");
        return -1; 
    }   

    do {
        status = ap_get_brigade(r->input_filters, bb, AP_MODE_READBYTES, APR_BLOCK_READ, FOURK);
        if (status == APR_SUCCESS) {
            for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) {
                if (APR_BUCKET_IS_EOS(b)) {
                    end = 1;
                    break;
                } else if (APR_BUCKET_IS_METADATA(b)) {
                    continue;
                }

                status = apr_bucket_read(b, &buf, &bytes, APR_BLOCK_READ);
                if (status != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "Failed reading input / bucket %d", status);
                    return -1; 
                }   
                ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "DEBUG len_read:%d", bytes);
                memcpy(blb + count, buf, bytes);
                count += bytes;
            }   
        }   
        apr_brigade_cleanup(bb);
    } while (!end && (status == APR_SUCCESS));
    
    *len = count;
    return OK;
}

static int brigade_bucket_handler(request_rec *r)
{
    if (!r->handler || strcmp(r->handler, "brigade-bucket-handler")) return(DECLINED);
    /* Set the appropriate content type */
    ap_set_content_type(r, "text/html");

    /* Print out the IP address of the client connecting to us: */
    ap_rprintf(r, "<h2>Hello, %s!</h2>", r->useragent_ip);
    
    /* If we were reached through a GET or a POST request, be happy, else sad. */
    if ( !strcmp(r->method, "POST") || !strcmp(r->method, "GET") ) {
        ap_rputs("You used a GET or a POST method, that makes us happy!<br/>", r);
    }
    else {
        ap_rputs("You did not use POST or GET, that makes us sad :(<br/>", r);
    }

    /* Printing out every HTTP header received */
    const apr_array_header_t    *fields;
    int                         i;
    apr_table_entry_t           *e = 0;
    fields = apr_table_elts(r->headers_in);
    e = (apr_table_entry_t *) fields->elts;
    ap_rputs("<h2>Printing out every HTTP header received</h2>", r);
    for(i = 0; i < fields->nelts; i++) {
        ap_rprintf(r, "%s: %s<br/>", e[i].key, e[i].val);
    }

    /* If there was a query string, let's print that too! */
    if (r->args) {
        ap_rprintf(r, "<h2>Your query string was:</h2><br/> %s", r->args);
    }
    
    /* Get request body from the apache request */
    if(!ap_request_has_body(r)){
        ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "Request has nobody!");
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "Request has body. Get request body from the apache request.1");
        unsigned char *buffer = malloc( HUGE_STRING_LEN );
        int size;
        if(readFromClient(r, buffer, &size) == OK) {
            ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "We read a request body that was %d bytes long", size);
            ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "Request body:%s", buffer);
        }else{
            ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "Read http request body error!");
        } 
        free(buffer);
    }
    return OK;
}

static void register_hooks(apr_pool_t* pool)
{
    ap_hook_handler(brigade_bucket_handler, NULL, NULL, APR_HOOK_LAST);
}
 
module AP_MODULE_DECLARE_DATA brigade_bucket_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    register_hooks
};

