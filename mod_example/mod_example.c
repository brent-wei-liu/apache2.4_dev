#include <httpd.h>
#include <http_protocol.h>
#include <http_config.h>
#include <http_log.h>
#include <stdbool.h>
#include <util_filter.h>

#define FOURK 4096
static int util_read(request_rec *r, unsigned char *rbuf, apr_off_t *size)
{
    ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "DEBUG rbuf=0x%x", rbuf);
    int rc = OK;
    if((rc = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR))) {
        return(rc);
    }
    if(ap_should_client_block(r)) {
        char         argsbuffer[HUGE_STRING_LEN];
        apr_off_t    rsize, len_read, rpos = 0;
        apr_off_t length = r->remaining;
        ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "DEBUG r->remaining:%d", r->remaining);
        //*rbuf = (const char *) apr_pcalloc(r->pool, (apr_size_t) (length + 1));
        *size = length;
        while((len_read = ap_get_client_block(r, argsbuffer, sizeof(argsbuffer))) > 0) {
            ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "DEBUG len_read:%d", len_read);
            if((rpos + len_read) > length) {
                rsize = length - rpos;
            }
            else {
                rsize = len_read;
            }
            ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "DEBUG argsbuffer=%s rsize=%d   ---->  0x%x", argsbuffer, rsize, rbuf + rpos); 
            memcpy(rbuf + rpos, argsbuffer, (size_t) rsize);
            rpos += rsize;
            ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "DEBUG argsbuffer=%s rsize=%d   ---->  0x%x", argsbuffer, rsize, rbuf + rpos); 
        }
    }
    return(rc);
}

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
                    
                    status = apr_bucket_read(b, &buf, &bytes, APR_BLOCK_READ);
                    if (status != APR_SUCCESS) {
                        ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "Failed reading input / bucket %d", status);
                        return -1;
                    }
                    ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "DEBUG len_read:%d", bytes);
                    if(bytes != 0) {
                        memcpy(blb + count, buf, bytes);
                        count += bytes;
                    }else {break;}
                    if (APR_BUCKET_IS_EOS(b)) {
                            end = true;
                    }   
                }   
            }   
        apr_brigade_cleanup(bb);
    } while (!end && (status == APR_SUCCESS));
    
    *len = count;
    return count;
}

static int example_handler(request_rec *r)
{
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
        ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "Request has body. Get request body from the apache request.");
        apr_off_t   size;
        unsigned char *buffer = malloc( HUGE_STRING_LEN );
//        if(util_read(r, buffer, &size) == OK) {
          if(readFromClient(r, buffer, size)>0){
            //ap_rprintf(r, "We read a request body that was %" APR_OFF_T_FMT " bytes long", size);
            ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "We read a request body that was %" APR_OFF_T_FMT " bytes long", size);
        } 

        free(buffer);
    }

    return OK;
}
static int test_input_filter(ap_filter_t *f, apr_bucket_brigade *bb,
                 ap_input_mode_t mode, apr_read_type_e block,
                 apr_off_t readbytes)
{
  int rv;
  rv = ap_get_brigade(f->next, bb, mode, block, readbytes);
  ap_log_rerror(APLOG_MARK, APLOG_NOTICE, rv, f->r, ">>> It works!");
  return rv;
}

static void register_hooks(apr_pool_t* pool)
{
    ap_hook_handler(example_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_register_input_filter("TEST_FILTER", test_input_filter, NULL, AP_FTYPE_RESOURCE);
}
 
module AP_MODULE_DECLARE_DATA example_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    register_hooks
};

