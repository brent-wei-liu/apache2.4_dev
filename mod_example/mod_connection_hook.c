#include <httpd.h>
#include <http_protocol.h>
#include <http_config.h>
#include <http_log.h>
#include <stdbool.h>
#include <util_filter.h>

#define FOURK 4096
const int MAX_HEADER_LINE_SIZE=32768;
const int MAX_HEADER_SIZE=32768;

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
                ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "DEBUG len_read:%d", (int)bytes);
                memcpy(blb + count, buf, bytes);
                count += bytes;
            }   
        }   
        apr_brigade_cleanup(bb);
    } while (!end && (status == APR_SUCCESS));
    
    *len = count;
    return OK;
}

static int util_read(request_rec *r, const char **rbuf, apr_off_t *size)
{
    ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "util_read ... ");
    /*~~~~~~~~*/
    int rc = OK;
    /*~~~~~~~~*/
    if((rc = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR))) {
        return(rc);
    }

    if(ap_should_client_block(r)) {
        /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
        char         argsbuffer[HUGE_STRING_LEN];
        apr_off_t    rsize, len_read, rpos = 0;
        apr_off_t length = r->remaining;
        /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

        *rbuf = (const char *) apr_pcalloc(r->pool, (apr_size_t) (length + 1));
        *size = length;
        while((len_read = ap_get_client_block(r, argsbuffer, sizeof(argsbuffer))) > 0) {
            if((rpos + len_read) > length) {
                rsize = length - rpos;
            }
            else {
                rsize = len_read;
            }

            memcpy((char *) *rbuf + rpos, argsbuffer, (size_t) rsize);
            rpos += rsize;
        }
    }
    return(rc);
}

static int brigade_bucket_handler(request_rec *r)
{
    if (!r->handler || strcmp(r->handler, "connection-hook-handler")) return(DECLINED);
    ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "Handling Requst ...");
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
/*        unsigned char *buffer = malloc( HUGE_STRING_LEN );
        int size;
        if(readFromClient(r, buffer, &size) == OK) {
            ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "We read a request body that was %d bytes long", size);
            ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "Request body:%s", buffer);
        }else{
            ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "Read http request body error!");
        } 
        free(buffer);
*/
        const char* requestBodyBuf;
        apr_off_t requestBodySize = 0;
        int rc;
        if ((rc = util_read(r, &requestBodyBuf, &requestBodySize)) != OK) {
            ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "Unable to read request body; rc=%d", rc);
        }else{
            ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "Request body of length=%d",(int)requestBodySize);
            ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "Request body:%s", requestBodyBuf);
        }
    }
    ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "Handling Requst ... Finish!");
    return OK;
}

int process_connection_hook(conn_rec *c) {
    ap_log_cerror(APLOG_MARK, APLOG_EMERG, 0, c, "Process Connection ...");

    apr_status_t rv;
    apr_bucket_brigade *bb;

    bb = apr_brigade_create(c->pool, c->bucket_alloc);
    if (bb == NULL) {
        ap_log_cerror(APLOG_MARK, APLOG_EMERG, 0, c, "hlfsPreConnectionHook: Error in apr_brigade_create");
        return DECLINED;
    }

    ap_filter_t *ipf = c->input_filters;

    if (ipf == NULL) {
        ap_log_cerror(APLOG_MARK, APLOG_EMERG, 0, c, "hlfsPreConnectionHook: input filters null.");
        return DECLINED;
    }

    char out[MAX_HEADER_SIZE];
    apr_size_t outl=MAX_HEADER_SIZE;

    ap_log_cerror(APLOG_MARK, APLOG_EMERG, 0, c, "hlfsPreConnectionHook: Filter: %s", ipf->frec->name);

    rv = ap_get_brigade(ipf, bb, AP_MODE_SPECULATIVE, APR_BLOCK_READ, outl);
    if (rv != APR_SUCCESS) {
        ap_log_cerror(APLOG_MARK, APLOG_EMERG, 0, c, "hlfsPreConnectionHook Error in ap_get_brigade %d", rv);
        apr_brigade_destroy(bb);
        return DECLINED;
    }

    rv = apr_brigade_flatten(bb, out, (apr_size_t*)&outl);
    if (rv != APR_SUCCESS) {
        ap_log_cerror(APLOG_MARK, APLOG_EMERG, 0, c, "Error in ap_get_brigade %d", rv);
        apr_brigade_destroy(bb);
        return -1;
    }

    ap_log_cerror(APLOG_MARK, APLOG_EMERG, 0, c, "bio_filter_read read %d bytes", (int)outl);
    ap_log_cerror(APLOG_MARK, APLOG_EMERG, 0, c, "string read: %s", out);
    if (outl == 0) {
        ap_log_cerror(APLOG_MARK, APLOG_EMERG, 0, c, "Zero sized data, not registering the handler.");
        apr_brigade_destroy(bb);
        return DONE;
    }
    apr_brigade_destroy(bb);

    bb = apr_brigade_create(c->pool, c->bucket_alloc);
    rv = ap_get_brigade(ipf, bb, AP_MODE_SPECULATIVE, APR_BLOCK_READ, outl);
    ap_log_cerror(APLOG_MARK, APLOG_EMERG, 0, c, "bio_filter_read read %d bytes", (int)outl);
    apr_brigade_destroy(bb);

    ap_log_cerror(APLOG_MARK, APLOG_EMERG, 0, c, "Process Connection ... Finish!");

    return DECLINED;
}

static void register_hooks(apr_pool_t* pool)
{
    ap_hook_process_connection (process_connection_hook, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(brigade_bucket_handler, NULL, NULL, APR_HOOK_LAST);
}
 
module AP_MODULE_DECLARE_DATA connection_hook__module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    register_hooks
};

