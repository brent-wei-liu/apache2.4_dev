#include <httpd.h>
#include <http_protocol.h>
#include <http_config.h>
#include <http_log.h>
#include <stdbool.h>
#include <util_filter.h>

#define FOURK 4096
static int util_read(request_rec *r, const char **rbuf, apr_off_t *size)
{
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
static int example_handler(request_rec *r)
{
    if (!r->handler || strcmp(r->handler, "example-handler")) return(DECLINED);
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
        const char  *buffer;
        apr_off_t   size;
        if(util_read(r, &buffer, &size) == OK) {
            ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "We read a request body that was %d bytes long", size);
            ap_log_rerror(APLOG_MARK, APLOG_EMERG, 0, r, "Request body:%s", buffer);
        } 
    }
    return OK;
}

static void register_hooks(apr_pool_t* pool)
{
    ap_hook_handler(example_handler, NULL, NULL, APR_HOOK_LAST);
}
 
module AP_MODULE_DECLARE_DATA post_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    register_hooks
};

