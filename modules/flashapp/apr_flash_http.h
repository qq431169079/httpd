/* 
**  apr_flashapp_http.h -- Apache  flashapp
*/ 
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_connection.h"
#include "http_request.h"
#include "http_log.h"
#include "unistd.h"

int openurl(apr_pool_t *p,const char *url,char**data,apr_size_t * len ,server_rec *s);
