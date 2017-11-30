/* 
**  apr_flashapp_http.c -- Apache  flashapp
*/ 
#include "apr.h"
#include "apr_signal.h"
#include "apr_strings.h"
#include "apr_network_io.h"
#include "apr_file_io.h"
#include "apr_time.h"
#include "apr_getopt.h"
#include "apr_general.h"
#include "apr_lib.h"
#include "apr_portable.h"
#include "ap_release.h"
#include "apr_poll.h"

#include "apr_flash_http.h"


#define CREQ_BUFFSIZE (2048)
#define CREV_BUFFSIZE (8192)

typedef struct _flash_http_ {
	apr_pool_t *flash_pool;
	apr_sockaddr_t *destsa;
	apr_socket_t *aprsock;
	apr_interval_time_t timeout;
	char request[CREQ_BUFFSIZE];
	char *revbuffer;
	apr_size_t revsize;
	char * fullurl;
	char * colonhost;
	char *hostname;         /* host name from URL */
	char *host_field;       /* value of "Host:" header field */
	char *path;             /* path name */
	apr_port_t port;        /* port number */
	char *cookie;           /* optional cookie line */
	char *auth;             /* optional (basic/uuencoded) auhentication */
	char *hdrs;             /* optional arbitrary headers */

	char *postdata;         /* *buffer containing data from postfile */
	apr_size_t postlen ; /* length of data to be POSTed */

	char content_type[CREQ_BUFFSIZE];/* content type to put in POST header */
	char *proxyhost;   /* proxy host name */
	apr_port_t proxyport;      /* proxy port */
	int isproxy;

	int ispost;
	int keepalive;
} flash_http;


static int init_flash_http(apr_pool_t *p,flash_http *phttp)
{
	phttp->flash_pool=NULL;
	phttp->destsa=NULL;
	phttp->aprsock=NULL;
	phttp->timeout=10000000;
	memset(phttp->request,0,CREQ_BUFFSIZE);
	phttp->revbuffer=NULL;
	phttp->revsize=0;
	phttp->fullurl=NULL;
	phttp->colonhost=NULL;
	phttp->hostname=NULL;
	phttp->host_field=NULL;
	phttp->path=NULL;
	phttp->port=80;
	phttp->cookie=NULL;
	phttp->auth=NULL;
	phttp->hdrs=NULL;
	phttp->postdata=NULL;
	phttp->postlen=0;
	memset(phttp->content_type,0,CREQ_BUFFSIZE);
	phttp->proxyhost=NULL;
	phttp->proxyport=0;
	phttp->isproxy=0;
	phttp->ispost=0;
	phttp->keepalive=0;

	if(p){
		apr_pool_create(&(phttp->flash_pool), p);
	}else{
		apr_pool_create(&(phttp->flash_pool), NULL);
	}

	return 0;
}


static int destory_flash_http(flash_http *phttp)
{
	apr_socket_close(phttp->aprsock);
	apr_pool_destroy(phttp->flash_pool);
	return 0;
}


/* split URL into parts */
static int parse_url(const char *url,flash_http *phttp)
{
    char *cp;
    char *h;
    char *purl=NULL;
    char *scope_id;
    apr_status_t rv;
    purl=(char *)url;

    /* Save a copy for the proxy */
    phttp->fullurl = apr_pstrdup(phttp->flash_pool, purl);

    if (strlen(purl) > 7 && strncmp(purl, "http://", 7) == 0) {
    	purl += 7;
    }

    if ((cp = strchr(purl, '/')) != NULL){
    	h = apr_palloc(phttp->flash_pool, cp - purl + 1);
    	memcpy(h, purl, cp - purl);
    	h[cp - purl] = '\0';
    	phttp->path = apr_pstrdup(phttp->flash_pool, cp);
    	*cp = '\0';
    }else{
    	h= apr_pstrdup(phttp->flash_pool, purl);
    }

    rv = apr_parse_addr_port(&(phttp->hostname), &scope_id, &(phttp->port), h, phttp->flash_pool);
    if (rv != APR_SUCCESS || (!phttp->hostname) || scope_id) {
    	phttp->path = apr_pstrdup(phttp->flash_pool, purl);
    }else{
    	if (*purl == '[') {      /* IPv6 numeric address string */
    		phttp->host_field = apr_psprintf(phttp->flash_pool, "[%s]", phttp->hostname);
    	}
    	else {
    		phttp->host_field = phttp->hostname;
    	}

    	if (phttp->port == 0) {        /* no port specified */
    	    	phttp->port = 80;
    	}

    	if (phttp->port != 80)
    	{
    		phttp->colonhost = apr_psprintf(phttp->flash_pool,":%d",phttp->port);
    	}
    	else{
    		phttp->colonhost = apr_psprintf(phttp->flash_pool,"");
    	}
    }
    return 0;
}

static int prepare_data(flash_http *phttp)
{
	if(phttp->host_field)
	{
		phttp->hdrs = apr_pstrcat(phttp->flash_pool, (phttp->hdrs!=NULL)?phttp->hdrs:"", "Host: ", phttp->host_field, phttp->colonhost, "\r\n", NULL);
	}
	/* setup request */
	 if (phttp->ispost <= 0) {
	        apr_snprintf(phttp->request,CREQ_BUFFSIZE,
	            "%s %s HTTP/1.0\r\n"
	            "%s" "%s" "%s"
	            "%s" "\r\n",
	            (phttp->ispost == 0) ? "GET" : "HEAD",
	            (phttp->isproxy) ? phttp->fullurl : ((phttp->path!=NULL)?phttp->path :phttp->fullurl) ,
	            (phttp->keepalive) ? "Connection: Keep-Alive\r\n" : "" ,
	            (phttp->cookie != NULL)? phttp->cookie: "",
	            (phttp->auth != NULL)? phttp->auth : "" ,
	            (phttp->hdrs !=NULL)? phttp->hdrs : "");
	 }
	 else {
	        apr_snprintf(phttp->request,  CREQ_BUFFSIZE,
	            "%s %s HTTP/1.0\r\n"
	            "%s" "%s" "%s"
	            "Content-length: %" APR_SIZE_T_FMT "\r\n"
	            "Content-type: %s\r\n"
	            "%s"
	            "\r\n",
	            (phttp->ispost == 1) ? "POST" : "PUT",
	            (phttp->isproxy) ? phttp->fullurl : ((phttp->path!=NULL)?phttp->path :phttp->fullurl) ,
	            (phttp->keepalive) ? "Connection: Keep-Alive\r\n" : "",
	            (phttp->cookie != NULL)? phttp->cookie: "",
	            (phttp->auth != NULL)? phttp->auth : "" ,
	            phttp->postlen,
	            (phttp->content_type[0]) ? phttp->content_type : "text/plain",
	            (phttp->hdrs !=NULL)? phttp->hdrs : "");
	    }

	return 0;
}

static int connect_remost(flash_http *phttp)
{
	char *connecthost;
	apr_port_t connectport;
	apr_status_t rv;

	if (phttp->isproxy){
	     connecthost = apr_pstrdup(phttp->flash_pool, phttp->proxyhost);
	     connectport = phttp->proxyport;
	}
	else {
	   connecthost = apr_pstrdup(phttp->flash_pool, phttp->hostname);
	   connectport = phttp->port;
	}

	rv = apr_sockaddr_info_get(&(phttp->destsa), connecthost, APR_UNSPEC, connectport, 0, phttp->flash_pool);
	if(rv!= APR_SUCCESS) {
	   return 1;
	}

	rv = apr_socket_create(&(phttp->aprsock), phttp->destsa->family,SOCK_STREAM, 0, phttp->flash_pool);
	if(rv!=APR_SUCCESS){
		return 1;
	}

	rv = apr_socket_opt_set(phttp->aprsock, APR_SO_NONBLOCK, 1);
	if (rv!= APR_SUCCESS) {
	    return 1;
	}

	rv = apr_socket_connect(phttp->aprsock, phttp->destsa);
	if(APR_STATUS_IS_EINPROGRESS(rv)){
		return 0;
	}

	return 1;
}


static int write_request(flash_http *phttp)
{
	apr_size_t reqlen;
	char *allbuff=NULL;
	apr_size_t alllen;
	apr_size_t writelen;
	apr_size_t l;
	apr_status_t rv;

	reqlen = strlen(phttp->request);
	alllen=phttp->postlen + reqlen;
	allbuff=apr_pcalloc(phttp->flash_pool,alllen + 1);
	strcpy(allbuff, phttp->request);
	if(phttp->postlen > 0)
	memcpy(allbuff + reqlen, phttp->postdata, phttp->postlen);

	apr_socket_timeout_set(phttp->aprsock, phttp->timeout);
	writelen= 0 ;
	do {
		l=alllen-writelen;
		rv=apr_socket_send(phttp->aprsock, allbuff + writelen, &l);
		if (rv != APR_SUCCESS && !APR_STATUS_IS_EAGAIN(rv)) {
		     return 1;
		}
		writelen += l;
		alllen -= l;
	 }while(alllen>0);

	return 0;
}

static int read_response(flash_http *phttp)
{
	apr_status_t rv;
	apr_size_t rlen;
	char buffer[CREV_BUFFSIZE]={0};
	char *ptem=NULL;

	do{
		rlen=CREV_BUFFSIZE;
		rv = apr_socket_recv(phttp->aprsock, buffer, &rlen);
		if (APR_STATUS_IS_EAGAIN(rv)){
			usleep(100000);
	       continue;
		}
		else if (rlen == 0 && APR_STATUS_IS_EOF(rv)) {
	       return 0;
		}
		if(rlen > 0){
			ptem=apr_pcalloc(phttp->flash_pool,phttp->revsize + rlen);
			if(phttp->revbuffer){
				memcpy(ptem,phttp->revbuffer,phttp->revsize);
			}
			memcpy(ptem+phttp->revsize,buffer,rlen);
			phttp->revsize+=rlen;
			phttp->revbuffer=ptem;
		}
	}while(rv == APR_SUCCESS && rlen>0);

	return 0;
}


int openurl(apr_pool_t *p,const char *url,char**data,apr_size_t *len,server_rec *s)
{
	apr_status_t rv;
	flash_http myhttp;
	int blen=0;
	char *pdoc=NULL;
	rv=init_flash_http(p,&myhttp);
	if(rv==0){
		//ap_log_error(APLOG_MARK, 7, 0, s,"11111111111111111111111111");
		rv=parse_url(url,&myhttp);
		if(rv==0){
			//ap_log_error(APLOG_MARK, 7, 0, s,"222222222222222222222222222222");
			rv=prepare_data(&myhttp);
			if(rv==0){
				//ap_log_error(APLOG_MARK, 7, 0, s,"33333333333333333333333");
				rv=connect_remost(&myhttp);
				if(rv==0){
					//ap_log_error(APLOG_MARK, 7, 0, s,"44444444444444444444444");
					rv=write_request(&myhttp);
					if(rv==0){
						//ap_log_error(APLOG_MARK, 7, 0, s,"5555555555555555555555555555");
						rv=read_response(&myhttp);
						if(rv==0){
							//ap_log_error(APLOG_MARK, 7, 0, s,"%s||%d",myhttp.revbuffer,myhttp.revsize);
							if(myhttp.revbuffer!=NULL){
								pdoc=strstr(myhttp.revbuffer,"\r\n\r\n");
								if(pdoc!=NULL){
									blen=pdoc-myhttp.revbuffer+4;
									//ap_log_error(APLOG_MARK, 7, 0, s,"%d",blen);
									blen=myhttp.revsize-blen;
									//ap_log_error(APLOG_MARK, 7, 0, s,"%d",blen);
									*data=apr_pcalloc(p,blen);
									*len=blen;
									memcpy(*data,pdoc+4,blen);
								}
							}
						}
					}
				}
			}
		}
	}
	destory_flash_http(&myhttp);
	return rv;
}
