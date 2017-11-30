/*
 *
 *hashcluster client
 */

#include "apr_hashcluster.h"
#include "apr_poll.h"
#include "apr_version.h"
#include <assert.h>
#include <stdlib.h>

#define HC_BUFFER_SIZE 512


#define HC_EOL "\r\n"
#define HC_EOL_LEN (sizeof(HC_EOL)-1)

//退出命令要改成动态的，不同的服务器不同， 现在是为squid 的
#define HC_QUIT "HEAD http://www.baidu.com/ HTTP/1.0"
#define HC_QUIT_LEN (sizeof(HC_QUIT)-1)

struct apr_hashcluster_conn_t
{
    char *buffer;
    apr_size_t blen;
    apr_pool_t *p;
    apr_pool_t *tp;
    apr_socket_t *sock;
    apr_bucket_brigade *bb;
    apr_bucket_brigade *tb;
    apr_hashcluster_server_t *hs;
};

/**
 * Indicates whewther a lock is held when calling helper functions from either
 * state.
 */
typedef enum {
  HC_LOCK_NOT_HELD,
  HC_LOCK_HELD
} lock_status_t;

static apr_status_t mark_server_dead(apr_hashcluster_server_t *hs,
                                     lock_status_t lock_status)
{
#if APR_HAS_THREADS
    if (lock_status == HC_LOCK_NOT_HELD) {
        apr_thread_mutex_lock(hs->lock);
    }
#endif
    hs->status = APR_HC_SERVER_DEAD;
    hs->btime = apr_time_now();
#if APR_HAS_THREADS
    if (lock_status == HC_LOCK_NOT_HELD) {
        apr_thread_mutex_unlock(hs->lock);
    }
#endif
    return APR_SUCCESS;
}

static apr_status_t make_server_live(apr_hashcluster_t *hc, apr_hashcluster_server_t *hs)
{
    hs->status = APR_HC_SERVER_LIVE;
    return APR_SUCCESS;
}


APU_DECLARE(apr_status_t) apr_hashcluster_add_server(apr_hashcluster_t *hc, apr_hashcluster_server_t *hs)
{
    apr_status_t rv = APR_SUCCESS;

    if(hc->ntotal >= hc->nalloc) {
        return APR_ENOMEM;
    }

    hc->live_servers[hc->ntotal] = hs;
    hc->ntotal++;
    hs->hashcluster = hc;
    make_server_live(hc, hs);
    return rv;
}

static apr_status_t hc_version_ping_lock_held(apr_hashcluster_server_t *hs);

APU_DECLARE(apr_hashcluster_server_t *)
apr_hashcluster_find_server_hash(apr_hashcluster_t *hc, const apr_uint32_t hash)
{
    if (hc->server_func) {
        return hc->server_func(hc->server_baton, hc, hash);
    }
    else {
        return apr_hashcluster_find_server_hash_default(NULL, hc, hash);
    }
}

APU_DECLARE(apr_hashcluster_server_t *)
apr_hashcluster_find_server_hash_default(void *baton, apr_hashcluster_t *hc,
                                      const apr_uint32_t hash)
{
    apr_hashcluster_server_t *hs = NULL;
    apr_uint32_t h = hash ? hash : 1;
    apr_uint32_t i = 0;
    apr_time_t curtime = 0;

    if(hc->ntotal == 0) {
        return NULL;
    }

    do {
        hs = hc->live_servers[h % hc->ntotal];
        if(hs->status == APR_HC_SERVER_LIVE) {
            break;
        }
        else {
            if (curtime == 0) {
                curtime = apr_time_now();
            }
#if APR_HAS_THREADS
            apr_thread_mutex_lock(hs->lock);
#endif
            /* Try the the dead server, every 5 seconds, keeping the lock. */
            if (curtime - hs->btime >  apr_time_from_sec(5)) {
                if (hc_version_ping_lock_held(hs) == APR_SUCCESS) {
                    hs->btime = curtime;
                    make_server_live(hc, hs);
#if APR_HAS_THREADS
                    apr_thread_mutex_unlock(hs->lock);
#endif
                    break;
                }
            }
#if APR_HAS_THREADS
            apr_thread_mutex_unlock(hs->lock);
#endif
        }
        h++;
        i++;
    } while(i < hc->ntotal);

    if (i == hc->ntotal) {
        hs = NULL;
    }

    return hs;
}

static apr_status_t hs_find_conn(apr_hashcluster_server_t *hs, apr_hashcluster_conn_t **conn)
{
    apr_status_t rv;
    apr_bucket_alloc_t *balloc;
    apr_bucket *e;

#if APR_HAS_THREADS
    rv = apr_reslist_acquire(hs->conns, (void **)conn);
#else
    *conn = ms->conn;
    rv = APR_SUCCESS;
#endif

    if (rv != APR_SUCCESS) {
        return rv;
    }
/*
    balloc = apr_bucket_alloc_create((*conn)->tp);
    (*conn)->bb = apr_brigade_create((*conn)->tp, balloc);
    (*conn)->tb = apr_brigade_create((*conn)->tp, balloc);

    e = apr_bucket_socket_create((*conn)->sock, balloc);
    APR_BRIGADE_INSERT_TAIL((*conn)->bb, e);
*/

    return rv;
}

static apr_status_t hs_bad_conn(apr_hashcluster_server_t *hs, apr_hashcluster_conn_t *conn)
{
#if APR_HAS_THREADS
    return apr_reslist_invalidate(hs->conns, conn);
#else
    return APR_SUCCESS;
#endif
}

static apr_status_t hs_release_conn(apr_hashcluster_server_t *hs, apr_hashcluster_conn_t *conn)
{
    apr_pool_clear(conn->tp);
#if APR_HAS_THREADS
    return apr_reslist_release(hs->conns, conn);
#else
    return APR_SUCCESS;
#endif
}

APU_DECLARE(apr_status_t) apr_hashcluster_enable_server(apr_hashcluster_t *hc, apr_hashcluster_server_t *hs)
{
    apr_status_t rv = APR_SUCCESS;

    if (hs->status == APR_HC_SERVER_LIVE) {
        return rv;
    }

    rv = make_server_live(hc, hs);
    return rv;
}

APU_DECLARE(apr_status_t) apr_hashcluster_disable_server(apr_hashcluster_t *hc, apr_hashcluster_server_t *hs)
{
    assert(hc == hs->hashcluster);
    return mark_server_dead(hs, HC_LOCK_NOT_HELD);
}

/*
 * Cleans up connections and/or bad servers as required.
 *
 * This function should only be called if rv is not APR_SUCCESS.
 */
static void disable_server_and_connection(apr_hashcluster_server_t *hs,
                                          lock_status_t lock_status,
                                          apr_hashcluster_conn_t *conn) {
    if (conn != NULL) {
        hs_bad_conn(hs, conn);
    }
    mark_server_dead(hs, lock_status);
}


static apr_status_t conn_connect(apr_hashcluster_conn_t *conn)
{
    apr_status_t rv = APR_SUCCESS;
    apr_sockaddr_t *sa=NULL;

    rv = apr_sockaddr_info_get(&sa, conn->hs->host, APR_INET, conn->hs->port, 0, conn->p);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    rv = apr_socket_timeout_set(conn->sock, 1 * APR_USEC_PER_SEC);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    rv = apr_socket_connect(conn->sock, sa);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    rv = apr_socket_timeout_set(conn->sock, -1);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    return rv;
}

static apr_status_t conn_clean(void *data)
{
    apr_hashcluster_conn_t *conn = data;
    struct iovec vec[3];
    apr_size_t written;

    /* send a quit message to the hash cluster server to be nice about it. */
    vec[0].iov_base = (char*) HC_QUIT;
    vec[0].iov_len = HC_QUIT_LEN;

    vec[1].iov_base = (char*) HC_EOL;
    vec[1].iov_len = HC_EOL_LEN;

    vec[2].iov_base = (char*) HC_EOL;
    vec[2].iov_len = HC_EOL_LEN;

    /* Return values not checked, since we just want to make it go away. */
    apr_socket_sendv(conn->sock, vec, 3, &written);
    apr_socket_close(conn->sock);

    conn->p = NULL; /* so that destructor does not destroy the pool again */

    return APR_SUCCESS;
}

static apr_status_t
hc_conn_construct(void **conn_, void *params, apr_pool_t *pool)
{
    apr_status_t rv = APR_SUCCESS;
    apr_hashcluster_conn_t *conn;
    apr_pool_t *np;
    apr_pool_t *tp;
    apr_hashcluster_server_t *hs = params;

    rv = apr_pool_create(&np, pool);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    rv = apr_pool_create(&tp, np);
    if (rv != APR_SUCCESS) {
        apr_pool_destroy(np);
        return rv;
    }

#if APR_HAS_THREADS
    conn = malloc(sizeof( apr_hashcluster_conn_t )); /* non-pool space! */
#else
    conn = apr_palloc(np, sizeof( apr_hashcluster_conn_t ));
#endif

    conn->p = np;
    conn->tp = tp;

    rv = apr_socket_create(&conn->sock, APR_INET, SOCK_STREAM, 0, np);

    if (rv != APR_SUCCESS) {
        apr_pool_destroy(np);
#if APR_HAS_THREADS
        free(conn);
#endif
        return rv;
    }

    conn->buffer = apr_palloc(conn->p, HC_BUFFER_SIZE);
    conn->blen = 0;
    conn->hs = hs;

    rv = conn_connect(conn);
    if (rv != APR_SUCCESS) {
        apr_pool_destroy(np);
#if APR_HAS_THREADS
        free(conn);
#endif
    }
    else {
        apr_pool_cleanup_register(np, conn, conn_clean, apr_pool_cleanup_null);
        *conn_ = conn;
    }

    return rv;
}

#if APR_HAS_THREADS
static apr_status_t
hc_conn_destruct(void *conn_, void *params, apr_pool_t *pool)
{
    apr_hashcluster_conn_t *conn = (apr_hashcluster_conn_t*)conn_;

    if (conn->p) {
        apr_pool_destroy(conn->p);
    }

    free(conn); /* free non-pool space */

    return APR_SUCCESS;
}
#endif

APU_DECLARE(apr_status_t) apr_hashcluster_server_create(apr_pool_t *p,
                                                     const char *host, apr_port_t port,
                                                     apr_uint32_t min, apr_uint32_t smax,
                                                     apr_uint32_t max, apr_uint32_t ttl,
                                                     apr_hashcluster_server_t **hs)
{
    apr_status_t rv = APR_SUCCESS;
    apr_hashcluster_server_t *server;
    apr_pool_t *np;

    rv = apr_pool_create(&np, p);

    server = apr_palloc(np, sizeof(apr_hashcluster_server_t));

    server->hplist = apr_pstrcat(np,host,":",apr_itoa(np,port),NULL);
    server->p = np;
    server->host = apr_pstrdup(np, host);
    server->port = port;
    server->status = APR_HC_SERVER_DEAD;
    server->hashcluster = NULL;
#if APR_HAS_THREADS
    rv = apr_thread_mutex_create(&server->lock, APR_THREAD_MUTEX_DEFAULT, np);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    rv = apr_reslist_create(&server->conns,
                               min,                     /* hard minimum */
                               smax,                    /* soft maximum */
                               max,                     /* hard maximum */
                               ttl,                     /* Time to live */
                               hc_conn_construct,       /* Make a New Connection */
                               hc_conn_destruct,        /* Kill Old Connection */
                               server, np);
#else
    rv = hc_conn_construct((void**)&(server->conn), server, np);
#endif

    if (rv != APR_SUCCESS) {
        return rv;
    }

    *hs = server;

    return rv;
}

APU_DECLARE(apr_status_t) apr_hashcluster_create(apr_pool_t *p,
                                              apr_uint16_t max_servers, apr_uint32_t flags,
                                              apr_hashcluster_t **hashcluster)
{
    apr_status_t rv = APR_SUCCESS;
    apr_hashcluster_t *hc;

    hc = apr_palloc(p, sizeof(apr_hashcluster_t));
    hc->p = p;
    hc->nalloc = max_servers;
    hc->ntotal = 0;
    hc->live_servers = apr_palloc(p, hc->nalloc * sizeof(struct apr_hashcluster_server_t *));
    hc->hash_func = NULL;
    hc->hash_baton = NULL;
    hc->server_func = NULL;
    hc->server_baton = NULL;
    *hashcluster = hc;
    return rv;
}


/* The crc32 functions and data was originally written by Spencer
 * Garrett <srg@quick.com> and was gleaned from the PostgreSQL source
 * tree via the files contrib/ltree/crc32.[ch] and from FreeBSD at
 * src/usr.bin/cksum/crc32.c.
 */

static const apr_uint32_t crc32tab[256] = {
  0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
  0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
  0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
  0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
  0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
  0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
  0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
  0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
  0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
  0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
  0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
  0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
  0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
  0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
  0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
  0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
  0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
  0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
  0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
  0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
  0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
  0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
  0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
  0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
  0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
  0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
  0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
  0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
  0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
  0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
  0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
  0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
  0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
  0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
  0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
  0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
  0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
  0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
  0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
  0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
  0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
  0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
  0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
  0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
  0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
  0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
  0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
  0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
  0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
  0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
  0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
  0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
  0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
  0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
  0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
  0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
  0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
  0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
  0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
  0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
  0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
  0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
  0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
  0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d,
};

APU_DECLARE(apr_uint32_t) apr_hashcluster_hash_crc32(void *baton,
                                                  const char *data,
                                                  const apr_size_t data_len)
{
    apr_uint32_t i;
    apr_uint32_t crc;
    crc = ~0;

    for (i = 0; i < data_len; i++)
        crc = (crc >> 8) ^ crc32tab[(crc ^ (data[i])) & 0xff];

    return ~crc;
}

APU_DECLARE(apr_uint32_t) apr_hashcluster_hash_default(void *baton,
                                                    const char *data,
                                                    const apr_size_t data_len)
{
    /* The default Perl Client doesn't actually use just crc32 -- it shifts it again
     * like this....
     */
    return ((apr_hashcluster_hash_crc32(baton, data, data_len) >> 16) & 0x7fff);
}

APU_DECLARE(apr_uint32_t) apr_hashcluster_hash(apr_hashcluster_t *hc,
                                            const char *data,
                                            const apr_size_t data_len)
{
    if (hc->hash_func) {
        return hc->hash_func(hc->hash_baton, data, data_len);
    }
    else {
        return apr_hashcluster_hash_default(NULL, data, data_len);
    }
}


static apr_status_t hc_version_ping_lock_held(apr_hashcluster_server_t *hs)
{
    apr_status_t rv;
    struct iovec vec[2];
    apr_hashcluster_conn_t *conn=NULL;

    rv = hs_find_conn(hs, &conn);

    if (rv != APR_SUCCESS) {
    	disable_server_and_connection(hs, HC_LOCK_HELD, conn);
        return rv;
    }

    hs_release_conn(hs, conn);
    return rv;
}


apr_status_t apr_hashcluster_get_server(apr_hashcluster_t *hc,
		apr_pool_t *p,const char *key,char ** hplist)
{
    apr_status_t rv=-1;
    apr_hashcluster_server_t *hs=NULL;
    apr_hashcluster_conn_t *conn=NULL;
    apr_uint32_t hash;
    apr_size_t klen = strlen(key);
    if((hc!=NULL) && (key!=NULL)){
    	hash = apr_hashcluster_hash(hc, key, klen);
    	hs = apr_hashcluster_find_server_hash(hc, hash);
    	if (hs == NULL)
    		return APR_NOTFOUND;

    	rv = hs_find_conn(hs, &conn);

    	if (rv != APR_SUCCESS) {
    		disable_server_and_connection(hs, HC_LOCK_NOT_HELD, conn);
    		return rv;
    	}

    	*hplist=apr_pstrdup(p,hs->hplist);

    	hs_release_conn(hs, conn);

    	rv=APR_SUCCESS;
    }

    return rv;
}
