/* for select hash cluster for some client
 *2013-6-8
 *tpc client
 */

#ifndef APR_HASHCLUSTER_H
#define APR_HASHCLUSTER_H


#include "apr.h"
#include "apr_pools.h"
#include "apr_time.h"
#include "apr_strings.h"
#include "apr_network_io.h"
#include "apr_ring.h"
#include "apr_buckets.h"
#include "apr_reslist.h"
#include "apr_hash.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


typedef enum
{
    APR_HC_SERVER_LIVE, /**< Server is alive and responding to requests */
    APR_HC_SERVER_DEAD  /**< Server is not responding to requests */
} apr_hashcluster_server_status_t;


typedef struct apr_hashcluster_conn_t apr_hashcluster_conn_t;

/** hashcluster object -- contains each server shard */
typedef struct apr_hashcluster_t apr_hashcluster_t;


typedef struct apr_hashcluster_server_t apr_hashcluster_server_t;
struct apr_hashcluster_server_t
{
	const char *hplist;// host:port
    const char *host; /**< Hostname of this Server */
    apr_port_t port; /**< Port of this Server */
    apr_hashcluster_server_status_t status; /**< @see apr_hashcluster_server_status_t */
#if APR_HAS_THREADS || defined(DOXYGEN)
    apr_reslist_t *conns; /**< Resource list of actual client connections */
#else
    apr_hashcluster_conn_t *conn;
#endif
    apr_pool_t *p; /** Pool to use for private allocations */
#if APR_HAS_THREADS
    apr_thread_mutex_t *lock;
#endif
    apr_time_t btime;
    apr_hashcluster_t* hashcluster;
};

/* Custom hash callback function prototype, user for server selection.
* @param baton user selected baton
* @param data data to hash
* @param data_len length of data
*/
typedef apr_uint32_t (*apr_hashcluster_hash_func)(void *baton,
                                               const char *data,
                                               const apr_size_t data_len);

/* Custom Server Select callback function prototype.
* @param baton user selected baton
* @param hc hashcluster instance, use hc->live_servers to select a node
* @param hash hash of the selected key.
*/
typedef apr_hashcluster_server_t* (*apr_hashcluster_server_func)(void *baton,
                                                 apr_hashcluster_t *hc,
                                                 const apr_uint32_t hash);

/** Container for a set of hashcluster servers */
struct apr_hashcluster_t
{
    apr_uint32_t flags; /**< Flags, Not currently used */
    apr_uint16_t nalloc; /**< Number of Servers Allocated */
    apr_uint16_t ntotal; /**< Number of Servers Added */
    apr_hashcluster_server_t **live_servers; /**< Array of Servers */
    apr_pool_t *p; /** Pool to use for allocations */
    void *hash_baton;
    apr_hashcluster_hash_func hash_func;
    void *server_baton;
    apr_hashcluster_server_func server_func;
};


/**
 * Creates a crc32 hash used to split keys between servers
 * @param mc The hashcluster client object to use
 * @param data Data to be hashed
 * @param data_len Length of the data to use
 * @return crc32 hash of data
 * @remark The crc32 hash is not compatible with old hashcluster clients.
 */
APU_DECLARE(apr_uint32_t) apr_hashcluster_hash(apr_hashcluster_t *hc,
                                            const char *data,
                                            const apr_size_t data_len);

/**
 * Pure CRC32 Hash. Used by some clients.
 */
APU_DECLARE(apr_uint32_t) apr_hashcluster_hash_crc32(void *baton,
                                                  const char *data,
                                                  const apr_size_t data_len);

/**
 * hash compatible with the standard Perl Client.
 */
APU_DECLARE(apr_uint32_t) apr_hashcluster_hash_default(void *baton,
                                                    const char *data,
                                                    const apr_size_t data_len);

/**
 * Picks a server based on a hash
 * @param hc The hashcluster client object to use
 * @param hash Hashed value of a Key
 * @return server that controls specified hash
 * @see apr_hashcluster_hash
 */
APU_DECLARE(apr_hashcluster_server_t *) apr_hashcluster_find_server_hash(apr_hashcluster_t *hc,
                                                                   const apr_uint32_t hash);

/**
 * server selection compatible with the standard Perl Client.
 */
APU_DECLARE(apr_hashcluster_server_t *) apr_hashcluster_find_server_hash_default(void *baton,
                                                                           apr_hashcluster_t *hc,
                                                                           const apr_uint32_t hash);

/**
 * Adds a server to a client object
 * @param hc The hashcluster client object to use
 * @param server Server to add
 * @remark Adding servers is not thread safe, and should be done once at startup.
 * @warning Changing servers after startup may cause keys to go to
 * different servers.
 */
APU_DECLARE(apr_status_t) apr_hashcluster_add_server(apr_hashcluster_t *hc,
                                                  apr_hashcluster_server_t *server);


/**
 * Enables a Server for use again
 * @param hc The hashcluster client object to use
 * @param hashcluster Server to Activate
 */
APU_DECLARE(apr_status_t) apr_hashcluster_enable_server(apr_hashcluster_t *hc,
                                                     apr_hashcluster_server_t *hs);


/**
 * Disable a Server
 * @param hc The hashcluster client object to use
 * @param hs Server to Disable
 */
APU_DECLARE(apr_status_t) apr_hashcluster_disable_server(apr_hashcluster_t *hc,
                                                      apr_hashcluster_server_t *hs);

/**
 * Creates a new Server Object
 * @param p Pool to use
 * @param host hostname of the server
 * @param port port of the server
 * @param min  minimum number of client sockets to open
 * @param smax soft maximum number of client connections to open
 * @param max  hard maximum number of client connections
 * @param ttl  time to live in microseconds of a client connection
 * @param ns   location of the new server object
 * @see apr_reslist_create
 * @remark min, smax, and max are only used when APR_HAS_THREADS
 */
APU_DECLARE(apr_status_t) apr_hashcluster_server_create(apr_pool_t *p,
                                                     const char *host,
                                                     apr_port_t port,
                                                     apr_uint32_t min,
                                                     apr_uint32_t smax,
                                                     apr_uint32_t max,
                                                     apr_uint32_t ttl,
                                                     apr_hashcluster_server_t **ns);
/**
 * Creates a new hashcluster client object
 * @param p Pool to use
 * @param max_servers maximum number of servers
 * @param flags Not currently used
 * @param hc   location of the new hashcluster client object
 */
APU_DECLARE(apr_status_t) apr_hashcluster_create(apr_pool_t *p,
                                              apr_uint16_t max_servers,
                                              apr_uint32_t flags,
                                              apr_hashcluster_t **hc);

/**
 * find host and port by key
 * @param hc client to use
 * @param p Pool to use
 * @param key null terminated string containing the key
 * @param hplist allocated for host and port
 */
apr_status_t apr_hashcluster_get_server(apr_hashcluster_t *hc,
		apr_pool_t *p,const char *key,char ** hplist);



/** @} */

#ifdef __cplusplus
}
#endif

#endif /* APR_HASHCLUSTER_H */
