sudo /usr/local/apache2/bin/apxs -c -i -a mod_cache.c cache_util.c cache_cache.c cache_storage.c cache_pqueue.c cache_hash.c 
sudo /usr/local/apache2/bin/apxs -c -i -a mod_disk_cache.c cache_util.c cache_cache.c cache_storage.c cache_pqueue.c cache_hash.c 
sudo /usr/local/apache2/bin/apxs -c -i -a mod_mem_cache.c cache_util.c cache_cache.c cache_storage.c cache_pqueue.c cache_hash.c
