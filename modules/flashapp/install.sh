#sudo ../../support/apxs -c -i -n flashapp  mod_flashapp.c apr_flash.c apr_memcache2.c
sudo /usr/local/apache2/bin/apxs -c  -lmysqlclient  -i -n flashapp  mod_flashapp.c apr_flash.c apr_memcache2.c apr_hashcluster.c  apr_flash_http.c -Wl,-rpath=/usr/local/apache2/lib -ljson
