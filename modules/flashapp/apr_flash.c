/* 
**  apr_flashapp.c -- Apache  flashapp
*/ 
//#include "apr_flash_http.h"
#include "apr_flash.h"

#define MAX_CONTECT_IMAGE_BUF 65536

//memcache 参数
const int kDefaultMcServerPort = 11211;
const int kDefaultMcServerMin = 0;
const int kDefaultMcServerSmax = 1;
const int kDefaultMcServerTtlUs = 600*1000*1000;

const char kXFlashProxyVideo[]=".flashsdkvideo";
const char kXFlashProxyAudio[]=".flashsdkaudio";

const char *MSG_KEY_FILES[2] =
        {
                "/usr/bin",
                "/bin"
        };
#define PERM S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IWOTH|S_IROTH
#define MSG_MAX_NUMS 2
#define MSG_PROJ_ID 'p'
#define MSG_TYPE 51169

////////////////////--------------日志函数------------------------///////////////////////////
void flash_log_printf(const char *file, int line, int level,
        apr_status_t status,LOG_TYPE itype,const void * vtype ,const char *fmt, ...)
{
	const request_rec *r=NULL;
	const conn_rec *c=NULL;
	const server_rec *s=NULL;
	apr_pool_t *p=NULL;
	va_list args;
	char buffer[MAX_STRING_LEN]={0};

#ifndef NO_LOG
	if(vtype!=NULL && fmt!=NULL){
		va_start(args, fmt);
		apr_vsnprintf(buffer, sizeof(buffer), fmt, args);
		va_end(args);
		if(itype == S_LOG){
			s=(const server_rec *)vtype;
			ap_log_error(file, line, level,status, s,"%s [pid:%d]",buffer,getpid());
		}else if(itype == C_LOG){
			c=(const conn_rec *)vtype;
			ap_log_cerror(file, line, level,status, c,"%s [pid:%d]",buffer,getpid());
		}else if(itype == R_LOG){
			r=(const request_rec *)vtype;
			ap_log_rerror(file, line, level,status, r,"%s [pid:%d]",buffer,getpid());
		}else if(itype == P_LOG){
			p=(apr_pool_t *)vtype;
			ap_log_perror(file, line, level,status, p,"%s [pid:%d]",buffer,getpid());
		}
	}
#endif
}

/**
 * 显示 http 头  调试
 */
int show_allhead(void *rec, const char *key, const char *value)
{
	request_rec *r=(request_rec *)rec;
	flash_log_printf(FLASHLOG_MARK,S_LOG,r->server,"[header]%s:%s",key,value);
	return 1;
}

void flash_log_printf_headers(request_rec *r, const apr_table_t *headers , const char *pinfo)
{
	flash_log_printf(FLASHLOG_MARK,S_LOG,r->server,"[header]###############%s##############",pinfo);
	if(r->status_line!=NULL){
		flash_log_printf(FLASHLOG_MARK,S_LOG,r->server,"[header]%s",r->status_line);
	}
	apr_table_do(show_allhead, (void*)r,headers, NULL);
	flash_log_printf(FLASHLOG_MARK,S_LOG,r->server,"[header]###############################");

}
//////////////////////////////////--------辅助功能函数-----------------//////////////////////////////////
/**
 * 读取json
 * 获取域名 ip 对应
 * list_hash  存放地址
 * filepath  文件地址
 */
static int get_hosts_fromjson(apr_pool_t *p,apr_hash_t *list_hash,char * filepath,server_rec *s)
{
	json_object *new_obj=NULL;
	json_object *val_obj=NULL,*val=NULL;
	array_list *new_list=NULL;
	struct lh_entry *entry =NULL;
	char *key=NULL;
	const char *data = NULL;
	char *chost=NULL;
	int i=0;

	flash_log_printf(FLASHLOG_MARK,S_LOG, s,"get_hosts_fromjson path%s ",filepath);

	if(filepath!=NULL && (0==access(filepath,R_OK))){
		new_obj=json_object_from_file(filepath);
		if(new_obj){
			new_list=json_object_get_array(new_obj);//(struct json_object *)(json_object_get_object(new_obj)->head)->v);
		}
		for(i=0;i< array_list_length(new_list); i++){
			val_obj = (struct json_object *) array_list_get_idx(new_list, i);
			if(val_obj){
				for (entry = json_object_get_object(val_obj)->head; entry; entry = entry->next){
					key = (char *) entry->k;
			        val = (struct json_object *) entry->v;
			        if (strcmp(key, "domain") == 0) {
			        	data=json_object_get_string(val);
			        	if(data!=NULL){
			        		chost=apr_pstrdup(p,data);
			        		char *pt=strstr(chost,".flash");
			        		if(pt!=NULL){
			        			*pt='\0';
			                }else{
			                	pt=strstr(chost,".fast");
			                	if(pt!=NULL){
			                		*pt='\0';
			                	}
			                }
			             }
			        }else if(strcmp(key, "ips") == 0){
			        	data=json_object_get_string(val);
			            data=apr_pstrdup(p,data);
			        }
				}
			 	 //添加
			 	 if((chost!=NULL)&&(data!=NULL)){
			 		//flash_log_printf(FLASHLOG_MARK,S_LOG, s,"get_hosts_fromjson read content -  %s  %s \n",chost,data);
			 		apr_hash_set(list_hash,chost, APR_HASH_KEY_STRING, data);
			 	 }
			}
		}
		if(new_obj){
			json_object_put(new_obj);
		}
	}
	return apr_hash_count(list_hash);
}

/**
 * 读取根据ip获取域名
 * ipbuf  ip地址
 * 返回域名
 * flist_hash 列表
 */
static char* get_host_fromip(request_rec *r,apr_hash_t *list_hash,const char * ipbuf)
{
	int i=0;
	const char *key= NULL;
	const char *data= NULL;
	char *phost = NULL;
	apr_hash_index_t *hi=NULL;
	//两次 fixup  第二次 list_hash 为空
	//flash_log_printf(FLASHLOG_MARK,R_LOG, r,"start get_host_fromip  %s   %d",ipbuf,list_hash);
	if(ipbuf!=NULL && list_hash!=NULL){
		if(apr_hash_count(list_hash)>0){
			for (hi = apr_hash_first(r->pool, list_hash); hi; hi = apr_hash_next(hi)) {
				apr_hash_this(hi, (const void**)&key, NULL, (void**)&data);
				if((data!=NULL)&&(key!=NULL)){
					if(strstr(data,ipbuf)!=NULL){
						phost=apr_pstrdup(r->pool,key);
						flash_log_printf(FLASHLOG_MARK,R_LOG, r,"get_host_fromip host: %s ips: %s ",key,data);
					}
				}
			}
		}
	}
	return phost;
}

////md5 校验算法
/**
 * 生成md5
 */
static int data_to_md5 (const char *data, char *md5res)
{
	unsigned int len = strlen (data);
	apr_md5_ctx_t context;
	unsigned char digest[16]={0};
	if(md5res!=NULL){
		apr_md5_init(&context);
		apr_md5_update(&context, (const unsigned char *) data, len);
		apr_md5_final(digest, &context);
		memcpy(md5res,digest,16);
		return OK;
	}
	return DECLINED;
}

/**
 * 生成验证的agent 和 host  的key
 * agent 处理过的agent
 * host  域名
 * xres 返回32位md5字符串
 */
static int make_agent_key(const char*agent,const char*host,char *xres,server_rec *s)
{
	int icount =0;
	char *pcount=NULL;
	char agentxbuf[513]={0};
	unsigned char md5age[17]={0};
	int alen=0;

	//转换16进制
	if(agent!=NULL){
		alen=strlen(agent);
		pcount=(char *)agent;
		for(icount=0;icount< alen;icount++){
			sprintf(agentxbuf,"%s%02x",agentxbuf,(unsigned char)(*pcount));
			pcount++;
		}
	}
	//转换16进制
	if(host!=NULL){
		alen=strlen(host);
		pcount=(char *)host;
		for(icount=0;icount< alen;icount++){
			sprintf(agentxbuf,"%s%02x",agentxbuf,(unsigned char)(*pcount));
			pcount++;
		}
	}

	if(s!=NULL){
		flash_log_printf(FLASHLOG_MARK,S_LOG, s,"the agent is %s host is %s xagent is %s ",
				agent,host,agentxbuf);
	}
	//md5 16
	if(0 == data_to_md5(agentxbuf,md5age)){
		for(icount=0;icount<16;icount++){
			sprintf(xres,"%s%02x",xres,md5age[icount]);
		}
	}else{
		//md5 error
		//ires=1;
		strncpy(xres,agentxbuf,32);
	}

	return OK;
}

/**
 * 生成验证key
 * data  字符串 最长使用 256 个字符
 * alen 字符串长度
 * xres 返回32位md5字符串
 */
static int make_auth_key(const char*data,int alen,char *xres)
{
	int icount =0;
	char *pcount=NULL;
	char xbuff[513]={0};
	unsigned char md5age[17]={0};
	char *hex = "0123456789abcdef";

	//最大长度 256个字符
	if(alen>256)
		alen=256;

	if(data!=NULL&&xres!=NULL){
		//包含中文 //中文赋值会直接变成16进制数
		pcount=(char *)data;
		for(icount=0;icount< alen;icount++){
			sprintf(xbuff,"%s%02x",xbuff,(unsigned char)(*pcount));
			pcount++;
		}

		//md5 16 to 32
		if(0 == data_to_md5(xbuff,md5age)){
			//无中文16进制转换
			for (icount = 0, pcount=xres; icount < 16; icount++) {
				*pcount++ = hex[md5age[icount] >> 4];
				*pcount++ = hex[md5age[icount] & 0xF];
			}
		}else{
			memcpy(xres,xbuff,32);
		}

		return OK;
	}
/*
for(icount=0,pcount=data;icount< alen;icount++){
sprintf(xbuff,"%s%02x",xbuff,(unsigned char)(*pcount));
pcount++;
}

for(icount=0;icount<16;icount++){
sprintf(xres,"%s%02x",xres,md5age[icount]);
}
*/
	return DECLINED;
}

/**
 * 生城客户端验证token
 * ptoken    生成的tocket 32位
 */
static int make_client_token(char* ptoken)
{
	char tbuf[21]={0};
	apr_time_t now;
	now=apr_time_now();
	apr_snprintf(tbuf, 20, "%" APR_TIME_T_FMT, now);
	make_auth_key(tbuf,20,ptoken);
	return OK;
}

//消息队列函数

/*
 * get the msgid of the msg queue with index of idx
 * return value:
 * > 0: msgid on success
 * -1 : error happens
 */
static int get_msg(int idx)
{
	key_t key;
	int msgid;

	if ( idx > MSG_MAX_NUMS - 1 || idx < 0)
	{
		return DECLINED;
	}

	if ( (key = ftok(MSG_KEY_FILES[idx], MSG_PROJ_ID)) == -1 )
	{
		return DECLINED;
	}

	if( (msgid = msgget(key, PERM)) == -1 )
	{
		if (errno == ENOENT)
		{
			/* no msg queue available, need to create it */
			if( (msgid = msgget(key, PERM | IPC_CREAT | IPC_EXCL)) == -1 )
			{
				return DECLINED;
			}
			else
				return msgid;
		}

		return DECLINED;
	}
	else
		return msgid;
}

/**
 *remove the   msgque with msgid
 */
static int message_remove()
{
	int msgid;
	int index;

	for (index = 0; index < MSG_MAX_NUMS; index++)
	{
		msgid = get_msg(index);
		if (msgid >= 0)
		{
			/* msgqueue exists */
			if ( msgctl(msgid, IPC_RMID, NULL) < 0 )
			{
				//perror("msgctl with IPC_RMID failed");
				return -1;
			}
		}
	}

	return 0;
}
/**
 *send the message to the msgque with msgid
 */
static int message_send(int index, flash_msg_item_t* p_item, int len)
{
	int idx = index % MSG_MAX_NUMS;
	int msgid = get_msg(idx);
	int icount=0;
	/* If  IPC_NOWAIT  is specified in msgflg, then the
	   call instead fails with the error EAGAIN.
	 */
	int msgflg =IPC_NOWAIT;
	int rc;
	if(msgid >= 0){
		p_item->msg_type = MSG_TYPE;
		do{
			rc = msgsnd(msgid, p_item, len, msgflg);
			//rc= errno;
			icount++;
			apr_sleep(10000);
		}while((errno == EAGAIN)&& (icount < 5)&& (rc <0));

		if(rc < 0){
			return DECLINED;
			//return msgid;
		}
		return OK;
	}
	return DECLINED;
}

/* recv the message from the msgque with msgid
 * return value:
 * > 0: msg lengh got from the msgqueue
 * = 0: no more message in the msgqueue
 * < 0: error happens
 */
static int message_recv(int index, flash_msg_item_t* p_item, int len)
{
	int idx = index % MSG_MAX_NUMS;
	int msgid = get_msg(idx);
	/* If  IPC_NOWAIT  is specified in msgflg, then the
	   call instead fails with the error EAGAIN.
	 */
	int msgflg = IPC_NOWAIT;
	int rc=DECLINED;
	if(msgid >=0 ){
		rc = msgrcv(msgid, p_item, len, MSG_TYPE, msgflg);
		if (rc < 0)
		{
			if (errno == ENOMSG || errno == EAGAIN)
			{
				return OK;
			}
			else
			{
				return DECLINED;
			}
		}
	}

	return rc;
}
/////////////////////////
/*
 *字符替换
 */
static int replace_char(char *sSrc, char cMatchChar, char cReplaceChar)
{
	char *p = sSrc;
	while (p && *p)
	{
		if (*p == cMatchChar)
		{
			*(sSrc + (p - sSrc)) = cReplaceChar;
		}
		p++;
	}
	return 0;
}

/* url 解码
 *dst  目的
 *src  源
 *size  源长度 包含结束符号
 *
 */
static void urldecode(char *dst, const char *src, int size)
{
   char tmp[3];
   tmp[2] = '\0';
   while (*src && size > 1) {
       if (*src == '%' && src[1] != '\0' && src[2] != '\0') {
           ++src;
           tmp[0] = *src;
           ++src;
           tmp[1] = *src;
           ++src;
           *dst = strtol(tmp, NULL, 16);
           ++dst;
       } else {
           *dst = *src;
           ++dst;
           ++src;
       }

       --size;
   }
   *dst = '\0';
}

/* 清理agent
 * 去掉 版本号
 * (
 * [
 *\/
 * 都去掉
 * srcagent 原agent 最长 1024
 * newagent 转化后agent 最长 64
 *
 */
static void translate_agent(const char *srcagent,char * newagent)
{
	char *oldagent=NULL;
	char *pagent=NULL;
	char abuffer[1024]={0};
	int agentlen=0;
	int ifcheck=0;
	int inalen=0;
	int iarr[10]={0};
	int irk=0;

	oldagent=(char *)srcagent;
	if(oldagent!=NULL){

		if(strstr(oldagent,"_weibo_") != NULL ){
			strcpy(newagent,"weibo");
			return;
		}
		agentlen=strlen(oldagent)+1;
		//去掉之前的空格
		while (agentlen >2){
			if(*oldagent == ' '){
				oldagent++;
				agentlen--;
			}else{
				break;
			}
		}


		if(agentlen>1024)
			agentlen=1024;

		pagent=abuffer;
		urldecode(pagent,oldagent, agentlen);

		//check "."   versoin  demo  1.2.3
		ifcheck=strcspn(pagent,".");
		if(ifcheck>0){
			while(ifcheck>0 && (isdigit(pagent[ifcheck-1]))>0){
			//while(ifcheck>0&&((pagent[ifcheck-1])>='0')&&((pagent[ifcheck-1])<='9')){
				ifcheck--;
			}
		}

		if(ifcheck>0){
			iarr[irk]=ifcheck;
			irk++;
		}

		// check "("
		ifcheck=strcspn(pagent,"(");
		if(ifcheck>0){
			iarr[irk]=ifcheck;
			irk++;
		}

		// check "/"
		ifcheck=strcspn(pagent,"/");
		if(ifcheck>0){
			iarr[irk]=ifcheck;
			irk++;
		}

		// check "/"
		ifcheck=strcspn(pagent,"[");
		if(ifcheck>0){
			iarr[irk]=ifcheck;
			irk++;
		}

		if(irk>0){
			inalen=iarr[irk-1];
			for(;irk>0;irk--){
				if(inalen>iarr[irk-1])
					inalen=iarr[irk-1];
			}
			if(inalen>0){
				if(inalen>63)
					inalen=63;
				strncpy(newagent,pagent,inalen);
			}
		}else{
			inalen=agentlen;
			if(inalen>63)
				inalen=63;
			strncpy(newagent,oldagent,inalen);
		}

		if(inalen>0){
			replace_char(newagent,'\'','"');
			//去掉,号 和数据导入有关系
			replace_char(newagent,',',' ');
			replace_char(newagent,'{',' ');
			replace_char(newagent,'}',' ');
			replace_char(newagent,';',' ');
			//去掉之后的空格
			agentlen=strlen(newagent);
			//去掉之后的空格
			while (agentlen >1){
				if(newagent[agentlen-1] == ' '){
					newagent[agentlen-1]=0;
					agentlen--;
				}else{
					break;
				}
			}
		}
	}
}

/**
 *初始化hashcluster client
 */
apr_status_t init_hashcluster(apr_pool_t *p,const char* hosts,apr_hashcluster_t **hc)
{
	 apr_status_t rv=-1;
	 int thread_limit = 50;
	 int nservers = 0;
	 char *host_list;
	 char *split;
	 char *tok;

	 if(hosts==NULL){
		 return rv;
	 }
	 ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);

	 //计算服务器数量
	 host_list = apr_pstrdup(p, hosts);
	 split = apr_strtok(host_list, ",", &tok);
	 while (split) {
	        nservers++;
	        split = apr_strtok(NULL,",", &tok);
	 }

	 rv=apr_hashcluster_create(p, nservers, 0, hc);

	 if (rv == APR_SUCCESS && nservers > 0) {//添加服务器
		 	 host_list = apr_pstrdup(p, hosts);
			 split = apr_strtok(host_list, ",", &tok);
			 while (split) {
				 	 apr_hashcluster_server_t *st=NULL;
				     char *host_str=NULL;
				     char *scope_id=NULL;
				     apr_port_t port;
				     rv = apr_parse_addr_port(&host_str, &scope_id, &port, split, p);
				     if(rv!=APR_SUCCESS)
				    	 return rv;
				     if (host_str == NULL)
				    	 host_str=apr_pstrdup(p,"127.0.0.1");
				     if (port == 0) {
				         port = 80;
				     }

				     rv = apr_hashcluster_server_create(p,
				    		 host_str,port,
				    		 0,
				    		 1,
				    		 thread_limit,
				    		 10*1000*1000,
				    		 &st);
				     if(rv!=APR_SUCCESS)
				    	 return rv;
				     rv=apr_hashcluster_add_server(*hc, st);
				     if(rv!=APR_SUCCESS)
				    	 return rv;
			         split = apr_strtok(NULL,",", &tok);
			 }
	        return rv;
	    }

	return rv;
}

/**
 *初始化memcached
 */
apr_status_t init_memcache(apr_pool_t *p,const char* hosts,apr_memcache2_t **mc)
{
	 apr_status_t rv;
	 int thread_limit = 0;
	 int nservers = 0;
	 char *host_list;
	 char *split;
	 char *tok;
	 int usnum=0;

	 ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);

	 //计算服务器数量
	 host_list = apr_pstrdup(p, hosts);
	 split = apr_strtok(host_list, ",", &tok);
	 while (split) {
	        nservers++;
	        split = apr_strtok(NULL,",", &tok);
	 }

	 rv=apr_memcache2_create(p, nservers, 0, mc);

	 if (rv == APR_SUCCESS && nservers > 0) {//添加服务器
		 	 host_list = apr_pstrdup(p, hosts);
			 split = apr_strtok(host_list, ",", &tok);
			 while (split) {
				 	 apr_memcache2_server_t *st=NULL;
				 	 apr_memcache2_stats_t *stats=NULL;
				     char *host_str=NULL;
				     char *scope_id=NULL;
				     apr_port_t port;
				     rv = apr_parse_addr_port(&host_str, &scope_id, &port, split, p);
				     if(rv!=APR_SUCCESS)
				    	 return DECLINED-1;
				     if (host_str == NULL)
				         return DECLINED-2;
				     if (port == 0) {
				         port = kDefaultMcServerPort;
				     }

				     rv = apr_memcache2_server_create(p,
				    		 host_str,port,
				    		 kDefaultMcServerMin,
				    		 kDefaultMcServerSmax,
				    		 thread_limit,
				    		 kDefaultMcServerTtlUs,
				    		 &st);
				     if(rv!=APR_SUCCESS)
				    	 return DECLINED-3;
				     rv=apr_memcache2_add_server(*mc, st);
				     if(rv!=APR_SUCCESS)
				    	 return DECLINED-4;
				     rv=apr_memcache2_stats(st,p,&stats);
				     if(rv==APR_SUCCESS){
				    	 usnum++;
				     }
			         split = apr_strtok(NULL,",", &tok);
			 }
			 if(usnum<=0){//没有可用的服务器
				 return DECLINED-5;
			 }
	        return rv;
	    }

	return DECLINED;
}

/**
 *获取 memcached 健值
 */
apr_status_t memcache_get(apr_pool_t *p,apr_memcache2_t *mc,const char* key,char **data,apr_size_t *data_len)
{
	if(mc!=NULL && key!=NULL && p!=NULL && data!=NULL){
		apr_status_t status = apr_memcache2_getp(mc, p,key, data, data_len, NULL);
		if (status == APR_SUCCESS) {
			return OK;
		}
	}
	return DECLINED;
}

/**
 *写入 memcached 健值
 */
apr_status_t memcache_put(apr_memcache2_t *mc,const char* key,char *data,apr_size_t data_len,apr_uint32_t timeout)
{
	if(mc!=NULL && key!=NULL){
		apr_status_t status = apr_memcache2_set(mc,key,data, data_len,timeout, 0);
		if (status == APR_SUCCESS) {
		   return OK;
		}
	}
	return DECLINED;
}

#ifdef USE_MYSQL
/**
 *初始化mysql
 */
apr_status_t init_mysql(apr_pool_t *p,const char* serverinfo,MYSQL **pmysql)
{
	static const char *const delims = " \r\n\t;|,";
	const char *ptr;
	const char *key;
#if MYSQL_VERSION_ID >= 50013
	my_bool do_reconnect = 1;
#endif
	int i;
	size_t klen;
	const char *value;
	size_t vlen;
	struct {
	        const char *field;
	        const char *value;
	} fields[] = {
	  {"host", NULL},
	  {"user", NULL},
	  {"pass", NULL},
	  {"dbname", NULL},
	  {"port", NULL},
	  {"sock", NULL},
	  {"flags", NULL},
	  {"fldsz", NULL},
	  {"group", NULL},
	  {"reconnect", NULL},
	  {NULL, NULL}
	};

	unsigned int port = 0;
	unsigned long flags = 0;
	MYSQL *real_conn;
	*pmysql = apr_pcalloc(p, sizeof(MYSQL));
	*pmysql=mysql_init(*pmysql);
	if(*pmysql!=NULL){
		//获取mysql 参数
	    for (ptr = strchr(serverinfo, '='); ptr; ptr = strchr(ptr, '=')) {
	        /* don't dereference memory that may not belong to us */
	        if (ptr == serverinfo) {
	            ++ptr;
	            continue;
	        }
	        for (key = ptr-1; apr_isspace(*key); --key);
	        klen = 0;
	        while (apr_isalpha(*key)) {
	            /* don't parse backwards off the start of the string */
	            if (key == serverinfo) {
	                --key;
	                ++klen;
	                break;
	            }
	            --key;
	            ++klen;
	        }
	        ++key;
	        for (value = ptr+1; apr_isspace(*value); ++value);
	        vlen = strcspn(value, delims);
	        for (i = 0; fields[i].field != NULL; i++) {
	            if (!strncasecmp(fields[i].field, key, klen)) {
	                fields[i].value = apr_pstrndup(p, value, vlen);
	                break;
	            }
	        }
	        ptr = value+vlen;
	    }

	    if (fields[4].value != NULL) {
	        port = atoi(fields[4].value);
	    }
	    if (fields[6].value != NULL &&
	        !strcmp(fields[6].value, "CLIENT_FOUND_ROWS")) {
	        flags |= CLIENT_FOUND_ROWS; /* only option we know */
	    }
	  /*  if (fields[7].value != NULL) {
	         = atol(fields[7].value);
	    }
	    */
	    if (fields[8].value != NULL) {
	         mysql_options(*pmysql, MYSQL_READ_DEFAULT_GROUP, fields[8].value);
	    }
#if MYSQL_VERSION_ID >= 50013
	    if (fields[9].value != NULL) {
	         do_reconnect = atoi(fields[9].value) ? 1 : 0;
	    }
#endif

#if MYSQL_VERSION_ID >= 50013
	    /* the MySQL manual says this should be BEFORE mysql_real_connect */
	    mysql_options(*pmysql, MYSQL_OPT_RECONNECT, &do_reconnect);
#endif

	    real_conn = mysql_real_connect(*pmysql, fields[0].value,
	                                   fields[1].value, fields[2].value,
	                                   fields[3].value, port,
	                                   fields[5].value, flags);

	    if(real_conn == NULL) {
	        mysql_close(*pmysql);
	        return DECLINED;
	    }

#if MYSQL_VERSION_ID >= 50013
	    /* Some say this should be AFTER mysql_real_connect */
	    mysql_options(*pmysql, MYSQL_OPT_RECONNECT, &do_reconnect);
#endif
	    return OK;
	}

	return DECLINED;
}

/**
 *关闭 mysql
 */
static apr_status_t close_mysql(MYSQL *pmysql)
{
    mysql_close(pmysql);

    return APR_SUCCESS;
}

/**
 *子进程退出 清理
 */
APR_DECLARE_NONSTD(apr_status_t) child_proc_close(void *data)
{

	flash_conf_t *cf=(flash_conf_t*)data;

	if(cf->spf_mysql){
		close_mysql(cf->spf_mysql);
	}

	if(cf->spf_mysqllock!=NULL){
		apr_thread_mutex_destroy(cf->spf_mysqllock);
	}

    return APR_SUCCESS;
}

/**
 *
 *检测 mysql  连接
 *
 */
static apr_status_t mysql_check_conn(MYSQL *pmysql)
{
	apr_status_t ret = DECLINED;
	if(pmysql){
		ret= mysql_ping(pmysql);
	}
	return ret;
}


/**
 *获取查询数据
 *squiery  查询语句
 *data  返回查询内容
 */
static apr_status_t query_mysql_result(apr_pool_t *p,MYSQL *pmysql,const char* squery,char **data)
{
	MYSQL_RES *res = NULL;
	MYSQL_ROW row;
	apr_status_t rv= DECLINED;
	 int ret;
	 if(pmysql){
		 ret = mysql_query(pmysql,squery);
		 if (!ret) {
			 if(mysql_field_count(pmysql) > 0){
				 res = mysql_store_result(pmysql);
				 if(res){
					 if(mysql_num_rows(res) > 0){
						 row = mysql_fetch_row(res);
			 			 *data=apr_pstrdup(p,row[0]);
			 			 rv = APR_SUCCESS;
			 		 }
					 mysql_free_result(res);
			 	}
			 }
		 }
	 }
    return rv;
}

/**
 *获取查询appinfo数据
 *squiery  查询语句
 *appinfo  返回查询内容
 */
static apr_status_t query_mysql_appinfo(apr_pool_t *p,MYSQL *pmysql,const char* appid,flash_appinfo_t *pinfo,server_rec *s)
{
	apr_status_t rv= DECLINED;
	MYSQL_RES *res = NULL;
	MYSQL_ROW row;
	char squery[1024]={0};
//	apr_snprintf(squery,1024,"SELECT a.appkey, b.id, b.pkgname FROM appinfo a ,pkginfo b where b.appid=%s and a.id=%s",appid,appid);
	apr_snprintf(squery,1024,"SELECT appkey, pkgid, pkgname FROM appinfo where appid = '%s' ",appid);
	 int ret;
	 if(pmysql){
		ret = mysql_query(pmysql,squery);
		flash_log_printf(FLASHLOG_MARK,S_LOG , s,"query_mysql_appinfo %d  %s",ret,squery);
		if (!ret) {
			if(mysql_field_count(pmysql) > 0){
			 res = mysql_store_result(pmysql);//mysql_store_result mysql_use_result
			 if(res){
			 	if(mysql_num_rows(res) > 0){
			 		row = mysql_fetch_row(res);
			 		memset(pinfo,0,sizeof(flash_appinfo_t));
			 		if(row[0]!=NULL && row[1]!=NULL && row[2]!=NULL){
			 			strcpy(pinfo->sf_appkey,row[0]);
			 			strcpy(pinfo->sf_pkgid,row[1]);
			 			strcpy(pinfo->sf_pkgname,row[2]);
			 			rv = APR_SUCCESS;
			 		}
			 	}
			 	mysql_free_result(res);
			 }
		   }
		}
	 }
    return rv;
}

/**
 *获取查询url 缩略数据
 *squiery  查询语句
 *appinfo  返回查询内容
 */
apr_status_t query_mysql_shorturl(apr_pool_t *p,MYSQL *pmysql,const char* appid,const char *surl,char **nurl,server_rec *s)
{
	apr_status_t rv= DECLINED;
	MYSQL_RES *res = NULL;
	MYSQL_ROW row;
	char squery[1024]={0};
	apr_snprintf(squery,1024,"select url from urls where concat(domain,'/',id) = '%s' and appid = '%s'",surl,appid);
	int ret;
	if(pmysql){
		ret = mysql_query(pmysql,squery);
		flash_log_printf(FLASHLOG_MARK,S_LOG , s,"query_mysql_shorturl %d  %s",ret,squery);
		if (!ret) {
			if(mysql_field_count(pmysql) > 0){
			 res = mysql_store_result(pmysql);
			 if(res){
			 	if(mysql_num_rows(res) > 0){
			 		row = mysql_fetch_row(res);
			 		if(row[0]!=NULL){
			 			*nurl=apr_pstrdup(p,row[0]);
			 			rv = APR_SUCCESS;
			 		}
			 	}
			 	mysql_free_result(res);
			 }
		   }
		}
	 }
    return rv;
}

#else
/**
 *获取查询appinfo数据
 *web 接口
 *appinfo  返回查询内容
 */
static apr_status_t query_url_appinfo(apr_pool_t *p,const char* appid,flash_appinfo_t *pinfo,server_rec *s)
{
	return DECLINED;
}

/**
 *获取查询url 缩略数据
 *web 接口
 *appinfo  返回查询内容
 */
apr_status_t query_url_shorturl(apr_pool_t *p,const char* appid,const char *surl,char **nurl,server_rec *s)
{
	return 0;
}
#endif

/**
 *获取cpu 信息
 *
 */
static  void native_cpuid(unsigned int *eax, unsigned int *ebx,
                                unsigned int *ecx, unsigned int *edx)
{
        /* ecx is often an input as well as an output. */
        asm volatile("cpuid"
            : "=a" (*eax),
              "=b" (*ebx),
              "=c" (*ecx),
              "=d" (*edx)
            : "0" (*eax), "2" (*ecx));
}

static void get_cpuinfo(apr_pool_t *p,flash_conf_t *cf,server_rec *s)
{
	unsigned eax, ebx, ecx, edx;
	int i=1;
	char cpuinfo[35]={0};
//	for(i=0;i< 6;++i){
	  eax = i; /* processor info and feature bits */
	  native_cpuid(&eax, &ebx, &ecx, &edx);

//	  flash_log_printf(FLASHLOG_MARK,S_LOG, s,"stepping %i", eax & 0xF);
//	  flash_log_printf(FLASHLOG_MARK,S_LOG, s,"model %i", (eax >> 4) & 0xF);
//	  flash_log_printf(FLASHLOG_MARK,S_LOG, s,"family %i", (eax >> 8) & 0xF);
//	  flash_log_printf(FLASHLOG_MARK,S_LOG, s,"processor type %i", (eax >> 12) & 0x3);
//	  flash_log_printf(FLASHLOG_MARK,S_LOG, s,"extended model %i", (eax >> 16) & 0xF);
//	  flash_log_printf(FLASHLOG_MARK,S_LOG, s,"extended family %i", (eax >> 20) & 0xFF);
	  apr_snprintf(cpuinfo,35,"%08x%08x%08x%08x",eax,ebx,ecx,edx);

	  flash_log_printf(FLASHLOG_MARK,S_LOG , s,"cpuid %d : %#010x %#010x %#010x %#010x  %s",
			  i,  eax, ebx, ecx, edx , cpuinfo);
//	}
}
///////////////////////////--------一下具体功能部分----------------//////////////////////////////////////////////

/**
 *验证服务器
 */

apr_status_t init_json_domain(apr_pool_t *p,flash_conf_t *cf,server_rec *s)
{
	apr_status_t rv=DECLINED;

	if(cf->spf_ip2domain_path!=NULL){
		char *fname = ap_server_root_relative(p, cf->spf_ip2domain_path);
		if (!fname) {
			ap_log_error(APLOG_MARK, APLOG_ERR, APR_EBADPATH, s,
				             "invalid json domain path %s.", cf->spf_ip2domain_path);
			return DECLINED;
		}

		if(cf->spf_json_hash){
			apr_hash_clear(cf->spf_json_hash);
			if(get_hosts_fromjson(p,cf->spf_json_hash,fname,s)>0){
				rv=OK;
			}
		}
	}
	return rv;
}
/**
 *验证服务器
 */
apr_status_t check_server_license(apr_pool_t *p,flash_conf_t *cf,server_rec *s)
{
	char *data=NULL;
	char *xmldata=NULL;
	apr_status_t rv;
	apr_size_t len;
	apr_xml_parser *parser;
	apr_xml_doc *pdoc;
	apr_xml_elem *child;
	apr_xml_attr *childattr;

	get_cpuinfo(p,cf,s);

	parser = apr_xml_parser_create(p);
	char url[]="http://192.168.11.51:8090/license.xml";
	openurl(p, url , &data ,&len ,s);
	if(data!=NULL){
		xmldata=data;

		rv=apr_xml_parser_feed(parser, xmldata, len);

		if(rv==APR_SUCCESS){
			rv = apr_xml_parser_done(parser, &pdoc);
			if(rv==APR_SUCCESS){
				for (child = pdoc->root->first_child; child!=NULL; child = child->next) {

					childattr=child->attr;
					do {
						if(childattr!=NULL){
							flash_log_printf(FLASHLOG_MARK,S_LOG, s,"getattr:%s  value:%s",childattr->name,childattr->value);
						}else{
							break;
						}
						childattr=childattr->next;
					}while(childattr);
					if(child->first_child!=NULL)
						child=child->first_child;
				}
			}
		}else{
			char xmlerror[1024];
			apr_xml_parser_geterror(parser,xmlerror,1024);
			flash_log_printf(FLASHLOG_MARK,S_LOG, s,"parser xml error:%s",xmlerror);
		}
	}

	flash_log_printf(FLASHLOG_MARK,S_LOG, s,
			"check_server_license: %s",xmldata);
	return OK;
}

/**
 *获取 ip 和 port
 */
apr_status_t get_ipandport(const char *data,apr_size_t len,char **pbdata,flash_conf_conn_t *cfc,conn_rec *c)
{
	char *ptc=NULL;
	int icount=0;
	proxyinfo orp;
	if(data!=NULL && len>0){
		ptc=(char *)data;
		while(*ptc == ' ' && icount<len){
			ptc++;
			icount++;
		}
		// this is response head
		if(strncasecmp(ptc,"HTTP/",5) == 0 ){
			cfc->enable_request=0;
		}else{//this is request head
			while (*ptc != ' ' && *ptc != '\0' && icount <len){
				ptc++;
				icount++;
			}
			ptc++;
			icount++;
			while (*ptc != ' ' && *ptc != '\0'&& icount <len){
				ptc++;
				icount++;
			}
			ptc++;
			icount++;
			//如果有修改则获取
			//if(strncasecmp(ptc,"HTTP/",5) != 0 ){
			flash_log_printf(FLASHLOG_MARK,C_LOG, c,"read ip port pct ......%s ",ptc);
			if(icount <= (len -6)){
				*pbdata = apr_bucket_alloc(len, c->bucket_alloc);
				 memcpy(*pbdata,data,len);
				 ptc=*pbdata+icount;
				 memcpy(&(orp), ptc, sizeof(proxyinfo));
				 cfc->proxy.paddr=orp.paddr;
				 cfc->proxy.pport=ntohs(orp.pport);
				 ptc[0] = 'H';
				 ptc[1] = 'T';
				 ptc[2] = 'T';
				 ptc[3] = 'P';
				 ptc[4] = '/';
				 ptc[5] = '1';
				 return OK;
			}
		}
	}
	return DECLINED;
}

/**
 *检测垃圾流量请求
 *APR_SUCCESS 不是垃圾
 *规则根据 deviceid 或者 ip port 访问次数判断
 */
static apr_status_t check_trash_req(request_rec *r,flash_conf_req_t *cfr,int max)
{
	apr_status_t rv = APR_SUCCESS;
	char key[128]={0};
	char *data=NULL;
	char *pfind=NULL;
	apr_size_t len=0;
	int iuse=0;
	apr_time_t iset=0,inow=0;
	if(cfr->spf_memc!=NULL && cfr->user_info.proxy.pport>0 && r->connection->remote_ip!=NULL){
		//snprintf(key, 128, "%s_%u_check_trash",r->connection->remote_ip, cfr->user_info.proxy.pport);
		snprintf(key, 128, "%u_%u_check_trash",cfr->user_info.proxy.paddr.s_addr, cfr->user_info.proxy.pport);
		rv=memcache_get(r->pool,cfr->spf_memc,key,&data,&len);
		if(rv==APR_SUCCESS){
			if(data!=NULL){
				pfind=strchr(data,'/');
				if(pfind!=NULL){
					*pfind='\0';
					pfind++;
					iset = atol(data);
					inow = apr_time_now();
					iuse=atoi(pfind);
					//ap_log_rerror(APLOG_MARK, APLOG_ERR,0,r,"check_trash_req %s used count.. %d",key,iuse);
					flash_log_printf(FLASHLOG_MARK,R_LOG, r,"check_trash_req %s used count.. %d "
							"inow-iset: %"APR_TIME_T_FMT "  inow: %"APR_TIME_T_FMT,
							key,iuse,inow-iset,inow);
					if(iuse>max){
						return DECLINED;
					}else{
						if((inow-iset) < 60000000){//1 分钟  微秒
							iuse++;
						}else{//超过1分钟重新计数
							iset = apr_time_now();
							iuse=1;
						}
					}
				}
			}
		}else{
			iset = apr_time_now();
		}
		data=apr_psprintf(r->pool, "%"APR_TIME_T_FMT"/%d", iset,iuse);
		memcache_put(cfr->spf_memc,key,data,strlen(data),60);//1分钟
	}
	return OK;
}

/**
 *检测禁用的agent url
 *APR_SUCCESS 通过
 */
static apr_status_t check_forbid_agent_url(request_rec *r,flash_conf_t *cf)
{
	apr_status_t rv = APR_SUCCESS;
	flash_forbid_agent_t *pagent=NULL;
	flash_forbid_url_t *purl=NULL;
	const char *val=NULL;
	int i=0;

	pagent=(flash_forbid_agent_t*)cf->spf_forbid_agentarry->elts;
	val = apr_table_get(r->headers_in, "User-Agent");
	if(val!=NULL){
		for(i=0;i<cf->spf_forbid_agentarry->nelts;i++){
			if(pagent[i].spf_agent !=NULL){
				if (strcmp(pagent[i].spf_agent, "*") == 0) {
					rv=DECLINED;
					return rv;
				}else if(strstr(val,pagent[i].spf_agent)!=NULL){
					rv=DECLINED;
					return rv;
				}
			}
		}
	}

	purl= (flash_forbid_url_t*)cf->spf_forbid_urlarry->elts;
	if(r->unparsed_uri!=NULL){
		for(i=0;i<cf->spf_forbid_urlarry->nelts;i++){
			if(purl[i].spf_url !=NULL){
				if (strcmp(purl[i].spf_url, "*") == 0) {
					rv=DECLINED;
					return rv;
				}else if(strstr(r->unparsed_uri,purl[i].spf_url)!=NULL){
					rv=DECLINED;
					return rv;
				}
			}
		}
	}
	return rv;
}

/**
 *验证使用权限
 *用户模式
 */
static apr_status_t process_authory_user(request_rec *r,flash_conf_req_t *cfr,flash_conf_t *cf)
{
	const char *val=NULL;
	const char *ref=NULL;
	apr_status_t rv = APR_SUCCESS;
	char agentnew[128]={0};

	apr_table_t *headersin=r->headers_in;
	apr_table_t *headersout=r->headers_out;

	//agent 禁用检测
	rv=check_forbid_agent_url(r,cf);
	if(rv!=APR_SUCCESS){
		return rv;
	}

	val = apr_table_get(headersin, "Fapp-DeviceId");
	if(val!=NULL){
		cfr->user_info.spf_devid=apr_pstrdup(r->pool,val);
	}

	if(cfr->user_info.enable_used==0){
		rv = DECLINED;
		return rv;
	}

	if(cfr->user_info.enable_passthrough){
		return rv;
	}

	val = apr_table_get(headersin, "FlashVpn");
	ref = apr_table_get(headersin, "Referer");

	if(val==NULL){
		val = apr_table_get(headersin, "User-Agent");
		if(r->hostname!=NULL && strstr(r->hostname,"zennolab.com") != NULL){
			rv = DECLINED;
			return rv;
		}

		if(val!=NULL){
			translate_agent(val,agentnew);

			if(strlen(agentnew) > 0){
				cfr->user_info.spf_tagent = apr_pstrdup(r->pool,agentnew);
			}

			if(cf->enable_usedforpc == 1){
				return rv;
			}
			if (strncasecmp( val, "Mozilla", 7) == 0|| strncasecmp(val, "Opera", 5) == 0){
				if(ref != NULL){
					return rv;
				}

				if(strstr(val,"Android")!=NULL){
					return rv;
				}

				if ( (r->hostname != NULL) &&(strstr(r->hostname,"qq.com") != NULL//wihte site
						       || strstr( r->hostname,"flashapp.cn") != NULL
							   || strstr( r->hostname,"xiaonei.com") != NULL
							   || strstr( r->hostname,"sogou.com") != NULL
							   || strstr( r->hostname,"91up.com") != NULL
							   || strstr( r->hostname,"12306.cn") != NULL
							   || strstr( r->hostname,"apple.com") != NULL
							   || strstr( r->hostname,"sohu.com") != NULL
							   || strstr( r->hostname,"tianya.cn") != NULL
							   || strstr( r->hostname,"weikan.cn") != NULL
							   || strstr( r->hostname,"baidu.com") != NULL
							   || strstr( r->hostname,"kchuan.com") != NULL
							   || strstr( r->hostname,"umeng.com") !=NULL
							   || strstr( r->hostname,"snssdk.com") != NULL
							   || strstr( r->hostname,"admob.com") != NULL
							   || strstr( r->hostname,"doubleclick.net") != NULL
							   || strstr( r->hostname,"apps.virsir.com") != NULL
							   || strstr( r->hostname,"sinaapp.com") != NULL
							   || strstr( r->hostname,"google.com") != NULL
							   || strstr( r->hostname,"ggpht.com") != NULL
							   || strstr( r->hostname,"duokan.com") != NULL
							   || strstr( r->hostname,"360tpcdn.com") != NULL
							   || strstr( r->hostname,"zaitianjin.net") != NULL
							   || strstr( r->hostname,"zol.com.cn") != NULL
							 )
						   ){
								return rv;
				}

				char *tmp = strrchr(val, '(');
				if( tmp != NULL ){
					tmp++ ; //skip '(';
					if(*tmp == ')'){
						rv = DECLINED;
						return rv;
					}

					while( *(tmp) == ' ' )
						tmp++;
					if (tmp == NULL)
						return rv;

					if ( strncasecmp(tmp,"Win",3) == 0  //from Win95/98/NT/XP/me ...
						//|| strncasecmp(tmp,"Macintosh",9) == 0  // from macintosh
						|| strncasecmp(tmp,"PalmOS",6) == 0  // from macintosh
						|| strncasecmp(tmp,"X11",3) == 0   // linux PC
						|| strncasecmp(tmp,"IE",2) == 0   // linux PC
						|| strncasecmp(tmp,"webOS",5) == 0   // webos
						|| strncasecmp(tmp,"BeOS",4) == 0   // webos
						|| strncasecmp(tmp,"UNIX",4) == 0   // webos
						|| strncasecmp(tmp,"Dream",5) == 0   // webos
						|| strncasecmp(tmp,"Slurp",5) == 0   // webos
						|| strncasecmp(tmp,"PDA",3) == 0   // webos
						|| strncasecmp(tmp,"MobilePhone",11) == 0   // webos
						|| strncasecmp(tmp,"Vagabondo",9) == 0   // webos
						|| strncasecmp(tmp,"Ubuntu",6) == 0   // webos
						|| strncasecmp(tmp,"Symbian",7) == 0   // webos
						|| strncasecmp(tmp,"BlackBerry",10) == 0   // webos
						|| strncasecmp(tmp,"compatib",8) == 0   // webos
						|| strncasecmp(tmp,"MSIE",4) == 0 )  // other IE
						{
							flash_log_printf(FLASHLOG_MARK,R_LOG, r,"the agent find ( is %s",tmp);
							rv = DECLINED;
							return rv;
						}
						else if( (tmp=strchr(val,';')) != NULL )
						{
							if( strncasecmp(tmp,"; MSIE",6) == 0
								|| strncasecmp(tmp,"; Konqueror",11) == 0
								|| strncasecmp(tmp,"; Powermarks",12) == 0 ){
								flash_log_printf(FLASHLOG_MARK,R_LOG, r,"the agent find ; is %s",tmp);
								rv = DECLINED;
								return rv;
							}
						}
					}
				if( strstr(val, "Windows") != NULL
								|| strstr(val, "http://") != NULL ){

					flash_log_printf(FLASHLOG_MARK,R_LOG, r,"the agent find windows is %s",val);
					rv = DECLINED;
					return rv;
				}
			}else{
				if ( strncasecmp(val,"MSIE ",5) == 0
							|| strncasecmp(val,"Proxy",5) == 0
							|| strncasecmp(val,"MobileRunner",12) == 0
							|| strncasecmp(val,"Googlebot",9) == 0
							|| strncasecmp(val,"libwww-",7) == 0
							|| strcasecmp(val,"HttpClient") == 0
							|| strcasecmp(val,"IE") == 0
							|| strncasecmp(val,"http://",7) == 0  ){
					flash_log_printf(FLASHLOG_MARK,R_LOG, r,"the agent find msie is %s",val);
					rv = DECLINED;
					return rv;
				}
			}

		}else{

			if(cfr->user_info.enable_used==0){
				rv = DECLINED;
				return rv;
			}

			if(cf->enable_usedforpc == 1){
				return rv;
			}

			if((ref!=NULL) && (strstr( ref,"renren.com") != NULL) ){
				 return rv;
			}
			if( (r->hostname != NULL) && (strstr(r->hostname,"qq.com") != NULL   //wihte site
					      || strstr( r->hostname,"flashapp.cn") != NULL
						  || strstr( r->hostname,"renren.com") != NULL
						  || strstr( r->hostname,"xiaonei.com") != NULL
						  || strstr( r->hostname,"sogou.com") != NULL
						  || strstr( r->hostname,"91up.com") != NULL
						  || strstr( r->hostname,"12306.cn") != NULL
						  || strstr( r->hostname,"apple.com") != NULL
						  || strstr( r->hostname,"sohu.com") != NULL
						  || strstr( r->hostname,"tianya.cn") != NULL
						  || strstr( r->hostname,"qunar.com") != NULL
						  || strstr( r->hostname,"taobao.com") != NULL
						  || strstr( r->hostname,"10010.com") != NULL
						  || strstr( r->hostname,"58.com") != NULL
						  || strstr( r->hostname,"126.net") != NULL
						  || strstr( r->hostname,"ganji.com") != NULL
						  || strstr( r->hostname,"qlogo.cn") != NULL
						  || strstr( r->hostname,"gtimg.com") != NULL
						  || strstr( r->hostname,"umeng.com") != NULL
						  || strstr( r->hostname,"zol.com.cn") != NULL
						  || strstr( r->hostname,"10086.cn") != NULL
						  || strstr( r->hostname,"fetionpic.com") != NULL
						  || strstr( r->hostname,"sinaimg.cn") != NULL
						  || strstr( r->hostname,"snssdk.com") != NULL
						  || strstr( r->hostname,"pstatp.com") != NULL
						  || strstr( r->hostname,"ucweb.com") != NULL
						  || strstr( r->hostname,"66call.com") != NULL
						  || strstr( r->hostname,"163.com") != NULL
						  || strstr( r->hostname,"sina.com.cn") != NULL
						  || strstr( r->hostname,"hicloud.com") != NULL
						  || strstr( r->hostname,"ibookstar.com") != NULL
						  || strstr( r->hostname,"shupeng.com") != NULL
						  || strstr( r->hostname,"cmread.com") != NULL
						  || strstr( r->hostname,"qreader.me") != NULL
						  || strstr( r->hostname,"bao.fm") != NULL
						  || strstr( r->hostname,"daoyoudao.com") != NULL
						  || strstr( r->hostname,"sinaapp.com") != NULL
						  || strstr( r->hostname,"jiayuan.com") != NULL
						  || strstr( r->hostname,"jyimg.com") != NULL
						  || strstr( r->hostname,"m1905.com") != NULL
						  || strstr( r->hostname,"wandoujia.com") != NULL
						  || strstr( r->hostname,"flurry.com") != NULL
						  || strstr( r->hostname,"muzhiwan.com") != NULL
						  || strstr( r->hostname,"hupu.com") != NULL
						  || strstr( r->hostname,"3g.cn") != NULL
						  || strstr( r->hostname,"apkads.com") != NULL
						  || strstr( r->hostname,"cntv.cn") != NULL
						  || strstr( r->hostname,"zcom.com") != NULL
						  || strstr( r->hostname,"ifeng.com") != NULL
						  || strstr( r->hostname,"wumii.com") != NULL
						  || strstr( r->hostname,"yiche.com") != NULL
						  || strstr( r->hostname,"xgres.com") != NULL
						  || strstr( r->hostname,"easou.com") != NULL
						  || strstr( r->hostname,"bitauto.com") != NULL
						  || strstr( r->hostname,"1000chi.com") != NULL
						  || strstr( r->hostname,"tenddata.com") != NULL
						  || strstr( r->hostname,"youguu.com") != NULL
						  || strstr( r->hostname,"mayiweigu.com") != NULL
						  || strstr( r->hostname,"west95582.com") != NULL
						  || strstr( r->hostname,"tebon.com.cn") != NULL
						  || strstr( r->hostname,"niugubao.com") != NULL
						  || strstr( r->hostname,"wengupiao.com") != NULL
						)
					  ){
						return rv; //just go
			}

			if( (r->hostname != NULL) &&
				( strstr(r->hostname,"semrush") != NULL   //innormal host
						  || strstr(r->hostname,"yahoo.com") != NULL
				 	 	  || strstr(r->hostname,"toolbarqueries") != NULL
						  || strstr(r->hostname,"bing.com") != NULL
						  || strstr(r->hostname,"proxy") != NULL
						  || strstr(r->hostname,"bhphotovideo.com") != NULL
						  || strstr(r->hostname,"ctdisk.com") != NULL
						  || strstr(r->hostname,"google.com.") != NULL
						  || strstr(r->hostname,"http") != NULL
						  || strstr(r->hostname,"google.co.") != NULL
						  || strstr(r->hostname,".ru") != NULL
						)
					  ){
						flash_log_printf(FLASHLOG_MARK,R_LOG, r,"the hostname find  is %s",r->hostname);
						rv = DECLINED;
						return rv;
			}

			if( (r->hostname != NULL) &&(r->uri != NULL) &&
					    ( strstr( r->uri , "check.php") != NULL
						  || strstr( r->uri , "proxy") != NULL
						  || strstr( r->uri , "login?login") != NULL
						  || strstr( r->uri , "pwtoken_get?") != NULL
						  || strstr( r->uri , "register.php") != NULL
						  || strstr( r->uri , "http") != NULL
						  || strstr( r->uri , "srch?query") != NULL
						  || strstr( r->uri , "pp/set-cookie.php") != NULL
						  || strstr( r->uri , "isp_verify_user") != NULL
						  || strstr( r->uri , "rss/booth") != NULL
						  || strstr( r->uri , "action=info_user&login") != NULL
						  || strstr( r->uri , "trackback") != NULL
						)
					  ){
						flash_log_printf(FLASHLOG_MARK,R_LOG, r,"the uri find  is %s",r->uri);
						rv = DECLINED;
						return rv;
			}
		}
	}
	return rv;
}

/**
 *获得 app 的信息
 *先从 memcache  没有在从mysql 里获得
 */
static apr_status_t get_appinfo(apr_pool_t *p,flash_conf_req_t *cfr,flash_appinfo_t *info,server_rec *s)
{
	apr_status_t rv=DECLINED;
	apr_size_t len=0;
	char *data=NULL;
	char key[128]={0};
	if(cfr->user_info.spf_appid){
		snprintf(key, 128, "%s_appinfo",cfr->user_info.spf_appid);
		rv=memcache_get(p,cfr->spf_memc,key,&data,&len);
		flash_log_printf(FLASHLOG_MARK,S_LOG, s,"get appinfo from mem key:%s ",key);
		if(rv==APR_SUCCESS){
			memcpy(info,data,sizeof(flash_appinfo_t));
			flash_log_printf(FLASHLOG_MARK,S_LOG , s,"appinfo find in mem "
				"appkey is:%s  pkgname is:%s pkgid: %s",info->sf_appkey,info->sf_pkgname,info->sf_pkgid);
		}else{
#ifdef  USE_MYSQL
			if(cfr->spf_mysqllock){
				apr_thread_mutex_lock(cfr->spf_mysqllock);
			}
			if((cfr->spf_mysql!=NULL) && ((mysql_ping(cfr->spf_mysql) == APR_SUCCESS))){
				flash_log_printf(FLASHLOG_MARK,S_LOG, s,"get appinfo from mysql key:%s ",cfr->user_info.spf_appid);
				rv=query_mysql_appinfo(p,cfr->spf_mysql,cfr->user_info.spf_appid,info,s);
			}
			if(cfr->spf_mysqllock){
				apr_thread_mutex_unlock(cfr->spf_mysqllock);
			}
#else
			rv=query_url_appinfo(p,cfr->user_info.spf_appid,info,s);
#endif
			if(rv==APR_SUCCESS){
				if(strlen(info->sf_appkey) >0 ){
					memcache_put(cfr->spf_memc,key,(char *)info,sizeof(flash_appinfo_t),43200);//12小时
					flash_log_printf(FLASHLOG_MARK,S_LOG, s,"find appinfo form mysql "
							"key is:%s pkgname is:%s pkgid: %s",info->sf_appkey,info->sf_pkgname,info->sf_pkgid);
				}
			}
		}
	}
	return rv;
}


/**
 *旧协议 agent 上使用
 *解析sdk agent 的内容
 *sdk模式
 */
static apr_int64_t parse_sdk_agent(request_rec *r,flash_conf_req_t *cfr)
{
	const char *val=NULL;
	char newagent[512]={0};
	char *plt=NULL;
	char *data=NULL;
	apr_size_t len=0;
	apr_int64_t icmd=0;
	apr_table_t *headersin=r->headers_in;

    val = apr_table_get(headersin, "cmd");
    if(val){
    	cfr->user_info.sdk_stepmode = icmd =apr_atoi64(val);
    	cfr->user_info.auth_mode = MODE_OLD;
    }

	val=apr_table_get(headersin, "User-Agent");
	if(val!=NULL && cfr->user_info.spf_appid==NULL){
		apr_cpystrn(newagent,val,512);
	    data=newagent;
	    cfr->user_info.spf_tagent=apr_pstrdup(r->pool,newagent);
	    plt=strchr(data,':');
	    if(plt){
	    	len=plt-data;
	    	cfr->user_info.spf_devid=apr_pstrdup(r->pool,plt+1);
	    	data[len]='\0';
	    	cfr->user_info.spf_appid=apr_pstrdup(r->pool,data);
	    }

		val=apr_table_get(headersin, "code");
		if(val!=NULL){
			cfr->user_info.spf_codetoken=apr_pstrdup(r->pool,val);
		}

		val=apr_table_get(r->headers_in, "sdkopts");
		if(val!=NULL){
			data=apr_pstrdup(r->pool,val);
			len=strlen(data);
			if(len >= 1){
				cfr->user_info.spf_nettype=apr_pstrndup(r->pool,data,1);
				len -=1;
				data++;
			}

			if(len >= 1){
				cfr->user_info.spf_platformtype=apr_pstrndup(r->pool,data,1);
				len -=1;
				data++;
			}

			if(len >=2){
				cfr->user_info.spf_imgype=apr_pstrndup(r->pool,data,2);
				data+=2;
			}
		}

		val=apr_table_get(r->headers_in,"s");
		if(val!=NULL){
			cfr->user_info.spf_urlshortparam = apr_pstrdup(r->pool,val);
			cfr->user_info.spf_urlshort = r->unparsed_uri;
		}
	}
	return icmd;
}

/**
 * 清理无效发送的http头
 */
apr_status_t clear_trash_header(request_rec *r,flash_conf_req_t *cfr)
{
	apr_status_t rv = APR_SUCCESS;
	if(cfr->user_info.server_mode==MODE_SDK){
		apr_table_unset(r->headers_in,"X-Fastsdk-Type");
		apr_table_unset(r->headers_in,"X-Fastsdk-Cmd");
		apr_table_unset(r->headers_in,"sdkopts");
		apr_table_unset(r->headers_in,"cmd");
		apr_table_unset(r->headers_in,"code");
		apr_table_unset(r->headers_in,"s");
	}
	return rv;
}

/**
 * 检测兰讯请求
 * http://cc.fastsdk.com/_ic00/_ap6038_10096e79218965eb72c92a549dd5a330112_002/www.baidu.com
 * _ic00: 图片压缩质量(image compress)，固定以_ic开头，00是数值
 *_ap6038_196e79218965eb72c92a549dd5a330112_002: app参数(app parameter),固定以_ap开头
 * 6038:  是appid
 * 196e79218965eb72c92a549dd5a330112:   分成两部分 110 和 96e79218965eb72c92a549dd5a330112，
 * 1代表网络类型（1-Wifi 2-2G），1,平台类型（1代表android 2代表ios） 0 是否缩略 后面的32位是验证码
 * 002： 压缩后的deveiceId
 */
static apr_int64_t check_sdk_lanxun_url(request_rec *r,flash_conf_req_t *cfr)
{
	const char *val=NULL;
	char *plt=NULL;
	char *data=NULL;
	char *tok=NULL;
	int len=0;
	apr_int64_t icmd=0;
	apr_table_t *headersin=r->headers_in;
	data=apr_pstrdup(r->pool,r->unparsed_uri);
	len=strlen(data);
	if((r->hostname) && (strstr(r->hostname,"fastsdk.com"))){
		plt=strstr(data,"_ic");
	}
	if(plt!=NULL && len>54){//54预估的最小长度,包括最短url
		len=strlen(plt);
		if((len>54) && (*(plt+5) == '/')){
			*(plt+5) = '\0';
			plt+=3;
			cfr->user_info.spf_imgype = plt;
			plt+=3;
			if(strncasecmp(plt,"_ap",3)==0){
				plt+=3;
				tok=strchr(plt,'_');
				if(tok!=NULL){
					*tok = '\0';
					cfr->user_info.spf_appid = plt;
					plt=tok+1;
					if(*(plt+35) == '_'){
						//cfr->user_info.spf_nettype = plt;
						plt++;// platform type
						plt++;
						if((*plt)=='1'){
							val=apr_table_get(r->headers_in,"s");
							if(val!=NULL){
								cfr->user_info.spf_urlshortparam = apr_pstrdup(r->pool,val);
								cfr->user_info.spf_urlshort = r->unparsed_uri;
							}
						}
						plt++;
						*(plt+32) = '\0';
						cfr->user_info.spf_codetoken = plt;
						plt+=33;
						tok=strchr(plt,'/');
						if(tok!=NULL){
							*tok = '\0';
							cfr->user_info.spf_devid = plt;
							plt = tok+1;
							///修改url
							r->unparsed_uri = apr_pstrcat(r->pool,ap_http_scheme(r),"://" , plt, NULL);
							apr_uri_parse(r->pool, r->unparsed_uri, &r->parsed_uri);
							r->hostname = r->parsed_uri.hostname;
							if(r->hostname){
								apr_table_set(r->headers_in,"Host",r->hostname);
							}
					        r->args = r->parsed_uri.query;
					        r->uri = r->parsed_uri.path ? r->parsed_uri.path
					                 : apr_pstrdup(r->pool, "/");

							if(!r->proxyreq){
								r->proxyreq = PROXYREQ_PROXY;
								r->handler = "proxy-server";
							}
							r->uri=apr_pstrdup(r->pool,r->unparsed_uri);
							r->filename=apr_pstrcat(r->pool, "proxy:",r->uri , NULL);
							r->the_request=apr_pstrcat(r->pool, r->method," ",r->unparsed_uri, NULL);

							cfr->user_info.sdk_stepmode = icmd =1;
						}
					}
				}
			}
		}
	}

	flash_log_printf(FLASHLOG_MARK,R_LOG, r,"check_sdk_lanxun_url %s  to:%s icmd:%ld ,deviceid: %s ",
			cfr->user_info.spf_appid,cfr->user_info.spf_codetoken,icmd,cfr->user_info.spf_devid);
	return icmd;
}

/**
 * 新协议
 * 获取sdk 的http head
 * X-Fastsdk-Cmd: timestamp,cmd,appid,deviceid,deviceName,deviceType,
 * osVersion,netType,mcc_mnc,imageRadio,token,channel
 * X-Fastsdk-Cmd: cmd,appid,deviceid,deviceType,nettype,imageRadio,[code|token]
 */
static apr_int64_t check_sdk_header(request_rec *r,flash_conf_req_t *cfr)
{
	const char *val=NULL;
	char *plt=NULL;
	char *data=NULL;
	char *tok=NULL;
	apr_int64_t icmd=0;
	apr_table_t *headersin=r->headers_in;

	val=apr_table_get(headersin, "X-Fastsdk-Type");
	if(val!=NULL){
		if(strcmp(val,"1")==0){
			cfr->user_info.auth_mode = MODE_LANXUN;
		}else if(strcmp(val,"2")==0){
			cfr->user_info.auth_mode = MODE_NOSQL;
		}else{
			val=apr_table_get(r->headers_in,"s");
			if(val!=NULL){
				cfr->user_info.spf_urlshortparam = apr_pstrdup(r->pool,val);
				cfr->user_info.spf_urlshort = r->unparsed_uri;
			}
		}
	}

	if(cfr->user_info.spf_appid==NULL){
		if (cfr->user_info.auth_mode == MODE_NORMAL) {
			val = apr_table_get(headersin, "X-Fastsdk-Cmd");
			if (val != NULL ) {
				data = apr_pstrdup(r->pool, val);
				plt = apr_strtok(data, ",", &tok);
				//cmd
				if (plt) {
					cfr->user_info.sdk_stepmode = icmd = apr_atoi64(plt);
					plt = apr_strtok(NULL, ",", &tok);
				}
				//appid
				if (plt) {
					cfr->user_info.spf_appid = plt;
					plt = apr_strtok(NULL, ",", &tok);
				}
				//deviceid
				if (plt) {
					cfr->user_info.spf_devid = plt;
					plt = apr_strtok(NULL, ",", &tok);
				}
				//deviceType
				if (plt) {
					cfr->user_info.spf_platformtype = plt;
					plt = apr_strtok(NULL, ",", &tok);
				}
				//nettype
				if (plt) {
					cfr->user_info.spf_nettype = plt;
					plt = apr_strtok(NULL, ",", &tok);
				}
				//imageRadio
				if (plt) {
					cfr->user_info.spf_imgype = plt;
					plt = apr_strtok(NULL, ",", &tok);
				}
				//code
				if (plt) {
					cfr->user_info.spf_codetoken = plt;
					plt = apr_strtok(NULL, ",", &tok);
				}
			}
		}else if(cfr->user_info.auth_mode==MODE_NOSQL){
			val = apr_table_get(headersin, "X-Fastsdk-Cmd");
			if (val != NULL ) {
				data = apr_pstrdup(r->pool, val);
				plt = apr_strtok(data, ",", &tok);
				//timestamp
				if (plt) {
					cfr->user_info.spf_timestamp = plt;
					plt = apr_strtok(NULL, ",", &tok);
				}
				//cmd
				if (plt) {
					cfr->user_info.sdk_stepmode = icmd = apr_atoi64(plt);
					plt = apr_strtok(NULL, ",", &tok);
				}
				//appid
				if (plt) {
					cfr->user_info.spf_appid = plt;
					plt = apr_strtok(NULL, ",", &tok);
				}
				//deviceid
				if (plt) {
					cfr->user_info.spf_devid = plt;
					plt = apr_strtok(NULL, ",", &tok);
				}
				//devicename
				if (plt) {
					cfr->user_info.spf_devname = plt;
					plt = apr_strtok(NULL, ",", &tok);
				}
				//deviceType
				if (plt) {
					cfr->user_info.spf_platformtype = plt;
					plt = apr_strtok(NULL, ",", &tok);
				}
				//osVersion
				if (plt) {
					cfr->user_info.spf_osversion = plt;
					plt = apr_strtok(NULL, ",", &tok);
				}
				//nettype
				if (plt) {
					cfr->user_info.spf_nettype = plt;
					plt = apr_strtok(NULL, ",", &tok);
				}
				//mcc_mnc
				if (plt) {
					cfr->user_info.spf_mccnc = plt;
					plt = apr_strtok(NULL, ",", &tok);
				}
				//imageRadio
				if (plt) {
					cfr->user_info.spf_imgype = plt;
					plt = apr_strtok(NULL, ",", &tok);
				}
				//code token
				if (plt) {
					cfr->user_info.spf_codetoken = plt;
					plt = apr_strtok(NULL, ",", &tok);
				}
				//channel
				if (plt) {
					cfr->user_info.spf_channel = plt;
					plt = apr_strtok(NULL, ",", &tok);
				}
			}
		}else if(cfr->user_info.auth_mode==MODE_LANXUN){
			cfr->user_info.sdk_stepmode = icmd = check_sdk_lanxun_url(r,cfr);
		}
	}else{
		icmd=cfr->user_info.sdk_stepmode;
	}
	return icmd;
}

/**
 * 生城客户端验证
 * 服务器时间的前后十五分钟
 * timestamp    客户端时间
 */
static apr_status_t check_client_time(char* timestamp)
{
	apr_status_t rv = DECLINED;
	char tbuf[21]={0};
	apr_time_t tstart=0,tend=0,tclient=0;
	apr_time_t now;
	now=apr_time_now();
	tstart = now-900;
	tend = now+900;
	if(timestamp){
		tclient = apr_atoi64(timestamp);
		if((tclient>tstart) && (tclient < tend)){
			rv = APR_SUCCESS;
		}
	}
	return rv;
}

/**
 *解析获取token 的内容
 *sdk模式
 */
static apr_status_t get_sdk_token(request_rec *r,flash_conf_req_t *cfr)
{
	apr_status_t rv=DECLINED;
	const char *val=NULL;
	char *data=NULL;
	apr_size_t len=0;
	int iuse=0;
	char key[128]={0};
	if(cfr->user_info.spf_codetoken==NULL){
		apr_table_t *headersin=r->headers_in;
		val = apr_table_get(headersin, "token");
	}else{
		val = cfr->user_info.spf_codetoken;
	}

	if(val!=NULL){
		snprintf(key, 128, "%s_token",val);
		rv=memcache_get(r->pool,cfr->spf_memc,key,&data,&len);
		if(rv==APR_SUCCESS){
			flash_log_printf(FLASHLOG_MARK,R_LOG, r,"get token form mem appid:%s key:%s agent:%s"
					,cfr->user_info.spf_appid,val,cfr->user_info.spf_tagent);
			if(data!=NULL){
				iuse = atoi(data);
				flash_log_printf(FLASHLOG_MARK,R_LOG, r,"token used type %d ",iuse);
				//token 规则  第一次分配， 然后每次验证 发现无效 写mem 累加 100
				if(1==iuse){//1 为正常  其他 为无效的 使用100 次 无效 token 后在用  禁用客户端
					cfr->user_info.check_result= 1;
				}else{
					iuse++;
					data=apr_itoa(r->pool,iuse);
					if(iuse >= 100){//无效访问100次 禁用
						rv=DECLINED;
					}else{
						memcache_put(cfr->spf_memc,key,data,strlen(data),60);//10分钟
					}
				}
			}
		}else{//mem  中没有值  把这个tocket 放入无效
			data=apr_pstrdup(r->pool,"2");
			memcache_put(cfr->spf_memc,key,data,strlen(data),60);
			rv=APR_SUCCESS;
		}
	}
	return rv;
}

/**
 *验证使用权限
 *sdk模式
 *auth=0: 未知验证结果；
 *auth=1：验证通过；
 *auth=2: 验证不通过；可能是由于服务器端缓存过期
 *auth=3：代理服务器不可用；
 *auth=4：换代理
 */
static apr_status_t process_authory_sdk(request_rec *r,flash_conf_req_t *cfr,flash_conf_t *cf)
{
	apr_status_t rv=APR_SUCCESS;
	const char *val=NULL;
	apr_int64_t icmd=0;
	flash_appinfo_t appinfo;
	apr_table_t *headersin=r->headers_in;

    char *data=NULL;
    apr_size_t len=0;
    char res[33]={0};
//https 加密直接跳过
    if(r->method_number == M_CONNECT){
    	if(r->parsed_uri.port== 443){
    		cfr->user_info.enable_settoken= 1;
    		cfr->user_info.check_result = 1;
    		return rv;
    	}
    }
    //新协议
    icmd=check_sdk_header(r,cfr);
    if(icmd==0){
    	//旧协议
    	icmd=parse_sdk_agent(r,cfr);
    }
    //第一次 验证用户
    if(icmd==1){
		cfr->user_info.check_result = 3;
		cfr->user_info.enable_settoken = 0;
		if (cfr->user_info.auth_mode == MODE_NORMAL || cfr->user_info.auth_mode == MODE_LANXUN ||
				cfr->user_info.auth_mode == MODE_OLD ) {
			flash_log_printf(FLASHLOG_MARK, R_LOG, r,
					"start  appinfo code: %s ", cfr->user_info.spf_codetoken);
			if (cfr->user_info.spf_codetoken != NULL ) {
				rv = get_appinfo(r->pool, cfr, &appinfo, r->server);
				if (rv == APR_SUCCESS) {
					cfr->user_info.spf_pkgid = apr_pstrdup(r->pool,
							appinfo.sf_pkgid);
					data = apr_pstrcat(r->pool, cfr->user_info.spf_appid,
							appinfo.sf_pkgname, appinfo.sf_appkey, NULL );
					len = strlen(data);
					make_auth_key(data, len, &(res[0]));

					flash_log_printf(FLASHLOG_MARK, R_LOG, r,
							"make code for clc %s len:%"APR_SIZE_T_FMT
							" mk:%s ", data, len, res);
					if (strcmp(res, cfr->user_info.spf_codetoken) == 0) {
						if(cfr->user_info.auth_mode == MODE_NORMAL || cfr->user_info.auth_mode == MODE_OLD){
							cfr->user_info.enable_settoken = 1;
						}
						cfr->user_info.check_result = 1;
						rv = APR_SUCCESS;
					}else{
						//普通模式没验证通过也返回正确内容
						if(cfr->user_info.auth_mode == MODE_NORMAL || cfr->user_info.auth_mode == MODE_OLD){
							rv = APR_SUCCESS;;
						}
					}
					//格式符合，仍然通过所以没放到上面括号里

				} else { //app 信息无效
					flash_log_printf(FLASHLOG_MARK, R_LOG, r,
							"appinfo is invalidation");
					rv = DECLINED;
				}
			} else { //验证头不完整
				flash_log_printf(FLASHLOG_MARK, R_LOG, r,
						"header is invalidation");
				rv = DECLINED;
			}
		}else if (cfr->user_info.auth_mode == MODE_NOSQL) {
			if(APR_SUCCESS==check_client_time(cfr->user_info.spf_timestamp)){
				data = apr_pstrcat(r->pool, cfr->user_info.spf_timestamp,
						cfr->user_info.spf_appid, NULL);
				len = strlen(data);
				make_auth_key(data, len, &(res[0]));

				flash_log_printf(FLASHLOG_MARK, R_LOG, r,
						"make code for clc %s len:%"APR_SIZE_T_FMT
						"mk:%s ", data, len, res);
				if (strcmp(res, cfr->user_info.spf_codetoken) == 0) {
					cfr->user_info.check_result = 1;
					rv = APR_SUCCESS;
				}else{
					flash_log_printf(FLASHLOG_MARK, R_LOG, r,
											"check code is invalidation");
					rv = DECLINED;
				}
			}else{
				flash_log_printf(FLASHLOG_MARK, R_LOG, r,
										"check time is invalidation");
				rv = DECLINED;
			}
		}
    }else if (icmd==2){// 验证token
    	cfr->user_info.check_result= 2;
    	rv=get_appinfo(r->pool,cfr,&appinfo,r->server);//取得包信息
    	if(rv==APR_SUCCESS){
    		cfr->user_info.spf_pkgid=apr_pstrdup(r->pool,appinfo.sf_pkgid);
    		rv=get_sdk_token(r,cfr);//  check_result =1
    	}else{//非法appid
    		rv=DECLINED;
    	}
    }else{//命令不合法
    	cfr->user_info.check_result= 3;
    	rv=DECLINED;
    }
    return rv;
}

/**
 *验证使用权限
 *
 */
apr_status_t process_authory(request_rec *r,flash_conf_req_t *cfr,flash_conf_t *cf)
{
	apr_status_t rv;

	if(cfr->user_info.server_mode==MODE_SDK){
		rv=process_authory_sdk(r,cfr,cf);
	}else{
		rv=process_authory_user(r,cfr,cf);
		//根据用户 源ip 和端口 在1分钟内的访问次数来判断过量访问，或者垃圾攻击
		if(rv==APR_SUCCESS){
			if(cf->enable_trashcheck){
				rv=check_trash_req(r,cfr,cf->max_visitperuser);
			}
		}
	}
/*
    val = apr_table_get(headersin, "Content-Length");

    if(val!=NULL)
    flash_log_printf(FLASHLOG_MARK,R_LOG, r,"process_authory in %s ",val);

    val = apr_table_get(headersin, "X-Original-Content-Length");

    if(val!=NULL)
    flash_log_printf(FLASHLOG_MARK,R_LOG, r,"process_authory in %s ",val);
*/
	return rv;

	//DECLINED 继续
}


/**
 *当前时间是否在区段
 *按照分钟计算
 */
static apr_status_t check_time_enable(request_rec *r,char *pdata)
{
	apr_status_t rv = APR_SUCCESS;
	apr_uint16_t min_start,min_end,min_now;
	apr_time_exp_t xt;
	apr_time_t now_sec;
	char ctime[5]={0};
	int data_len,i;
	if(pdata){
		now_sec=apr_time_now();
		//ap_explode_recent_localtime(&xt,now_sec);
		ap_explode_recent_gmt(&xt,now_sec);
		min_now=xt.tm_hour*60+xt.tm_min;
		data_len=strlen(pdata);
		for(i=0;i<data_len/8;i++){
			strncpy(ctime,pdata+i*8,4);
			min_start = atoi(ctime);
			strncpy(ctime,pdata+i*8+4,4);
			min_end = atoi(ctime) +min_start;
			flash_log_printf(FLASHLOG_MARK,R_LOG, r,"check_time_enable now:%d start:%d end:%d "
					,min_now,min_start,min_end);

			if(min_now>=min_start && min_now<=min_end){
				rv=DECLINED;
				break;
			}
		}
	}
	return rv;
}

/**
 *获取用户是否禁用
 *
 */
static apr_status_t check_user_enable(request_rec *r,flash_conf_req_t *cfr,char *phost)
{
	apr_status_t rv = APR_SUCCESS;
	char key[128]={0};
	char *data=NULL;
	apr_size_t len=0;

	if(cfr->user_info.server_mode==MODE_USER){
	//创建key
		if(cfr->user_info.spf_devid!=NULL){
			snprintf(key, 128, "%s_flashapp_enable",cfr->user_info.spf_devid);
		}else{
			if(phost){
				snprintf(key, 128, "%s_%u_flashapp_enable",
							phost, cfr->user_info.proxy.pport);
			}else{
				//严谨的时候开把这个打开
				//rv=DECLINED;
				return rv;
			}
		}

		flash_log_printf(FLASHLOG_MARK,R_LOG, r,"the enable key is %s ",key);
		//查询
		rv=memcache_get(r->pool,cfr->spf_memc,key,&data,&len);
		if(rv==APR_SUCCESS){
			flash_log_printf(FLASHLOG_MARK,R_LOG, r,"the enable value is %s ",data);
			if(len==1){//旧规则
				if((*data)=='1'){
					rv = DECLINED;
				}
			}else{//新规则
				rv = check_time_enable(r,data);
			}
		}else{
			rv = APR_SUCCESS;
		}
	}
	return rv;
}

/**
 *获取app是否禁用
 *
 */
static apr_status_t check_app_enable(request_rec *r,flash_conf_req_t *cfr,char *phost)
{
	apr_status_t rv = APR_SUCCESS;
	const char *val=NULL;
	char key[128]={0};
	char xres[33]={0};
	char *data=NULL;
	apr_size_t len=0;
	if(cfr->user_info.server_mode==MODE_USER){
		make_agent_key(cfr->user_info.spf_tagent,NULL,xres,r->server);
		if(cfr->user_info.spf_devid!=NULL){
			snprintf(key, 128, "%s_%s",cfr->user_info.spf_devid,xres);
		}else{
			if(phost){
				snprintf(key, 128, "%s_%u_%s",phost, cfr->user_info.proxy.pport,xres);
			}else{
				//严谨的时候开把这个打开
				//rv=DECLINED;
				return rv;
			}
		}

		flash_log_printf(FLASHLOG_MARK,R_LOG, r,"the agent is%s key is %s  ",cfr->user_info.spf_tagent,key);

		rv=memcache_get(r->pool,cfr->spf_memc,key,&data,&len);
		if(rv == APR_SUCCESS){
			flash_log_printf(FLASHLOG_MARK,R_LOG, r,"the agent value is %s ",data);
			if(1==len){
				if((*data)=='1'){
					rv=DECLINED;
				}
			}else{//新协议
				rv = check_time_enable(r,data);
			}
		}else{
			rv =APR_SUCCESS;
		}

		if(rv == APR_SUCCESS){//判断 agent 和 host
			if(r->hostname!=NULL){
				memset(key,0,128);
				memset(xres,0,33);
				make_agent_key(cfr->user_info.spf_tagent,r->hostname,xres,r->server);
				if(cfr->user_info.spf_devid!=NULL){
					snprintf(key, 128, "%s_%s",cfr->user_info.spf_devid,xres);
				}else{
					if(phost){
						snprintf(key, 128, "%s_%u_%s",phost, cfr->user_info.proxy.pport,xres);
					}else{
						//严谨的时候开把这个打开
						//rv=DECLINED;
						return rv;
					}
				}

				flash_log_printf(FLASHLOG_MARK,R_LOG, r,"the agent and host key is %s ",key);

				rv=memcache_get(r->pool,cfr->spf_memc,key,&data,&len);
				if(rv == APR_SUCCESS){
					flash_log_printf(FLASHLOG_MARK,R_LOG, r,"the agent and host value is %s ",data);
					if(1==len){
						if((*data)=='1'){
							rv=DECLINED;
						}
					}else{//新处理
						rv = check_time_enable(r,data);
					}
				}else{
					rv =APR_SUCCESS;
				}
			}
		}
	}
	return rv;
}

/**
 *获取用户图片等级
 *
 */
static apr_status_t check_image_level(request_rec *r,flash_conf_req_t *cfr,char *phost)
{
	apr_status_t rv = APR_SUCCESS;
	char key[128]={0};
	char *data=NULL;
	apr_size_t len=0;
	int iq=1;

	flash_log_printf(FLASHLOG_MARK,R_LOG, r,"process_usersetting");

	if(cfr->user_info.server_mode==MODE_SDK){
//*************************************************
//sdkopts=option1+option2+…
//*		目前sdkopts包括2项：网络类型和图片压缩设置
//*		网络设置占用1个字节，1：WIFI；2：2G/3G
//*		平台类型占用1个字节，1：android；2：ios
//*		图片压缩设置占用2个字节：
//*		00：不压缩；
//*		15:低压缩率（压缩比15%）;
//*		25:中压缩率(压缩比25%)；
//*		60：高压缩率（压缩比60%）
//**************************************************
		if(cfr->user_info.spf_imgype!=NULL){
			if(strcmp(cfr->user_info.spf_imgype,"15")==0){
				cfr->user_info.image_quality = IQ_LOW;
			}else if(strcmp(cfr->user_info.spf_imgype,"60")==0){
				cfr->user_info.image_quality = IQ_HIGH;
			}else if(strcmp(cfr->user_info.spf_imgype,"00")==0){
				cfr->user_info.image_quality = IQ_NO;
			}else if(strcmp(cfr->user_info.spf_imgype,"85")==0){
				cfr->user_info.image_quality = IQ_HIGH_1;
			}else if(strcmp(cfr->user_info.spf_imgype,"90")==0){
				cfr->user_info.image_quality = IQ_HIGH_2;
			}else if(strcmp(cfr->user_info.spf_imgype,"95")==0){
				cfr->user_info.image_quality = IQ_HIGH_3;
			}
		}
	}else if(cfr->user_info.server_mode==MODE_USER){
		//创建key
		if(cfr->user_info.spf_devid!=NULL){
			snprintf(key, 128, "%s_flashapp_qimage",cfr->user_info.spf_devid);
		}else{
			if(phost){
				snprintf(key, 128, "%s_%u_flashapp_qimage",phost, cfr->user_info.proxy.pport);
			}else{
				return DECLINED;
			}
		}

		flash_log_printf(FLASHLOG_MARK,R_LOG, r,"the img key is %s ",key);

		rv=memcache_get(r->pool,cfr->spf_memc,key,&data,&len);
		if(rv == APR_SUCCESS){
			if(data!=NULL){
				flash_log_printf(FLASHLOG_MARK,R_LOG, r,"the img value is %s ",data);
				iq=atoi(data);
				if(0==iq){
					cfr->user_info.image_quality = IQ_LOW;
				}else if(2==iq){
					cfr->user_info.image_quality = IQ_HIGH;
				}else if(3==iq){
					cfr->user_info.image_quality = IQ_NO;
				}else if(4==iq){
					cfr->user_info.image_quality = IQ_HIGH_1;
				}else if(5==iq){
					cfr->user_info.image_quality = IQ_HIGH_2;
				}else if(6==iq){
					cfr->user_info.image_quality = IQ_HIGH_3;
				}else{
					cfr->user_info.image_quality = IQ_MID;
				}
			}
		}else{
			rv=DECLINED;
		}
	}
	return rv;
}

/**
 *获取用户设置
 *设置属性
 */
apr_status_t process_usersetting(request_rec *r,flash_conf_req_t *cfr)
{
	apr_status_t rv = APR_SUCCESS;
	char *pdip =NULL;
	char *phost =NULL;

	flash_log_printf(FLASHLOG_MARK,R_LOG, r,"process_usersetting");

	if(cfr->user_info.enable_passthrough){
		return rv;
	}

	if(cfr->user_info.server_mode==MODE_USER){
		pdip=inet_ntoa(cfr->user_info.proxy.paddr);
		if(pdip!=NULL){
			phost = get_host_fromip(r,cfr->spf_json_hash,pdip);
		}
	}

	rv=check_user_enable(r,cfr,phost);

	if(rv == APR_SUCCESS){
		rv = check_app_enable(r,cfr,phost);
		if(rv==APR_SUCCESS){
			check_image_level(r,cfr,phost);
		}
	}
	return rv;
}


/**
 *处理squid 的分发资源和属性
 *属性放到头中
 */
apr_status_t process_distribution_squid(request_rec *r,flash_conf_req_t *cfr,flash_conf_t *cf)
{
	apr_status_t rv=DECLINED;
	flash_squid_host_t *phost=NULL;
	flash_squid_type_t *ptype=NULL;
	char key[12]={0};
	char *ptn=NULL;
	char *pproxy=NULL;
	const char *content_type=NULL;
	int i=0;

	if(r->content_type!=NULL){
		content_type=apr_pstrdup(r->pool,r->content_type);
		flash_log_printf(FLASHLOG_MARK,R_LOG, r,"process_distribution_squid type %s ",r->content_type);
	}else{
		content_type=apr_table_get(r->headers_in, "Accept");
	}

	if((cf->spf_squid_proxy!=NULL) ){ //&& (r->method_number == M_GET)
		if(r->hostname!=NULL){
			phost=(flash_squid_host_t*)cf->spf_squid_domainarry->elts;
			for(i=0;i<cf->spf_squid_domainarry->nelts;i++){
				if(phost[i].spf_host!=NULL){
					if (strcmp(phost[i].spf_host, "*") == 0) {
						rv=APR_SUCCESS;
						break;
					}else if(strstr(r->hostname,phost[i].spf_host)!=NULL){
						rv=APR_SUCCESS;
						break;
					}
				}
			}
		}

		if((rv!=APR_SUCCESS) && (content_type!=NULL)){
			ptype=(flash_squid_type_t*)cf->spf_squid_typearry->elts;
			for(i=0;i<cf->spf_squid_typearry->nelts;i++){
				if(ptype[i].spf_type!=NULL){
					if(strstr(content_type,ptype[i].spf_type)!=NULL){
						rv=APR_SUCCESS;
						break;
					}
				}
			}
		}

		if(rv==APR_SUCCESS){
			rv=apr_hashcluster_get_server(cfr->spf_squid,r->pool,r->hostname,&pproxy);
			if(rv==APR_SUCCESS){
				apr_table_add(r->headers_in, "X-Flashapp-Proxy", pproxy);
				flash_log_printf(FLASHLOG_MARK,R_LOG, r,
					"process_distribution_squid add proxy squid %s  %s",pproxy,r->hostname);

				if(cf->enable_ziproxyaftersquid==1){
					if((cfr->user_info.enable_passthrough==1) || (cf->enable_usedforpc==1)){
						apr_table_set(r->headers_in,"X-Flashapp-Pass","OK");
					}
				}

				//图片文件处理
				if(content_type!=NULL){
					if(((strncasecmp(content_type, "image/gif", 9)==0)||
					(strncasecmp(content_type, "image/jpeg", 10)==0)||
					(strncasecmp(content_type, "image/png", 9)==0))){
						if((r->filename!=NULL) && (cf->enable_ziproxyaftersquid==1)){
							ptn=apr_pstrdup(r->pool,r->filename);
							if(cfr->user_info.image_quality==IQ_HIGH){
								apr_snprintf(key, 12, "|%d.ziproxy",2);//用户配置属性
							}else if(cfr->user_info.image_quality==IQ_LOW){
								apr_snprintf(key, 12, "|%d.ziproxy",0);//用户配置属性
							}else if(cfr->user_info.image_quality==IQ_NO){ //用户配置属性
								apr_snprintf(key, 12, "|%d.ziproxy",3);
							}else if(cfr->user_info.image_quality==IQ_HIGH_1){ //用户配置属性
								apr_snprintf(key, 12, "|%d.ziproxy",4);
							}else if(cfr->user_info.image_quality==IQ_HIGH_2){ //用户配置属性
								apr_snprintf(key, 12, "|%d.ziproxy",5);
							}else if(cfr->user_info.image_quality==IQ_HIGH_3){ //用户配置属性
								apr_snprintf(key, 12, "|%d.ziproxy",6);
							}else{
								//apr_snprintf(key, 12, "|%d.ziproxy",1);
							}
						r->filename = apr_pstrcat(r->pool, ptn,key, NULL);
						}
					}
				}
			}
		}
	}
	return rv;
}

/**
 *处理ziproxy 的分发资源和属性
 *属性放到头中
 */
apr_status_t process_distribution_ziproxy(request_rec *r,flash_conf_req_t *cfr,flash_conf_t *cf)
{
	char key[12]={0};
	char *ptn=NULL;
	apr_status_t rv=DECLINED;
	const char *content_type=NULL;

	//图片等单一文件处理
	flash_log_printf(FLASHLOG_MARK,R_LOG, r,"process_distribution_ziproxy type %s ",r->content_type);
	if(r->content_type!=NULL){
		content_type=apr_pstrdup(r->pool,r->content_type);
	}else{
		content_type=apr_table_get(r->headers_in, "Accept");
	}

	if(content_type!=NULL&&r->filename!=NULL){
		if ((strncasecmp(content_type, "image/gif", 9)==0)||
				(strncasecmp(content_type, "image/jpeg", 10)==0)||
				(strncasecmp(content_type, "image/png", 9)==0))
		{
			ptn=apr_pstrdup(r->pool,r->filename);
			if(cfr->user_info.image_quality==IQ_HIGH){
				apr_snprintf(key, 12, "|%d.ziproxy",2);//用户配置属性
			}else if(cfr->user_info.image_quality==IQ_LOW){
				apr_snprintf(key, 12, "|%d.ziproxy",0);//用户配置属性
			}else if(cfr->user_info.image_quality==IQ_NO){ //用户配置属性
				apr_snprintf(key, 12, "|%d.ziproxy",3);
			}else if(cfr->user_info.image_quality==IQ_HIGH_1){ //用户配置属性
				apr_snprintf(key, 12, "|%d.ziproxy",4);
			}else if(cfr->user_info.image_quality==IQ_HIGH_2){ //用户配置属性
				apr_snprintf(key, 12, "|%d.ziproxy",5);
			}else if(cfr->user_info.image_quality==IQ_HIGH_3){ //用户配置属性
				apr_snprintf(key, 12, "|%d.ziproxy",6);
			}else{
				//apr_snprintf(key, 12, "|%d.ziproxy",1);
			}
			rv=APR_SUCCESS;
		}else if((strncasecmp(content_type, "application/javascript", 22)==0)||
			(strncasecmp(content_type, "text/css", 8)==0))
		{
			ptn=apr_pstrdup(r->pool,r->filename);
//			apr_snprintf(key, 12, ".ziproxy");
			rv=APR_SUCCESS;
		}
	}

	//地图处理
	if((r->unparsed_uri!=NULL) && (r->method!=NULL)&&(r->filename!=NULL))
	{
		//google 地图
		if((strncasecmp(r->unparsed_uri, "http://www.google.com/glm/mmap",30) == 0)||
			(strncasecmp(r->unparsed_uri, "http://www.google.cn/glm/mmap",29) == 0)||
			// gaode 地图
			(strstr(r->unparsed_uri,"cn.apple.com/appmaptile") && !strncasecmp(r->method,"POST",4))
			)
		{
			ptn=apr_pstrdup(r->pool,r->filename);
//			apr_snprintf(key, 12, ".ziproxy");
			rv=APR_SUCCESS;
		}
	}

	// app android 市场优化
	if((r->filename!=NULL) && (r->hostname !=NULL) && (strstr(r->hostname,"phobos.apple.com")!=NULL)){
		ptn=apr_pstrdup(r->pool,r->filename);
//		apr_snprintf(key, 12, ".ziproxy");
		rv=APR_SUCCESS;
	}

	if(rv==APR_SUCCESS){
		if((cfr->user_info.enable_passthrough==1) || (cf->enable_usedforpc==1)){
			apr_table_set(r->headers_in,"X-Flashapp-Pass","OK");
		}
		r->filename = apr_pstrcat(r->pool, ptn,key, NULL);
		apr_table_add(r->headers_in, "X-Flashapp-Proxy", cf->spf_ziproxy_proxy);
		flash_log_printf(FLASHLOG_MARK,R_LOG, r,"process_distribution add proxy ziproxy %s",r->filename);
	}
	return rv;
}

/**
 *处理http 内容 post
 *如果是独立图片 压缩处理
 * 输入过滤器
 */
apr_status_t process_content_from_in(ap_filter_t *filter, apr_bucket_brigade *bb,
        ap_input_mode_t eMode,apr_read_type_e eBlock,apr_off_t nBytes)
{
	apr_bucket *b;
	apr_status_t status = APR_SUCCESS;
	flash_conf_req_t *cfr = filter->ctx;
	request_rec *r=filter->r;
	apr_bucket_brigade *abb=NULL;
	apr_size_t len=0;

	const char *val=NULL;
	apr_table_t *headers=r->headers_out;


	if(cfr->image_c.type_image==NO_CHECK)
	{
		if (strncasecmp(r->content_type, "image/gif", 9)==0)
		{
			cfr->image_c.type_image=IMG_GIF;
		}else if(strncasecmp(r->content_type, "image/jpeg", 10)==0){
			cfr->image_c.type_image=IMG_JPEG;
		}else if(strncasecmp(r->content_type, "image/png", 9)==0){
			cfr->image_c.type_image=IMG_PNG;
		}else{
			cfr->image_c.type_image=NO_IMG;
		}
	}

	if((cfr->image_c.type_image==IMG_PNG)||
		(cfr->image_c.type_image==IMG_JPEG)||
		(cfr->image_c.type_image==IMG_GIF)){

		if(cfr->image_c.spf_all_cache==NULL){
			val = apr_table_get(headers, "Content-Length");
			if(val!=NULL){
				cfr->image_c.all_len=apr_atoi64(val);
				cfr->image_c.spf_all_cache=apr_pcalloc(r->pool,cfr->image_c.all_len);
			}else{
				return ap_get_brigade(filter->next, bb, eMode, eBlock, nBytes);
			}
		}


	if(cfr->image_c.spf_all_cache!=NULL){
		ap_get_brigade(filter->next, bb, eMode, eBlock, nBytes);
		len=cfr->image_c.all_len-cfr->image_c.now_len;
		status=apr_brigade_flatten(bb,(char*)(cfr->image_c.spf_all_cache+cfr->image_c.now_len),&len);
		apr_brigade_destroy(bb);
			//数据读取完毕， 压缩数据处理

			if(cfr->image_c.now_len>=cfr->image_c.all_len){
				//调用压缩算法
			//	abb=apr_brigade_create(r->pool, filter->c->bucket_alloc);
			//	apr_brigade_write(abb, NULL, NULL, cfr->image_c.spf_all_cache, cfr->image_c.all_len);
			//	ap_get_brigade(filter->next, abb, AP_MODE_READBYTES, eBlock, cfr->image_c.all_len);
			}
			flash_log_printf(FLASHLOG_MARK,R_LOG, filter->r,
				"process_content in all:%"APR_INT64_T_FMT" now:%"APR_INT64_T_FMT,
				cfr->image_c.all_len,cfr->image_c.now_len);
			//return OK;//处理了内容的
		}else{
			//放在最后 return
		}
	}else{
		//放在最后 return
	}
	return ap_get_brigade(filter->next, bb, eMode, eBlock, nBytes);//没处理内容的
}


/**
 *处理http 内容 get
 *如果是独立图片 压缩处理
 *输出过滤器
 */
apr_status_t process_content_from_out(ap_filter_t *filter, apr_bucket_brigade *bb)
{
	apr_bucket *b;
	apr_status_t status = OK;
	flash_conf_req_t *cfr = filter->ctx;
	request_rec *r=filter->r;
	apr_bucket_brigade *abb=NULL;
	apr_size_t len=0;

	const char *val;
	apr_table_t *headers=r->headers_out;

	if(cfr->image_c.type_image==NO_CHECK)
	{
		if (strncasecmp(r->content_type, "image/gif", 9)==0)
		{
			cfr->image_c.type_image=IMG_GIF;
		}else if(strncasecmp(r->content_type, "image/jpeg", 10)==0){
			cfr->image_c.type_image=IMG_JPEG;
		}else if(strncasecmp(r->content_type, "image/png", 9)==0){
			cfr->image_c.type_image=IMG_PNG;
		}else{
			cfr->image_c.type_image=NO_IMG;
		}
	}

	if(cfr->image_c.type_image==IMG_PNG||
		cfr->image_c.type_image==IMG_JPEG||
		cfr->image_c.type_image==IMG_GIF){

		if(cfr->image_c.spf_all_cache==NULL){
			val = apr_table_get(headers, "Content-Length");
			if(val!=NULL){
				cfr->image_c.all_len=apr_atoi64(val);
				cfr->image_c.spf_all_cache=apr_pcalloc(r->pool,cfr->image_c.all_len);
			}else{
				return ap_pass_brigade(filter->next,bb);
			}
		}

	if(cfr->image_c.spf_all_cache!=NULL){
		len=cfr->image_c.all_len-cfr->image_c.now_len;
		status=apr_brigade_flatten(bb,(char*)(cfr->image_c.spf_all_cache+cfr->image_c.now_len),&len);
		if(status==APR_SUCCESS){
			cfr->image_c.now_len+=len;
		}
		apr_brigade_destroy(bb);
			//数据读取完毕， 压缩数据处理
		if(cfr->image_c.now_len>=cfr->image_c.all_len){
			//调用压缩算法
			abb=apr_brigade_create(r->pool, filter->c->bucket_alloc);
			apr_brigade_write(abb, NULL, NULL, cfr->image_c.spf_all_cache, cfr->image_c.all_len);
			ap_pass_brigade(filter->next,abb);
		}
		flash_log_printf(FLASHLOG_MARK,R_LOG, filter->r,
				"process_content all:%"APR_SIZE_T_FMT" now:%"APR_SIZE_T_FMT,
				cfr->image_c.all_len,cfr->image_c.now_len);
			return OK;//处理了内容的
		}else{
			//放在最后 return
		}
	}else{
		//放在最后 return
	}
	return ap_pass_brigade(filter->next,bb);//没处理内容的
}

/**
 *处理 第三方防代理 协议
 */
apr_status_t set_third_party_proxy(request_rec *r)
{
	apr_status_t status = DECLINED;
	apr_table_t *headersin=r->headers_in;
	char *val=NULL;
	char *pfind=NULL;
	int ilen=0;
	int icount=0;

	//instagram  video
	if(r->filename!=NULL){
		if(strncasecmp(r->filename, "proxy:", 6)==0){
			val=apr_pstrdup(r->pool,r->filename);
			pfind=strstr(val,"127.0.0.1:13758/");
			if(pfind !=NULL){
				pfind+=16;
				if(pfind && strncasecmp(pfind, "http://", 7) == 0 )
				{
					r->uri = apr_pstrdup(r->pool,pfind);
					r->filename = apr_pstrcat(r->pool, "proxy:", r->uri, NULL);
					r->hostname = apr_pstrdup(r->pool,pfind);
					r->unparsed_uri=apr_pstrdup(r->pool,r->uri);
					r->the_request=apr_pstrcat(r->pool, r->method," ",r->unparsed_uri, NULL);
					apr_uri_parse(r->pool, r->unparsed_uri, &r->parsed_uri);
					apr_table_set(r->headers_in,"Host",r->parsed_uri.hostname);
					flash_log_printf(FLASHLOG_MARK,R_LOG, r,
							"third party proxy: %s |%s  filename: %s  ",val,pfind,r->filename);
					status=OK;
				}
			}
		}
	}
	return status;
}


/**
 *处理 移动网关私有代理协议  X-Online-Host
 */
apr_status_t set_xonline_host_proxy(request_rec *r)
{
	apr_status_t status = DECLINED;
	apr_table_t *headersin=r->headers_in;
	const char *val=NULL;
	char *pfind=NULL;
	int ilen=0;
	int icount=0;

	val=apr_table_get(headersin, "X-Online-Host");
	if(val!=NULL){
		if(r->filename!=NULL){
			if(strncasecmp(r->filename, "proxy:", 6)==0){
				ilen=strlen(val);
				pfind=apr_pstrdup(r->pool,val);
				while (pfind && *pfind == ' ' &&icount<ilen){
					pfind++;
					icount++;
				}

				if(pfind && strncasecmp(pfind, "http://", 7) == 0 )
				{
					pfind += 7 ;
				}

				if(r->parsed_uri.query!=NULL){
					r->uri = apr_pstrcat(r->pool, ap_http_scheme(r),"://",pfind, r->parsed_uri.path,"?",r->parsed_uri.query, NULL);
				}else{
					r->uri = apr_pstrcat(r->pool, ap_http_scheme(r),"://" ,pfind, r->parsed_uri.path, NULL);
				}
				r->filename = apr_pstrcat(r->pool, "proxy:", r->uri, NULL);
				r->hostname = apr_pstrdup(r->pool,pfind);
				apr_table_set(r->headers_in,"Host",pfind);
				r->unparsed_uri=apr_pstrdup(r->pool,r->uri);
				r->the_request=apr_pstrcat(r->pool, r->method," ",r->unparsed_uri, NULL);
				apr_uri_parse(r->pool, r->unparsed_uri, &r->parsed_uri);
				flash_log_printf(FLASHLOG_MARK,R_LOG, r,
					 "X-Online-Host: %s |%s  filename: %s  ",val,pfind,r->filename);
				status=OK;
			}
		}
	}
	return status;
}

/**
 *静态文件缓存
 *解决大文件本地缓存
 *自定义url 到本地缓存
 *规则
 */
apr_status_t detect_flashapp_cache(request_rec *r,flash_conf_req_t *cfr,flash_conf_t *cf)
{
	apr_status_t status = DECLINED;
	char *pdata=NULL;
	char *pfind=NULL;
	const char *key = NULL;
	const char *value = NULL;
	apr_hash_index_t *hi = NULL;
	const char *docroot = NULL;
	char *pfilepath = NULL;
	char  *thisserver = NULL;
	char  *thisport = NULL;
	apr_finfo_t finfo;

	docroot =ap_document_root(r);

	if(r->method_number == M_GET && cfr->spf_cache_hash!=NULL && (apr_hash_count(cfr->spf_cache_hash)>0)){
		pdata=apr_pstrdup(r->pool,r->unparsed_uri);
		for (hi = apr_hash_first(r->pool, cfr->spf_cache_hash); hi; hi = apr_hash_next(hi)){
			apr_hash_this(hi, (const void**)&key, NULL, (void**)&value);
			if(key!=NULL && value!=NULL){
				pfind=strstr(pdata,key);
				if(pfind!=NULL){
					*pfind='\0';
					pfind+=strlen(key);
					pfilepath=apr_pstrcat(r->pool,docroot,value,pfind,NULL);
					break;
				}
			}
		}

		if(pfilepath!=NULL){
			status=apr_stat(&finfo, pfilepath, APR_FINFO_MIN,r->pool);
		}

		//文件存在
		if(status==APR_SUCCESS){
			if(r->proxyreq != PROXYREQ_NONE){
				r->proxyreq = PROXYREQ_NONE;
			}

			cfr->in_len=cfr->out_len=finfo.size;//log 不传递第二次cfr 所以这里赋值

			pfilepath=apr_pstrcat(r->pool,value,pfind,NULL);

			if(r->server->server_hostname!=NULL){
				thisserver = apr_pstrdup(r->pool,r->server->server_hostname);
				if(r->server->port!=80 && r->server->port !=0){
					thisport = apr_psprintf(r->pool, ":%u", r->server->port);
				}
			}

			flash_log_printf(FLASHLOG_MARK,R_LOG, r,"detect_flashapp_cache src  %s  %s \n %s \n %s \n %s \n %s",
					thisserver,thisport,r->filename,r->unparsed_uri,r->uri,r->the_request);

			r->unparsed_uri = apr_pstrcat(r->pool,ap_http_scheme(r),"://",
					(thisserver!=NULL)?thisserver:"localhost",(thisport!=NULL)?thisport:"",pfilepath,NULL);

			r->hostname = apr_psprintf(r->pool, "%s%s",
					(thisserver!=NULL)?thisserver:"localhost",(thisport!=NULL)?thisport:"");

			apr_table_set(r->headers_in, "Host",r->hostname);

			r->uri = apr_pstrdup(r->pool,r->unparsed_uri);

			r->filename = apr_pstrdup(r->pool,pfilepath);

			r->handler = "flashapp-handler";

			apr_table_set(r->headers_in,"X-Flashapp-Pass","OK");

			flash_log_printf(FLASHLOG_MARK,R_LOG, r,"detect_flashapp_cache change %s  %s  %s  %s  ",
								r->filename,r->unparsed_uri,r->uri,r->the_request);
		}
	}

	return status;
}


/**
 *自定义代理协议  X-FlashApp-Proxy 正向代理
 *需要重新编译mod_proxy
 *分发 squid  ziproxy  audio  video
 *反向代理
 */
apr_status_t set_xflashapp_proxy(request_rec *r,flash_conf_req_t *cfr,flash_conf_t *cf)
{
	apr_status_t status = DECLINED;
	char *pdata=NULL;
    char *pfind=NULL;
    int ilen=0;

    flash_log_printf(FLASHLOG_MARK,R_LOG, r,"set_xflashapp_proxy %s  type %s",r->filename,r->content_type);

	if(r->filename!=NULL){
		if(strncasecmp(r->filename, "proxy:", 6)==0){
			//video and audio proxy
			pdata=apr_pstrdup(r->pool,r->filename);
			pfind=strstr(pdata,kXFlashProxyVideo);
			if(pfind!=NULL && cf->spf_video_proxy!=NULL){
				ilen=strlen(kXFlashProxyVideo);
				*pfind='\0';
				pfind+=ilen;
				r->filename=apr_pstrcat(r->pool,pdata,pfind, NULL);
				apr_table_add(r->headers_in, "X-Flashapp-Proxy", cf->spf_video_proxy);
				//视频质量
				apr_table_add(r->headers_in, "Video-Quality", "60");
				apr_table_add(r->headers_in, "Video-Max-Width", "640");
				apr_table_add(r->headers_in, "Max-Wait-Time", "10");
				status=OK;
			}else{
				pfind=strstr(pdata,kXFlashProxyAudio);
				if(pfind!=NULL && cf->spf_audio_proxy!=NULL){
					ilen=strlen(kXFlashProxyAudio);
					*pfind='\0';
					pfind+=ilen;
					r->filename=apr_pstrcat(r->pool,pdata,pfind, NULL);
					apr_table_add(r->headers_in, "X-Flashapp-Proxy", cf->spf_audio_proxy);
					//音频质量
					apr_table_add(r->headers_in, "Audio-Quality", "60");
					apr_table_add(r->headers_in, "Max-Wait-Time", "10");
					status=OK;
				}
			}

			/** 反向代理 可以改造支持
			 *
			if (pdata) {
            	r->filename = found;
            	pfind=strstr(r->filename,r->hostname);
            	if(pfind!=NULL){
            		ilen=strlen(r->hostname);
					*pfind='\0';
				 	 pfind+=ilen;
					r->filename=apr_pstrcat(r->pool,r->filename,pdata,pfind, NULL);
            	}
            	r->handler = "proxy-server";
            	r->proxyreq = PROXYREQ_REVERSE;
                //apr_table_setn(r->notes, "proxy-nocanon", "1");
            	status=OK;
        	}
			 */

			//squid  proxy
			if((status!=OK) && (cf->spf_squid_proxy!=NULL)){
				if(process_distribution_squid(r,cfr,cf)==APR_SUCCESS){
					status=OK;
				}
			}

			//ziproxy proxy
			if((status!=OK) && (cf->spf_ziproxy_proxy!=NULL)){
				if(process_distribution_ziproxy(r,cfr,cf)==APR_SUCCESS){
					status=OK;
				}
			}
		}
	}
	return status;
}

/**
 *自定义代理协议  X-FlashApp-Proxy 正向代理
 *需要重新编译mod_proxy
 *分发 squid  ziproxy  audio  video
 *反向代理
 */
apr_status_t check_connect_port(request_rec *r,flash_conf_req_t *cfr,flash_conf_t *cf)
{
	apr_status_t status = APR_SUCCESS;
	flash_connect_port_t *ports=NULL;
	int i=0;
	ports=(flash_connect_port_t*)cf->spf_forbid_connect_port->elts;
	for(i=0;i<cf->spf_squid_typearry->nelts;i++){
		if(ports[i].icport == r->parsed_uri.port){
			status=DECLINED;
			break;
		}
	}
	return status;
}

/**
 *处理http 视频 音频
 *跳转
 *输出过滤器
 */
apr_status_t process_content_video_audio(ap_filter_t *filter, apr_bucket_brigade *bb,flash_conf_t *cf)
{
	apr_status_t status = DECLINED;
	request_rec *r=filter->r;
	flash_conf_req_t *cfr = filter->ctx;
	char *lurl=NULL;
	char *pdata=NULL;
	char *pfind=NULL;

	if(r->content_type!=NULL && r->unparsed_uri!=NULL ){
		if(cf->spf_video_proxy!=NULL){
			if(strstr(r->unparsed_uri,kXFlashProxyVideo)==NULL){
				if (strncasecmp(r->content_type, "video/", 6)==0){
					r->status= HTTP_MOVED_TEMPORARILY;
					pdata=apr_pstrdup(r->pool,r->unparsed_uri);
					pfind=strrchr(pdata,'.');
					if(pfind!=NULL){
						*pfind='\0';
						lurl=apr_pstrcat(r->pool,pdata,kXFlashProxyVideo, NULL);
						*pfind='.';
						lurl=apr_pstrcat(r->pool,lurl,pfind, NULL);
					}else{
						lurl=apr_pstrcat(r->pool,r->unparsed_uri,kXFlashProxyVideo, NULL);
					}
					//apr_table_set(filter->r->headers_out, "Location", lurl);
					status=OK;
					ap_remove_output_filter(filter);
					flash_log_printf(FLASHLOG_MARK,R_LOG, r,"process_content_video_audio  %s",lurl);
					ap_internal_redirect(apr_pstrcat(r->pool, lurl,
								            r->args ? "?" : NULL, r->args, NULL), r);
				}
			}
		}

		if(cf->spf_audio_proxy!=NULL){
			if(strstr(r->unparsed_uri,kXFlashProxyAudio)==NULL){
				if (strncasecmp(r->content_type, "audio/", 6)==0){
					r->status= HTTP_MOVED_TEMPORARILY;
					pdata=apr_pstrdup(r->pool,r->unparsed_uri);
					pfind=strrchr(pdata,'.');
					if(pfind!=NULL){
						*pfind='\0';
						lurl=apr_pstrcat(r->pool,pdata,kXFlashProxyAudio, NULL);
						*pfind='.';
						lurl=apr_pstrcat(r->pool,lurl,pfind, NULL);
					}else{
						lurl=apr_pstrcat(r->pool,r->unparsed_uri,kXFlashProxyAudio, NULL);
					}
					//apr_table_set(filter->r->headers_out, "Location", lurl);
					status=OK;
					ap_remove_output_filter(filter);
					flash_log_printf(FLASHLOG_MARK,R_LOG, r,"process_content_video_audio  %s",lurl);
					ap_internal_redirect(apr_pstrcat(r->pool, lurl,
									r->args ? "?" : NULL, r->args, NULL), r);
				}
			}
		}
	}
	return status;
}


/**
 *判断查找到的域名是否是完整的
 * 域名由 数字 字母  -  和 . 构成
 *如果前一个字符和最后一个字符都没有则是完整的
 */
apr_status_t check_isall_domain(char p)
{
	 if((p>=48)&&(p<=57)){
		 return DECLINED;
	 }

	 if( ((p >= 65)&&(p <= 90)) || ((p >= 97)&&(p <= 122)) ){
		 return DECLINED;
	 }

	 if((p== '.' )||p == '-'){
		 return DECLINED;
	 }
	 return OK;
}

/**
 *处理http 内容
 *txt  内容替换
 *输出过滤器
 *list_hash
 *iflag  1
 *是把其中的 value 替换成key
 *value 不能重复
 *iflag 0  key 替换value
 */
apr_status_t process_content_replace(ap_filter_t *filter, apr_bucket_brigade *bb,apr_hash_t *list_hash,int iflag)
{
	apr_bucket *b=NULL,*newb=NULL;
	apr_status_t status = DECLINED;
	flash_conf_req_t *cfr = filter->ctx;
	request_rec *r=filter->r;

	const char *data=NULL;
	char *pdata=NULL;
	char *pfind=NULL;
	apr_size_t len=0, klen=0 ,vlen=0;
	int ifid=-1,ialen=0,inoc=0;
	const char *key = NULL;
	const char *value = NULL;
	apr_hash_index_t *hi=NULL;

	if ((list_hash==NULL)||(apr_hash_count(list_hash)<=0))
	{
		return status;
	}

	 if(!APR_BRIGADE_EMPTY(bb)){
		for (hi = apr_hash_first(r->pool, list_hash); hi; hi = apr_hash_next(hi)){
			apr_hash_this(hi, (const void**)&key, NULL, (void**)&value);

//			flash_log_printf(FLASHLOG_MARK,R_LOG, r,
//					    	"process_content_replace the key is: %s  value:%s  ",key,value);

			if(key!=NULL && value!=NULL && (strcmp(key,value)!=0) ){

				for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b))
				{
					if (APR_BUCKET_IS_EOS(b)) {
							break;
					}
					if (APR_BUCKET_IS_FLUSH(b)) {
							continue;
					}
					apr_bucket_read(b, &data, &len, APR_BLOCK_READ);

					if(len>0){
		    			pdata=(char *)data;
		    			ialen=len;
		    			inoc=0;
		    			if(pdata!=NULL){
		    				if(iflag==1){
		    				  pfind=strstr(pdata,value);
		    				}else{
		    				  pfind=strstr(pdata,key);
		    				}
		    			}else{
		    				pfind=NULL;
		    			}

		    			if(pfind!=NULL){
		    				ifid=((unsigned long int)pfind - (unsigned long int)pdata) / sizeof(char);
		    				klen=strlen(key);
		    				vlen=strlen(value);

		    				while(ifid >= 0){
		    					ialen-=ifid;
		    					if(iflag==1){
		    						ialen-=vlen;
		    					}else{
		    						ialen-=klen;
		    					}

		    					if(ialen < 0){
		    						break;
		    					}
		    					pdata+=ifid;

		    					//检测头一个字母
		    					status=check_isall_domain((pdata-1)[0]);

		    					if(iflag==1){
		    						pdata+=vlen;
		    					}else{
		    						pdata+=klen;
		    					}

		    					//检测后一个字母
		    					if(status==APR_SUCCESS){
		    						status=check_isall_domain(pdata[0]);
		    					}

		    					if(status==APR_SUCCESS){
		    						//准备开始替换
		    						ifid+=inoc;//合并没有替换的长度
		    						apr_bucket_split(b,ifid);
		    						newb = APR_BUCKET_NEXT(b);
		    						if(iflag==1){
		    							status=apr_bucket_split(newb,vlen);
		    						}else{
		    							status=apr_bucket_split(newb,klen);
		    						}
		    						b = APR_BUCKET_NEXT(newb);
		    						apr_bucket_delete(newb);
		    						if(iflag==1){
		    							newb=apr_bucket_pool_create(key,klen,r->pool,bb->bucket_alloc);
		    						}else{
		    							newb=apr_bucket_pool_create(value,vlen,r->pool,bb->bucket_alloc);
		    						}
		    						APR_BUCKET_INSERT_BEFORE(b, newb);
		    						inoc=0;
		    					}else{//不提换要累加长度
			    					if(iflag==1){
			    						inoc=inoc+ifid+vlen;
			    					}else{
			    						inoc=inoc+ifid+klen;
			    					}
		    					}

		    					//替换完成，继续下一个循环
		    					if(pdata!=NULL && ialen>0){
		    						if(iflag==1){
		    							pfind=strstr(pdata,value);
		    						}else{
		    							pfind=strstr(pdata,key);
		    						}
		    					}else{
		    						pfind=NULL;
		    					}

		    					if(pfind!=NULL){
		    						ifid=((unsigned long int)pfind - (unsigned long int)pdata) / sizeof(char);
		    					}else{
		    						ifid=-1;
		    					}
		    					status=APR_SUCCESS;
		    				}
		    			}
		    		}
		    	}
		    }
		}
	 }
	return status;
}


/**
 *
 *txt
 *插入 js http 头
 */
apr_status_t process_content_inserthead(ap_filter_t *filter, apr_bucket_brigade *bb,const char *pheadc)
{
	apr_status_t status = DECLINED;
	flash_conf_req_t *cfr = filter->ctx;
	request_rec *r=filter->r;

	apr_size_t len=strlen(pheadc);
	apr_hash_t * list_hash=NULL;
	const char *data;
	char * key=NULL;

	if (strncasecmp(r->content_type, "text/html", 9)!=0)
	{
		return status;
	}

	if(len>0){
		list_hash=apr_hash_make(r->pool);
		key=apr_pstrdup(r->pool,"</head>");
		data=apr_pstrcat(r->pool,pheadc,"</head>", NULL);
		apr_hash_set(list_hash,key, APR_HASH_KEY_STRING, data);
		status=process_content_replace(filter,bb,list_hash,0);
	}
	return status;
}

/**
 *http 头
 *txt
 *替换 指定域名
 */
apr_status_t process_headers_replacehost(ap_filter_t *filter)
{
	apr_status_t status = DECLINED;
	flash_conf_req_t *cfr = filter->ctx;
	request_rec *r=filter->r;
	const char *val= NULL;
	const char *key = NULL;
	const char *value = NULL;
	char *pdata=NULL;
	char *pfind=NULL;
	char *newdata=NULL;
	apr_size_t len=0, klen=0 ,vlen=0;
	apr_hash_index_t *hi=NULL;
	int ifid=-1,ialen=0;

	if(cfr->spf_domain_hash!=NULL){
		val=apr_table_get(r->headers_out,"Location");
		if(val!=NULL){
			flash_log_printf(FLASHLOG_MARK,R_LOG, r,"process_headers_replacehost in %s ",val);
			newdata=apr_pstrdup(r->pool,val);
			for (hi = apr_hash_first(r->pool, cfr->spf_domain_hash); hi; hi = apr_hash_next(hi)){
				apr_hash_this(hi, (const void**)&key, NULL, (void**)&value);
				if(key!=NULL && value!=NULL && newdata!=NULL && (strcmp(key,value)!=0) ){
					pdata=apr_pstrdup(r->pool,newdata);
					ialen=strlen(pdata);
					pfind=strstr(pdata,value);
					if(pfind!=NULL){
						newdata=NULL;
						ifid=((unsigned long int)pfind - (unsigned long int)pdata) / sizeof(char);
						klen=strlen(key);
						vlen=strlen(value);
						while(ifid >= 0){
							ialen-=ifid;
						    ialen-=vlen;
						    if(ialen < 0){
						    	break;
						    }
						    //检测头一个字母
						    status=check_isall_domain(pdata[ifid-1]);
						    //检测后一个字母
						    if(status==APR_SUCCESS){
						    	status=check_isall_domain(pdata[ifid+vlen]);
						    }

						    if(status==APR_SUCCESS){
						    	pdata[ifid]='\0';
						    	if(newdata!=NULL){
						    		newdata=apr_pstrcat(r->pool,newdata,pdata,key,NULL);
						    	}else{
						    		newdata=apr_pstrcat(r->pool,pdata,key,NULL);
						    	}
						    }else{
						    	pdata[ifid]='\0';
						    	if(newdata!=NULL){
						    		newdata=apr_pstrcat(r->pool,newdata,pdata,value,NULL);
						    	}else{
						    		newdata=apr_pstrcat(r->pool,pdata,value,NULL);
						    	}
						    }
						    pdata+=ifid;
						    pdata+=vlen;

						    if(ialen>0){
						    	pfind=strstr(pdata,value);
						    }else{
						    	pfind=NULL;
						    }
						    if(pfind!=NULL){
						    	ifid=((unsigned long int)pfind - (unsigned long int)pdata) / sizeof(char);
						    }else{
						    	ifid=-1;
						    }
						}
						if(pdata!=NULL){
							if(newdata!=NULL){
								newdata=apr_pstrcat(r->pool,newdata,pdata,NULL);
							}else{
								newdata=apr_pstrcat(r->pool,pdata,NULL);
							}
						}
					}
				}
			}
			if(newdata!=NULL){
				apr_table_set(filter->r->headers_out, "Location", newdata);
				flash_log_printf(FLASHLOG_MARK,R_LOG, r,"process_headers_replacehost out %s ",newdata);
			}
		}
	}
	return status;
}


/**
 *htt 内容
 *txt
 *替换 指定域名
 */
apr_status_t process_content_replacehost(ap_filter_t *filter, apr_bucket_brigade *bb)
{
	apr_status_t status = DECLINED;
	flash_conf_req_t *cfr = filter->ctx;
	request_rec *r=filter->r;

	if(cfr->spf_domain_hash!=NULL){
		apr_size_t len=apr_hash_count(cfr->spf_domain_hash);

		if ((r->content_type!=NULL)
				&&(strncasecmp(r->content_type, "text/html", 9)==0||
				strncasecmp(r->content_type, "application/javascript", 22)==0 ||
				strncasecmp(r->content_type, "text/css", 8)==0)
		){
			if(len>0){
				status=process_content_replace(filter,bb,cfr->spf_domain_hash,1);
			}
		}
	}
	return status;
}

/**
 *发送命令
 *使用http 头 向客户端
 *flag  APR_SUCCESS  正常头
 *flag  其他位错误头信息修改
 */
apr_status_t set_command(request_rec *r,flash_conf_req_t *cfr,apr_status_t flag)
{
	apr_status_t rv;

	apr_table_t *commheaders = NULL;

	if(flag==APR_SUCCESS){
		commheaders=r->headers_out;
	}else{
		commheaders=r->err_headers_out;
	}

    char token[33]={0};

    char auth[128]={0};

    char data[]="1";

    char key[128]={0};

    if(cfr->user_info.server_mode==MODE_SDK){
    	if(cfr->user_info.enable_used==0){
    		cfr->user_info.check_result = 4;
    	}
    	//flashapp domain  都成功
    	if(cfr->user_info.enable_passthrough){
    		cfr->user_info.check_result= 1;
    	}

        //新协议
        if(cfr->user_info.auth_mode == MODE_LANXUN || cfr->user_info.auth_mode == MODE_NORMAL){
        	if (cfr->user_info.enable_settoken == 1) {
        		make_client_token(token);
            	//考虑有效时间变化 随机取值 设置token 有效期
            	snprintf(key, 128, "%s_token", token);
            	rv = memcache_put(cfr->spf_memc, key, data, 1, 1800); //30分钟
            	flash_log_printf(FLASHLOG_MARK, R_LOG, r,"set mem is rv: %d  |%s  ", rv, token);

        		apr_snprintf(auth, 128,"%d,%s",cfr->user_info.check_result,token);
        	}else{
        		apr_snprintf(auth, 128,"%d",cfr->user_info.check_result);
        	}
        	apr_table_set(commheaders, "X-Fastsdk-Cmd", auth);
        }else{
        	apr_snprintf(auth, 10,"%d",cfr->user_info.check_result);
        	apr_table_set(commheaders, "auth", auth);

        	if (cfr->user_info.enable_settoken == 1) {
        		make_client_token(token);
        		apr_table_set(commheaders, "token", token);
        		//apr_table_unset(headersout,"Cache-Control");
        		if (cfr->user_info.spf_appid != NULL ) {
        			//考虑有效时间变化 随机取值 设置token 有效期
        			snprintf(key, 128, "%s_token", token);
        			rv = memcache_put(cfr->spf_memc, key, data, 1, 1800); //30分钟
        			flash_log_printf(FLASHLOG_MARK, R_LOG, r,
						"set mem is rv: %d  |%s  ", rv, token);
        		}
        	}
        }
    }
	return OK;

	//DECLINED 继续
}

/**
 *某些不能添加pagespeed 优化
 *
 */
static apr_status_t check_used_pagespeed(ap_filter_t *filter)
{
	const char *val=NULL;
	apr_status_t rv = APR_SUCCESS;
	request_rec * r= filter->r;
	flash_conf_req_t *cfr = filter->ctx;

	if(cfr->user_info.server_mode==MODE_SDK){
		if(cfr->user_info.enable_pagespeed == 0){
			rv = DECLINED;
		}
	}else{
		val = apr_table_get(r->headers_in, "User-Agent");
		if(strstr(r->hostname,"ebrun.com")!=NULL){
			rv = DECLINED;
		}
		if(val!=NULL){
			//ppstream tv
			if(
				strstr(val,"Apache-HttpClient")!=NULL &&
				(
				 strstr(r->hostname,"dp.ugc.pps.tv")!=NULL
				)
				){
				rv = DECLINED;
			}
		}else{

		}
	}

	if(r->method_number != M_GET){
		rv = DECLINED;
	}
/*
	if(rv!=APR_SUCCESS){
	  ap_filter_rec_t* clf = ap_get_output_filter_handle("MOD_FLASHSDK_OUTPUT_FILTER") ;
	  ap_filter_t* ff = filter->next ;
	  do {
	    ap_filter_t* fnext = ff->next ;
	    if ( ff->frec == clf ){
	      ap_remove_output_filter(ff) ;
	      break;
	    }
	    ff = fnext ;
	  } while ( ff ) ;
	}
	*/
	return rv;
}

/**
 *添加pagespeed 控制
 *
 */
apr_status_t add_headers_pagespeed(ap_filter_t *filter)
{
	const char *val=NULL;
	request_rec * r= filter->r;
	flash_conf_req_t *cfr = filter->ctx;
	apr_table_t *headers=r->headers_in;

	//apr_table_add(headers, "Vary", "User-Agent");
	//apr_table_add(headers, "Cache-Control", "private");
	//头设置不管用 要在配置文件中写入
	//apr_table_add(headers, "ModPagespeedTrackOriginalContentLength", "on");

	if(check_used_pagespeed(filter) ==APR_SUCCESS ){
		apr_table_add(headers, "ModFlashsdk", "on");
		apr_table_add(headers, "ModFlashsdkFilters", "+rewrite_images,+convert_png_to_jpeg");
		apr_table_add(headers, "ModFlashsdkFilters", "+recompress_images,+inline_images");

		apr_table_add(headers, "ModFlashsdkFilters", "+combine_css,+combine_javascript");
		apr_table_add(headers, "ModFlashsdkFilters", "+rewrite_javascript,+rewrite_css");
		apr_table_add(headers, "ModFlashsdkFilters", "+inline_css,+inline_javascript");

		//html
		apr_table_add(headers, "ModFlashsdkFilters", "+remove_comments,+collapse_whitespace");
		apr_table_add(headers, "ModFlashsdkFilters", "+elide_attributes,+remove_quotes");

		apr_table_add(headers, "ModFlashsdkFilters", "+move_css_above_scripts,+move_css_to_head");

		/*
		apr_table_add(headers, "ModPagespeed", "on");
		apr_table_add(headers, "ModPagespeedFilters", "+rewrite_images,+convert_png_to_jpeg");
		apr_table_add(headers, "ModPagespeedFilters", "+recompress_images,+inline_images");

		apr_table_add(headers, "ModPagespeedFilters", "+combine_css,+combine_javascript");
		apr_table_add(headers, "ModPagespeedFilters", "+rewrite_javascript,+rewrite_css");
		apr_table_add(headers, "ModPagespeedFilters", "+inline_css,+inline_javascript");
		//html
		apr_table_add(headers, "ModPagespeedFilters", "+remove_comments,+collapse_whitespace");
		apr_table_add(headers, "ModPagespeedFilters", "+elide_attributes,+remove_quotes");

		apr_table_add(headers, "ModPagespeedFilters", "+move_css_above_scripts,+move_css_to_head");
		 */


		apr_table_add(headers, "ModFlashsdkImageLimitOptimizedPercent", "100");

//		apr_table_add(headers, "ModPagespeedImageLimitOptimizedPercent", "100");
//
		val=apr_itoa(r->pool,(int)cfr->user_info.image_quality);

		if(val==NULL){
			val=apr_pstrdup(r->pool,"30");
		}

		//直接通过不处理
		if(cfr->user_info.enable_passthrough){
			apr_table_set(headers, "ModFlashsdk", "off");
			//apr_table_add(headers, "ModPagespeed", "off");
		}
//限制逻辑整理扩充
		if(cfr->user_info.server_mode==MODE_NOPROXY){

		}
////////////////////////
		flash_log_printf(FLASHLOG_MARK,R_LOG, r,"add_headers_pagespeed ------%s  stat:%d ",val,r->status);
		apr_table_add(headers, "ModFlashsdkImageRecompressionQuality", val);
		//apr_table_add(headers, "ModPagespeedImageRecompressionQuality", val);
	}else{
		apr_table_add(headers, "ModFlashsdk", "off");
		//apr_table_add(headers, "ModPagespeed", "off");
	}

	return OK;
}

/**
 *获取 内容的原始长度 和处理后长度
 */
apr_status_t get_headers_length(request_rec *r,flash_conf_req_t *cfr)
{
	const char *val;
	apr_table_t *headers=r->headers_out;
	val = apr_table_get(headers, "Content-Length");
	if(val!=NULL){
			cfr->out_len=apr_atoi64(val);
	}

	val = apr_table_get(headers, "Original-Length");//for ziproxy
	if(val!=NULL){
			cfr->in_len=apr_atoi64(val);
			//apr_table_unset(headers, "Original-Length");
			//AP_FTYPE_PROTOCOL  修改http 头不生效
	}

	val = apr_table_get(headers, "X-Original-Content-Length");//for pagespeed
	if(val!=NULL){
			cfr->in_len=apr_atoi64(val);
			//apr_table_unset(headers, "X-Original-Content-Length");
			//AP_FTYPE_PROTOCOL  修改http 头不生效
	}

	cfr->e_time = apr_time_now();

	flash_log_printf(FLASHLOG_MARK,R_LOG, r,
			 "get_headers_length in %"APR_OFF_T_FMT"out %"APR_OFF_T_FMT "%s ",
			 cfr->in_len,cfr->out_len,r->unparsed_uri);

}
////////////////////日志处理部分
/**
 * 在每个请求中收集日志信息并发送消息队列
 */
apr_status_t log_collection(request_rec *r,flash_conf_req_t *cfr,flash_conf_t *cf)
{
	flash_msg_item_t seitem;
	const char *pagent = NULL;
	const char *prefer = NULL;
	char *ptype =NULL;
	char *plt =NULL;
	char *pdip = NULL;
	apr_status_t rv;
	apr_time_t imq=0;
	char buffer[ONCE_LOG_LONG]={0};
	apr_size_t buflen;

	char stime[APR_CTIME_LEN]={0};
	apr_size_t rvt;
	apr_time_exp_t xt;
	double ftimestamp=0.0;
	//one day sec

	//页面发生错误不记录日志
	if(r->status >= 300)
		return OK;

	if(r->hostname==NULL)
		return OK;

	if(cfr->user_info.enable_passthrough ==1){
		return OK;
	}

	if(cfr->in_len<=0){
		cfr->in_len = cfr->in_lenadd;
	}

	flash_log_printf(FLASHLOG_MARK,R_LOG, r,"get len is in:%"APR_SIZE_T_FMT " out is:%"
			APR_SIZE_T_FMT,cfr->in_len,cfr->out_len);

	if(cfr->in_len > INT_MAX ){
		cfr->in_len=0;
	}
	if(cfr->out_len > INT_MAX ){
		cfr->out_len =0;
	}

	if(cfr->in_len<=0 && cfr->out_len<=0){
		cfr->in_len=cfr->out_len=r->bytes_sent;
	}

	if(cfr->out_len<=0){
		cfr->out_len=r->bytes_sent;
	}

	if(cfr->in_len<=0 && cfr->out_len>0){
		cfr->in_len = cfr->out_len;
	}

	if(cfr->in_len < cfr->out_len){
		cfr->out_len=cfr->in_len;
	}

	////?
	if(cfr->out_len > 0){
		if(cfr->in_len/cfr->out_len > 10){
			cfr->in_len=cfr->out_len*2;
		}
	}

	if(cfr->e_time <=0){
		flash_log_printf(FLASHLOG_MARK,R_LOG, r,
				"log_collection time  end:%"APR_TIME_T_FMT"start:%"APR_TIME_T_FMT" "
				,cfr->e_time,cfr->s_time);
		cfr->e_time = apr_time_now();
	}

	if(cfr->e_time<cfr->s_time){
		cfr->e_time=cfr->s_time;
	}

	imq=(apr_time_now()/(apr_time_t)APR_USEC_PER_SEC)%(apr_time_t)(86400);

	seitem.msg_type=MSG_TYPE;

	apr_table_t *headers=r->headers_in;

	memset(&seitem,0,sizeof(flash_msg_item_t));

	seitem.summary_log.count=1;

	pagent = apr_table_get(headers, "User-Agent");

	if(pagent!=NULL){
		if(cfr->user_info.spf_tagent!=NULL){
			apr_cpystrn(seitem.summary_log.content.appAgent,cfr->user_info.spf_tagent,128);
		}else{
			translate_agent(pagent,seitem.summary_log.content.appAgent);
		}
	}else{
#ifdef USE_LOG_SERVER
		apr_cpystrn(seitem.summary_log.content.appAgent,"-",128);
#endif
	}

	prefer = apr_table_get(headers,"Referer");

	if(prefer!=NULL){
		apr_cpystrn(seitem.summary_log.content.refer,prefer,512);
	}

	if(r->connection->remote_ip!=NULL){
		apr_cpystrn(seitem.summary_log.content.sip,r->connection->remote_ip,64);
	}else{
#ifdef USE_LOG_SERVER
		apr_cpystrn(seitem.summary_log.content.sip,"-",64);
#endif
	}

	if(cfr->user_info.spf_appid!=NULL){
		apr_cpystrn(seitem.summary_log.content.appid,cfr->user_info.spf_appid,64);
	}else{
#ifdef USE_LOG_SERVER
		apr_cpystrn(seitem.summary_log.content.appid,"-",64);
#endif
	}

	if(cfr->user_info.spf_pkgid!=NULL){
		apr_cpystrn(seitem.summary_log.content.pkgid,cfr->user_info.spf_pkgid,64);
	}else{
#ifdef USE_LOG_SERVER
		apr_cpystrn(seitem.summary_log.content.pkgid,"-",64);
#endif
	}

	if(cfr->user_info.spf_devid!=NULL){
		apr_cpystrn(seitem.summary_log.content.userid,cfr->user_info.spf_devid,64);
	}else{
#ifdef USE_LOG_SERVER
		apr_cpystrn(seitem.summary_log.content.userid,"-",64);
#endif
	}

	if(cfr->user_info.spf_nettype!=NULL){
		apr_cpystrn(seitem.summary_log.content.nettype,cfr->user_info.spf_nettype,11);
	}

	if(cfr->user_info.spf_platformtype!=NULL){
			apr_cpystrn(seitem.summary_log.content.platformtype,cfr->user_info.spf_platformtype,11);
	}

	if(cfr->user_info.spf_imgype!=NULL){
		apr_cpystrn(seitem.summary_log.content.imgtype,cfr->user_info.spf_imgype,11);
	}

	if(r->content_type!=NULL){
		ptype=apr_pstrdup(r->pool,r->content_type);
		/*plt=strchr(ptype,'/');
		if(plt){
		    *plt='\0';
		}*/
		apr_cpystrn(seitem.summary_log.content.requestType,ptype,64);
	}else{
#ifdef USE_LOG_SERVER
		apr_cpystrn(seitem.summary_log.content.requestType,"-",64);
#endif
	}

	seitem.summary_log.content.accessTime=apr_time_now();

#ifdef USE_LOG_SERVER
	//flashsdk
	if((cfr->user_info.spf_pkgid!=NULL) && (cfr->user_info.spf_appid!=NULL)){
		apr_snprintf(seitem.summary_log.content.url,512,"http://%s.%s.%s.%s.fastsdk.com/%s%s",
				(cfr->user_info.spf_appid!=NULL)?cfr->user_info.spf_appid:"_",
				(cfr->user_info.spf_pkgid!=NULL)?cfr->user_info.spf_pkgid:"_",
				(cfr->user_info.spf_nettype!=NULL)?cfr->user_info.spf_nettype:"0",
				(cfr->user_info.spf_platformtype!=NULL)?cfr->user_info.spf_platformtype:"0",
				(r->hostname!=NULL)?r->hostname:"",
				(r->parsed_uri.path!=NULL)?r->parsed_uri.path:"");
		//flashnoproxy
	}else if(r->unparsed_uri!=NULL){
		apr_cpystrn(seitem.summary_log.content.url,r->unparsed_uri,512);
	}else{
		apr_cpystrn(seitem.summary_log.content.url,"-",512);
	}
#else
	if(r->hostname!=NULL)
		apr_cpystrn(seitem.summary_log.content.url,r->hostname,512);
#endif

	if(r->method!=NULL){
		apr_cpystrn(seitem.summary_log.content.requestMethod,r->method,10);
	}else{
#ifdef USE_LOG_SERVER
		apr_cpystrn(seitem.summary_log.content.requestMethod,"-",10);
#endif
	}

	if(cfr->user_info.proxy.pport!=0){
		pdip=inet_ntoa(cfr->user_info.proxy.paddr);
		if(pdip!=NULL){
#ifdef USE_LOG_SERVER
			//flashuser
			apr_snprintf(seitem.summary_log.content.url,512,"http://%s.%d.fastsdk.com/%s%s",pdip,
					cfr->user_info.proxy.pport,(r->hostname!=NULL)?r->hostname:"",
					(r->parsed_uri.path!=NULL)?r->parsed_uri.path:"");
#else
			apr_cpystrn(seitem.summary_log.content.dip,pdip,64);
			seitem.summary_log.content.dport=cfr->user_info.proxy.pport;
#endif
		}
	}

	seitem.summary_log.orilength=cfr->in_len;
	seitem.summary_log.ziplength=cfr->out_len;

	seitem.summary_log.usec =(cfr->e_time-cfr->s_time)/1000;// 豪秒

/////////////////////初始化完成


#ifndef USE_LOG_SERVER
#ifndef USER_LOG_SERVER_TEST
	if(cf->log_sumfd!=NULL){
		rv=message_send((int)imq,&seitem,sizeof(flash_msg_item_t));
		flash_log_printf(FLASHLOG_MARK,R_LOG, r,
				"log_collection send agent:%s  inlen:%"APR_SIZE_T_FMT" outlen:%"APR_SIZE_T_FMT
				" url:%s  imq:%"APR_TIME_T_FMT" rv:%d",
				pagent,cfr->in_len,cfr->out_len,r->unparsed_uri,imq,rv);
	}
#endif
#endif

	if(cf->log_allfd!=NULL){
		memset(buffer,0,ONCE_LOG_LONG);//APR_TIME_T_FMT

#ifndef USE_LOG_SERVER
		memset(stime, 0, APR_CTIME_LEN);
		ap_explode_recent_localtime(&xt, seitem.summary_log.content.accessTime);
		apr_strftime(stime, &rvt, APR_CTIME_LEN,"%Y-%m-%d %H:%M:%S",&xt);
#else
		ftimestamp=seitem.summary_log.content.accessTime/1000.0;
		ftimestamp=ftimestamp/1000.0;
#endif

		if(cfr->user_info.server_mode==MODE_SDK){
#ifdef USE_LOG_SERVER
		if(cfr->user_info.spf_pkgid!=NULL){
				if (cfr->user_info.auth_mode == MODE_LANXUN) {
					memset(buffer,0,ONCE_LOG_LONG);
				}else{
					apr_snprintf(buffer, ONCE_LOG_LONG,
							"%.3f\t%d\t%s\t%s\t%"APR_SIZE_T_FMT
							"\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%"APR_SIZE_T_FMT"\t%s\n",
							ftimestamp, seitem.summary_log.usec,
							seitem.summary_log.content.sip, "TCP_HIT/200",
							seitem.summary_log.ziplength,
							seitem.summary_log.content.requestMethod,
							seitem.summary_log.content.url, "-", "-",
							seitem.summary_log.content.requestType,
							(r->protocol != NULL )?r->protocol:"-",
							"-",
							"-",
							seitem.summary_log.orilength,
							seitem.summary_log.content.userid
							);
				}
		}
#else
			apr_snprintf(buffer, ONCE_LOG_LONG, "DATA:%s,%d,%s,%s,%"
					APR_SIZE_T_FMT",%"APR_SIZE_T_FMT
					",%s,%s,%s,%s,%s,%s\n",
					stime,
					seitem.summary_log.usec,
					seitem.summary_log.content.sip,
					seitem.summary_log.content.userid,
					seitem.summary_log.orilength,
					seitem.summary_log.ziplength,
					seitem.summary_log.content.requestMethod,
					seitem.summary_log.content.url,
					seitem.summary_log.content.nettype,
					seitem.summary_log.content.pkgid,
					seitem.summary_log.content.appid,
					seitem.summary_log.content.imgtype);
#endif

		}else if(cfr->user_info.server_mode==MODE_DLIBRARY){
			apr_snprintf(buffer, ONCE_LOG_LONG, "DATA:%s,%s,%"
					APR_SIZE_T_FMT",%"APR_SIZE_T_FMT",%d,%d\n",
					stime,
					seitem.summary_log.content.url,
					seitem.summary_log.orilength,
					seitem.summary_log.ziplength,
					seitem.summary_log.count,
					seitem.summary_log.usec);

		}else if(cfr->user_info.server_mode==MODE_NOPROXY){
#ifdef USE_LOG_SERVER
			apr_snprintf(buffer, ONCE_LOG_LONG, "%.3f\t%d\t%s\t%s\t%"APR_SIZE_T_FMT
					"\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%"APR_SIZE_T_FMT"\t%s\n",
					ftimestamp,
					seitem.summary_log.usec,
					seitem.summary_log.content.sip,
					"TCP_HIT/200",
					seitem.summary_log.ziplength,
					seitem.summary_log.content.requestMethod,
					seitem.summary_log.content.url,
					"-",
					"-",
					seitem.summary_log.content.requestType,
					(r->protocol!=NULL)?r->protocol:"-",
					"-",
					"-",
					seitem.summary_log.orilength,
					"-"
					);
#else
			apr_snprintf(buffer, ONCE_LOG_LONG, "DATA:%s,%s,%"
					APR_SIZE_T_FMT",%"APR_SIZE_T_FMT",%d,%d\n",
					stime,
					//seitem.summary_log.content.url,
					(r->unparsed_uri!=NULL)?r->unparsed_uri:" ",
					seitem.summary_log.orilength,
					seitem.summary_log.ziplength,
					seitem.summary_log.count,
					seitem.summary_log.usec);
#endif
		}else{
#ifdef USE_LOG_SERVER
			apr_snprintf(buffer, ONCE_LOG_LONG, "%.3f\t%d\t%s\t%s\t%"APR_SIZE_T_FMT
					"\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%"APR_SIZE_T_FMT"\t%s\n",
					ftimestamp,
					seitem.summary_log.usec,
					seitem.summary_log.content.sip,
					"TCP_HIT/200",
					seitem.summary_log.ziplength,
					seitem.summary_log.content.requestMethod,
					seitem.summary_log.content.url,
					"-",
					"-",
					seitem.summary_log.content.requestType,
					(r->protocol!=NULL)?r->protocol:"-",
					seitem.summary_log.content.userid,
					"-",
					seitem.summary_log.orilength,
					"-"
					);
#else
#ifdef USER_LOG_SERVER_TEST

			apr_snprintf(buffer, ONCE_LOG_LONG, "DATA:%s,%s,%d"
					",%"APR_SIZE_T_FMT",%"APR_SIZE_T_FMT",%s,%s,%s,%s\n",
					stime,
					seitem.summary_log.content.dip,
					seitem.summary_log.content.dport,
					seitem.summary_log.orilength,
					seitem.summary_log.ziplength,
					seitem.summary_log.content.requestMethod,
					seitem.summary_log.content.requestType,
					seitem.summary_log.content.appAgent,
					(r->unparsed_uri!=NULL)?r->unparsed_uri:" ");
#else
			apr_snprintf(buffer, ONCE_LOG_LONG, "DATA:%s,%d,%s,%d,%s,%d,"
					"%s,%"APR_SIZE_T_FMT",%"APR_SIZE_T_FMT",%s,%s\n",
					stime,
					seitem.summary_log.usec,
					seitem.summary_log.content.sip,
					seitem.summary_log.count,
					seitem.summary_log.content.dip,
					seitem.summary_log.content.dport,
					seitem.summary_log.content.appAgent,
					seitem.summary_log.orilength,
					seitem.summary_log.ziplength,
					//seitem.summary_log.content.url,
					(r->unparsed_uri!=NULL)?r->unparsed_uri:" ",
					seitem.summary_log.content.userid);
#endif
#endif
		}

		buflen=strlen(buffer);
		if(buflen>0){
			rv = apr_file_write(cf->log_allfd, buffer, &buflen);
		}
	}

	return OK;
}

static apr_status_t open_log_file(apr_pool_t *plog,server_rec *s,apr_file_t ** log_fd,char *path)
{
	const char *fname = ap_server_root_relative(plog, path);
	apr_status_t rv;
	int xfer_flags = (APR_WRITE | APR_APPEND | APR_CREATE | APR_LARGEFILE);
	apr_fileperms_t xfer_perms = APR_OS_DEFAULT;

	if (!fname) {
		ap_log_error(APLOG_MARK, APLOG_ERR, APR_EBADPATH, s,
			             "invalid flash log path %s.", path);
		return DECLINED;
	}

	rv = apr_file_open(log_fd, fname, xfer_flags, xfer_perms, plog);
	if (rv != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
			             "could not open flash log file %s.", path);
		*log_fd=NULL;
		return DECLINED;
	}

	return OK;
}

static apr_status_t log_init(apr_pool_t *plog,server_rec *s,flash_conf_t *cf)
{
	if(cf->spf_logsum_path!=NULL){
		open_log_file(plog,s,&(cf->log_sumfd),(char *)cf->spf_logsum_path);
	}

	if(cf->spf_logall_path!=NULL){
		open_log_file(plog,s,&(cf->log_allfd),(char*)cf->spf_logall_path);
	}

	return OK;
}

/**
 *从消息队列中获取日志信息 并写入文件
 */
static apr_status_t log_process(apr_pool_t *plog,server_rec *s,flash_conf_t *cf)
{
	apr_hash_t *log_hash;
	apr_time_t startcamp=0;
	int timecamped=0;
	apr_size_t buflen;
	apr_size_t rvt;
	apr_status_t rv;
	flash_summary_log_t *pitem;
	flash_msg_item_t rcvitem;
	apr_hash_index_t *hi;
	apr_pool_t *hash_pool;
	char buffer[ONCE_LOG_LONG];
	const char *key=NULL;
	char stime[APR_CTIME_LEN];
	apr_time_exp_t xt;
	int iudlen=0;
	int imq=1;

	if(cf->log_sumfd==NULL)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
					     "error:: flash log file fd  in null");
		return DECLINED;
	}

	if (apr_pool_create(&hash_pool, plog) != APR_SUCCESS){
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
					     "error:: create  flash log pool failed");
	    return DECLINED;
	}

	log_hash = apr_hash_make(hash_pool);

	 while(1){

		if(0==startcamp){
			 startcamp=apr_time_now();
		}
		imq++;
		imq=imq%MSG_MAX_NUMS;
		timecamped =0;

		while ((message_recv(imq, &rcvitem, sizeof(flash_msg_item_t)) > 0) && (timecamped <120)){

			flash_log_printf(FLASHLOG_MARK,S_LOG, s,"start:: recv log info %d  ",imq);
			memset(stime, 0, APR_CTIME_LEN);
			ap_explode_recent_localtime(&xt, rcvitem.summary_log.content.accessTime);
			apr_strftime(stime, &rvt, APR_CTIME_LEN,"%Y-%m-%d %H:%M:%S",&xt);

			//make hask key
			if(cf->server_mode==MODE_SDK){
				key=apr_pstrcat(hash_pool,rcvitem.summary_log.content.userid,
						rcvitem.summary_log.content.appid,rcvitem.summary_log.content.nettype,NULL);
			}else if(cf->server_mode==MODE_DLIBRARY){
				key=apr_pstrcat(hash_pool,rcvitem.summary_log.content.url,NULL);
			}else if(cf->server_mode==MODE_NOPROXY){
				key=apr_pstrcat(hash_pool,rcvitem.summary_log.content.url,NULL);
			}else{
				iudlen=strlen(rcvitem.summary_log.content.userid);
				if(iudlen>0){
					key=apr_pstrcat(hash_pool,rcvitem.summary_log.content.userid,
							rcvitem.summary_log.content.appAgent,NULL);
				}else{
					key=apr_itoa(hash_pool, rcvitem.summary_log.content.dport);
					key=apr_pstrcat(hash_pool,rcvitem.summary_log.content.dip,key,
							rcvitem.summary_log.content.appAgent,NULL);
				}
			}

			flash_log_printf(FLASHLOG_MARK,S_LOG, s,
							"message_recvlogis %s %s  %"APR_SIZE_T_FMT"  %"APR_SIZE_T_FMT
							"  %s the key is %s",stime,
							rcvitem.summary_log.content.appAgent,
							rcvitem.summary_log.orilength,
							rcvitem.summary_log.ziplength,
							rcvitem.summary_log.content.url,
							key);

			pitem=apr_hash_get(log_hash,key,APR_HASH_KEY_STRING);
			if(pitem!=NULL){
				if((pitem->orilength < (UINT_MAX - rcvitem.summary_log.orilength))
						&& (pitem->ziplength < (UINT_MAX - rcvitem.summary_log.ziplength))){
					pitem->orilength+=rcvitem.summary_log.orilength;
					pitem->ziplength+=rcvitem.summary_log.ziplength;
				}
				pitem->usec+=rcvitem.summary_log.usec;
				memcpy(&pitem->content,&rcvitem.summary_log.content,sizeof(flash_once_log_t));
				pitem->count++;
			}else{
				pitem=apr_pcalloc(hash_pool,sizeof(flash_summary_log_t));
				memcpy(pitem,&(rcvitem.summary_log),sizeof(flash_summary_log_t));
				apr_hash_set(log_hash,key, APR_HASH_KEY_STRING, pitem);
			}
			timecamped=(int)((apr_time_now()-startcamp)/1000000);
		}

		//获取间隔时间妙
		timecamped=(int)((apr_time_now()-startcamp)/1000000);
		//超过一定时间写日志文件
		if(timecamped>=120){
			startcamp=0;
			if(apr_hash_count(log_hash)>0){
				if(cf->log_sumfd!=NULL){
					for (hi = apr_hash_first(hash_pool, log_hash); hi; hi = apr_hash_next(hi)) {
						apr_hash_this(hi, (const void**)&key, NULL, (void**)&pitem);
						memset(buffer,0,ONCE_LOG_LONG);//APR_TIME_T_FMT
						if(cf->server_mode==MODE_SDK){
							ap_explode_recent_localtime(&xt, pitem->content.accessTime);
							apr_strftime(stime, &rvt, APR_CTIME_LEN,"%Y-%m-%d %H:%M:%S",&xt);
							apr_snprintf(buffer, ONCE_LOG_LONG, "DATA:%s,%d,%s,%s,%"
									APR_SIZE_T_FMT", %"APR_SIZE_T_FMT
								",%s,%s,%s,%s,%s,%s\n",
								stime,
								pitem->usec,
								pitem->content.sip,
								pitem->content.userid,
								pitem->orilength,
								pitem->ziplength,
								pitem->content.requestMethod,
								pitem->content.url,
								pitem->content.nettype,
								pitem->content.pkgid,
								pitem->content.appid,
								pitem->content.imgtype);
						}else if(cf->server_mode==MODE_DLIBRARY){
							ap_explode_recent_localtime(&xt, pitem->content.accessTime);
							apr_strftime(stime, &rvt, APR_CTIME_LEN,"%Y-%m-%d %H:%M:%S",&xt);
							apr_snprintf(buffer, ONCE_LOG_LONG, "DATA:%s,%s,%"
								APR_SIZE_T_FMT",%"APR_SIZE_T_FMT",%d,%d\n",
								stime,
								pitem->content.url,
								pitem->orilength,
								pitem->ziplength,
								pitem->count,
								pitem->usec);
						}else if(cf->server_mode==MODE_NOPROXY){
							ap_explode_recent_localtime(&xt, pitem->content.accessTime);
							apr_strftime(stime, &rvt, APR_CTIME_LEN,"%Y-%m-%d %H:%M:%S",&xt);
							apr_snprintf(buffer, ONCE_LOG_LONG, "DATA:%s,%s,%"
								APR_SIZE_T_FMT",%"APR_SIZE_T_FMT",%d,%d\n",
								stime,
								pitem->content.url,
								pitem->orilength,
								pitem->ziplength,
								pitem->count,
								pitem->usec);
						}else{
							ap_explode_recent_localtime(&xt, pitem->content.accessTime);
							apr_strftime(stime, &rvt, APR_CTIME_LEN,"%Y-%m-%d %H:%M:%S",&xt);
							apr_snprintf(buffer, ONCE_LOG_LONG, "DATA:%s,%d,%s,%d,%s,%d,"
								"%s,%"APR_SIZE_T_FMT",%"APR_SIZE_T_FMT",%s,%s\n",
								stime,
								pitem->usec,
								pitem->content.sip,
								pitem->count,
								pitem->content.dip,
								pitem->content.dport,
								pitem->content.appAgent,
								pitem->orilength,
								pitem->ziplength,
								pitem->content.url,
								pitem->content.userid
								);
							/*
							ap_explode_recent_localtime(&xt, pitem->content.accessTime);
							apr_strftime(stime, &rvt, APR_CTIME_LEN,"%Y%m%d",&xt);
							apr_snprintf(buffer, ONCE_LOG_LONG,"insert into accessLog%s (accessTime,usec,ip,cport,dip,"
									"dport,appAgent,orilength,ziplength,url,username) VALUES("
									"FROM_UNIXTIME(%"APR_TIME_T_FMT"),%d,'%s',%d,'%s',%d,'%s',%"APR_SIZE_T_FMT
									",%"APR_SIZE_T_FMT",'%s','%s');\n",
									stime,
									pitem->content.accessTime/1000000,
									pitem->usec,
									pitem->content.sip,
									pitem->count,
									pitem->content.dip,
									pitem->content.dport,
									pitem->content.appAgent,
									pitem->orilength,
									pitem->ziplength,
									pitem->content.url,
									pitem->content.userid);
									*/
						}
						flash_log_printf(FLASHLOG_MARK,S_LOG, s,"log_process =%s ",buffer);

						buflen=strlen(buffer);
						if(buflen >0 )
							rv = apr_file_write(cf->log_sumfd, buffer, &buflen);
					}
				}
				//清理内存
				apr_hash_clear(log_hash);
				apr_pool_clear(hash_pool);
				log_hash = apr_hash_make(hash_pool);
			}
		}
		if(timecamped <120 ){//没有消息不能空转
			apr_sleep(50000);//0.05 seconds
		}
	}
	return OK;
}

/**
 *关闭日志进程
 */
APR_DECLARE_NONSTD(apr_status_t) log_proc_close(void *data)
{
	int ret=0;
	//apr_proc_t *proc=(apr_proc_t *)data;

	flash_conf_t *cf=(flash_conf_t*)data;

	if(cf->log_proc.pid>0)
		kill(cf->log_proc.pid,SIGTERM);

	if(cf->log_sumfd!=NULL)
		apr_file_close(cf->log_sumfd);

	if(cf->log_allfd!=NULL)
		apr_file_close(cf->log_allfd);

	//remove msgseq
		ret=message_remove();

    return APR_SUCCESS;
}

/**
 *启动日志进程
 */
apr_status_t start_log_proc(apr_pool_t *plog,server_rec *s,flash_conf_t *cf)
{
	apr_status_t rv;
	int exitcode;
	apr_exit_why_e exitwhy;

	//初始化log
	log_init(plog,s,cf);

#ifndef USE_LOG_SERVER
	if(cf->log_sumfd!=NULL){
		rv = apr_proc_fork(&(cf->log_proc), plog);
		switch (rv) {
			case APR_INPARENT:
				rv = apr_proc_wait(&(cf->log_proc), &exitcode, &exitwhy, APR_NOWAIT);//APR_NOWAIT APR_WAIT
//		     	flash_log_printf(FLASHLOG_MARK,S_LOG, s,"in parent process");
				apr_pool_cleanup_register(plog, cf, log_proc_close, log_proc_close);
				return OK;

			case APR_INCHILD:
				log_process(plog,s,cf);
				//退出此进程
				exit(1);
				break;
			default:
				return OK;
		}
	}
#endif

	return OK;
}

/**
 * 解析url 中自定义的参数
 */
apr_status_t parse_param_head(apr_table_t *params,  char *key, char *value)
{
	apr_status_t rv = OK;
	//url 解码
	ap_unescape_url(value);

	if(strcasecmp(key,"u")==0){
		apr_table_setn(params,"url", value);
	}else if(strcasecmp(key,"c")==0){
        apr_table_setn(params, "Cookie", value);
	}else if(strcasecmp(key,"h")==0){
		char *tok, *val;
		while (value && *value) {
			if ((val = ap_strchr(value, '='))){
				*val++ = '\0';
			    if ((tok = ap_strchr(val, 0x02)))
			    	*tok++ = '\0';
			     apr_table_setn(params, value, val);
			     value = tok;
			 }else{
				 return HTTP_BAD_REQUEST;
			 }
		}
	}else{
		apr_table_setn(params, key, value);
	}

	return rv;
}

/**
 * 合并url 转换中参数的信息到htt头中
 */
int merge_param_head(void *rec, const char *key, const char *value)
{
	request_rec *r=(request_rec *)rec;
	apr_table_t *headers=r->headers_in;
	if(strcmp(key,"url")!=0){
		apr_table_set(headers, key, value);
	}else{
		r->unparsed_uri = apr_pstrdup(r->pool, value);
		apr_uri_parse(r->pool, r->unparsed_uri, &r->parsed_uri);
		r->hostname = r->parsed_uri.hostname;
		if(r->hostname){
			apr_table_set(r->headers_in,"Host",r->hostname);
		}
        r->args = r->parsed_uri.query;
        r->uri = r->parsed_uri.path ? r->parsed_uri.path
                 : apr_pstrdup(r->pool, "/");

		if(!r->proxyreq){
			r->proxyreq = PROXYREQ_PROXY;
			r->handler = "proxy-server";
		}
		r->uri=apr_pstrdup(r->pool,r->unparsed_uri);
		r->filename=apr_pstrcat(r->pool, "proxy:",r->uri , NULL);
		r->the_request=apr_pstrcat(r->pool, r->method," ",r->unparsed_uri, NULL);
	}
	flash_log_printf(FLASHLOG_MARK,S_LOG,r->server,"[urlparam]%s:%s",key,value);
	return 1;
}


 /**
 * url代理检测
 * URL地址：http://代理服务器IP:端口号/w~.v?u=xxx&c=xxx&h=xxx
 **其中，如果URL路径后有/w~.v，表示通过URL方式走代理服务器，非普通的HTTP请求。
 **参数：
 **u=原始url
 **c=cookies，格式：name=value;name=value;name=value…
 **h=headers，格式：name=value0x02 name=value0x02 name=value…
 **其中，0x02是分隔符（16进制，为了避免转义字符）。
 */
apr_status_t flashapp_url_proxy(request_rec *r,flash_conf_req_t *cfr,flash_conf_t *cf)
{
	apr_status_t rv=DECLINED;
	apr_table_t *params = apr_table_make(r->pool, 10);
	if(r->unparsed_uri){
		if(strstr(r->unparsed_uri,"/w~.v")!=NULL){
			rv=APR_SUCCESS;
		}
	}
	if (r->args && rv==APR_SUCCESS) {
		flash_log_printf(FLASHLOG_MARK,R_LOG,r,"flashapp_url_proxy:%s | %s",r->unparsed_uri,r->filename);
		char *args = apr_pstrdup(r->pool, r->args);
	    char *tok, *val ,*cval;
	    while (args && *args) {
	    	if ((val = ap_strchr(args, '='))) {
	    		*val++ = '\0';
	            	if ((tok = ap_strchr(val, '&')))
	                    *tok++ = '\0';
	            	cval=apr_pstrdup(r->pool,val);
	            	rv=parse_param_head(params,args,cval);
	            	if(rv!=OK){
	            		flash_log_printf(FLASHLOG_MARK,R_LOG,r,"flashapp_url_proxy error :%s | %s",args,val);
	            		return rv;
	            	}
	                args = tok;
	         }else
	                return HTTP_BAD_REQUEST;
	    }
	    //合并http 头
	    apr_table_do(merge_param_head, (void*)r, params, NULL);
	    cfr->user_info.access_urlproxy =1;
	}
	return rv;
}


/**
 *获得 url缩略的源 的信息
 *先从 memcache  没有在从mysql 里获得
 */
static apr_status_t get_shorturl(request_rec *r,flash_conf_req_t *cfr,char **url)
{
	apr_status_t rv=DECLINED;
	apr_size_t len=0;
	char *data=NULL;
	char key[128]={0};
	if(r->unparsed_uri!=NULL && cfr->user_info.spf_appid!=NULL){
		snprintf(key, 128, "%s_%s_shorturl",cfr->user_info.spf_appid,cfr->user_info.spf_urlshort);
		rv=memcache_get(r->pool,cfr->spf_memc,key,&data,&len);
		flash_log_printf(FLASHLOG_MARK,S_LOG, r->server,"get shorturl from mem %s ",key);
		if(rv==APR_SUCCESS){
			*url=apr_pstrdup(r->pool,data);
			flash_log_printf(FLASHLOG_MARK,S_LOG ,r->server,"shorturl find in mem "
				"url: %s",*url);
		}else{
#ifdef USE_MYSQL
			if(cfr->spf_mysqllock){
				apr_thread_mutex_lock(cfr->spf_mysqllock);
			}
			if((cfr->spf_mysql!=NULL) && ((mysql_ping(cfr->spf_mysql) == APR_SUCCESS))){
				flash_log_printf(FLASHLOG_MARK,S_LOG, r->server,"get shorturl from mysql");
				rv=query_mysql_shorturl(r->pool,cfr->spf_mysql,cfr->user_info.spf_appid,
						cfr->user_info.spf_urlshort,url,r->server);
			}
			if(cfr->spf_mysqllock){
				apr_thread_mutex_unlock(cfr->spf_mysqllock);
			}
#else
			rv=query_url_shorturl(p,cfr->user_info.spf_appid,r->unparsed_uri,url,r->server);
#endif
			if (rv == APR_SUCCESS) {
				if (*url != NULL ) {
					memcache_put(cfr->spf_memc, key, *url, strlen(*url), 900); //15分钟
					flash_log_printf(FLASHLOG_MARK, S_LOG, r->server,
							"find shorturl form mysql "
									"url: %s", *url);
				} else {
					rv = DECLINED;
				}
			}
		}
	}
	return rv;
}

/**
 *  url缩略
 * {~}是URL占位符。如果是固定的URL，就不需要占位符了。
 *缩略后占位符的内容，通过header传递
 *header名称为s，内容是占位符的内容
 *如果有多个占位符的话，用0x02分割。
 *Header： s=value1%02value2
*/
apr_status_t flashapp_url_forshort(request_rec *r,flash_conf_req_t *cfr,flash_conf_t *cf)
{
	apr_status_t rv=DECLINED;
	char *purl=NULL;
	char *newurl=NULL;
	char *pvalue=NULL;
	char *spliturl,*splitvalue;
	char *tokurl,*tokvalue;
	char sc[2];

	sc[0]=0x02;
	sc[1]=0;
	if(cfr->user_info.server_mode==MODE_SDK){
		if(!check_sdk_header(r,cfr)){
			parse_sdk_agent(r,cfr);
		}
		if(cfr->user_info.spf_urlshortparam != NULL){
			rv=get_shorturl(r,cfr,&purl);
			flash_log_printf(FLASHLOG_MARK,S_LOG, r->server,"flashapp_url_forshort: "
					"url: %s %s  %s  %s  %d",cfr->user_info.spf_urlshortparam,cfr->user_info.spf_urlshort,
					cfr->user_info.spf_appid,purl,rv);
			if(rv==APR_SUCCESS){
				pvalue=apr_pstrdup(r->pool,cfr->user_info.spf_urlshortparam);
				ap_unescape_url(pvalue);
				ap_unescape_url(purl);
				spliturl = apr_strtok(purl, "{~}", &tokurl);
				splitvalue = apr_strtok(pvalue,sc, &tokvalue);
				while (spliturl) {
					//结束的时候如果参数多,不往后添加
					if(tokurl && strlen(tokurl)<=0){
						splitvalue=NULL;
					}
					newurl=apr_pstrcat(r->pool,(newurl!=NULL)?newurl:"",
							spliturl,(splitvalue!=NULL)?splitvalue:"",NULL);
					flash_log_printf(FLASHLOG_MARK,S_LOG, r->server,"flashapp_url_forshort"
							"url: %s |%s|  %s",spliturl,tokurl,splitvalue);
					spliturl = apr_strtok(NULL,"{~}", &tokurl);

					if(splitvalue){
						splitvalue = apr_strtok(NULL,sc, &tokvalue);
					}
				}
			}
		}

		if(newurl){
			flash_log_printf(FLASHLOG_MARK,S_LOG, r->server,"flashapp_url_forshort: "
													"newurl: %s",newurl);
			r->unparsed_uri = apr_pstrdup(r->pool, newurl);
			apr_uri_parse(r->pool, r->unparsed_uri, &r->parsed_uri);
			r->hostname = r->parsed_uri.hostname;
			apr_table_set(r->headers_in,"Host",r->hostname);
		    r->args = r->parsed_uri.query;
		    r->uri = r->parsed_uri.path ? r->parsed_uri.path
		            : apr_pstrdup(r->pool, "/");

			if(!r->proxyreq){
				r->proxyreq = PROXYREQ_PROXY;
				r->handler = "proxy-server";
			}
			r->uri=apr_pstrdup(r->pool,r->unparsed_uri);
			r->filename=apr_pstrcat(r->pool, "proxy:",r->uri , NULL);
			r->the_request=apr_pstrcat(r->pool, r->method," ",r->unparsed_uri, NULL);
		}
	}
	return rv;
}

/**
 * 输出压缩检测，有些数据类型会有问题
 *
 */
apr_status_t flashapp_check_nodeflate(request_rec *r)
{
	apr_status_t rv=DECLINED;
	const char *val=NULL;
	// mod_deflate 不压缩 环境变量设置
	if (apr_table_get(r->subprocess_env, "no-gzip")==NULL){
		val=apr_table_get(r->headers_in,"User-Agent");
		if(val!=NULL){
			if (strncasecmp( val, "Mozilla", 7) == 0|| strncasecmp(val, "Opera", 5) == 0){
				return rv;
			}
		}

		val=apr_table_get(r->headers_in, "Range");//range 不能压缩

		if( (r->content_type == NULL)||//一下类型压缩处理
				(val !=NULL)||
				( strstr(r->content_type, "text/") == NULL &&
				  strstr(r->content_type, "application/shockwave") ==NULL &&
				  strstr(r->content_type, "application/msword") ==NULL &&
				  strstr(r->content_type, "application/msexcel") ==NULL &&
				  strstr(r->content_type, "application/mspowerpoint") ==NULL &&
				  strstr(r->content_type, "application/rtf") ==NULL &&
				  strstr(r->content_type, "application/postscript") ==NULL &&
				  strstr(r->content_type, "application/java") ==NULL &&
				  strstr(r->content_type, "application/javascript") ==NULL &&
				  strstr(r->content_type, "application/staroffice") ==NULL &&
				  strstr(r->content_type, "application/vnd") ==NULL &&
				  strstr(r->content_type, "application/futuresplash") ==NULL &&
				  strstr(r->content_type, "application/asp") ==NULL &&
				  strstr(r->content_type, "application/class") ==NULL &&
				  strstr(r->content_type, "application/font") ==NULL &&
				  strstr(r->content_type, "application/truetype-font") ==NULL &&
				  strstr(r->content_type, "application/php") ==NULL &&
				  strstr(r->content_type, "application/cgi") ==NULL &&
				  strstr(r->content_type, "application/executable") ==NULL &&
				  strstr(r->content_type, "application/shellscript") ==NULL &&
				  strstr(r->content_type, "application/perl") ==NULL &&
				  strstr(r->content_type, "application/python") ==NULL &&
				  strstr(r->content_type, "application/awk") ==NULL &&
				  strstr(r->content_type, "application/dvi") ==NULL &&
				  strstr(r->content_type, "application/css") ==NULL &&
				  strstr(r->content_type, "application/xml") ==NULL &&
				  strstr(r->content_type, "application/pdf") ==NULL &&
				  strstr(r->content_type, "application/tar") ==NULL &&
				  strstr(r->content_type, "application/json") ==NULL &&
				  strstr(r->content_type, "application/xml-dtd") ==NULL &&
				  strstr(r->content_type, "application/iso9660-image") ==NULL &&
				  strstr(r->content_type, "image/svg+xml") ==NULL
				)){
					apr_table_set(r->subprocess_env, "no-gzip","2");
					//flash_log_printf_headers(r,r->subprocess_env,"subprocess_env");
					rv=OK;
				}
	}
	return rv;
}

/**
 * 执行自定义命令
 *flashapp-command?cmd=refresh&
 */
apr_status_t flashapp_command_run(request_rec *r,flash_conf_t *cf)
{
	apr_status_t rv=DECLINED;
    apr_procattr_t *procattr=NULL;
    apr_proc_t *procnew=NULL;
	apr_table_t *params = apr_table_make(r->pool, 10);
	const char* cmd =NULL;
	char **argv =NULL;
	char *runstr =NULL;
	if (r->args) {
		flash_log_printf(FLASHLOG_MARK,R_LOG,r,"flashapp_command_run:%s | %s",r->unparsed_uri,r->args);
		char *args = apr_pstrdup(r->pool, r->args);
	    char *tok, *val ,*cval;
	    while (args && *args) {
	    	if ((val = ap_strchr(args, '='))) {
	    		*val++ = '\0';
	            	if ((tok = ap_strchr(val, '&')))
	                    *tok++ = '\0';
	            	cval=apr_pstrdup(r->pool,val);
	            	apr_table_setn(params, args, val);
	                args = tok;
	         }else{
	        	 break;
	         }
	    }
	    cmd=apr_table_get(params,"cmd");
	    flash_log_printf(FLASHLOG_MARK,R_LOG,r,"flashapp_command_run cmd:%s ",cmd);
	    if(cmd!=NULL){
	    	if(strcasecmp(cmd,"flaushcache")==0){
	    		if(cf->spf_pagespeed_cache){
	    			runstr=apr_pstrcat(r->pool,"touch ",cf->spf_pagespeed_cache,"cache.flush" ,NULL);
	    			procnew = (apr_proc_t *)apr_pcalloc(r->pool, sizeof(*procnew));
	    			 if (APR_SUCCESS == apr_procattr_create(&procattr, r->pool)
	    			     && APR_SUCCESS ==apr_procattr_io_set(procattr, APR_FULL_BLOCK,
	    			                                                  APR_FULL_BLOCK,APR_NO_PIPE)
	    			     && APR_SUCCESS == apr_procattr_cmdtype_set(procattr, APR_SHELLCMD)
	    			     && APR_SUCCESS == apr_procattr_error_check_set(procattr, 1)){
	    				 apr_tokenize_to_argv(runstr, &argv, r->pool);
	    				 rv = apr_proc_create(procnew, argv[0], (const char **)argv, NULL,
	    				                              procattr, r->pool);
	    				 if (rv == APR_SUCCESS) {
	    				     apr_pool_note_subprocess(r->pool, procnew, APR_KILL_AFTER_TIMEOUT);
	    				 }
	    			 }
	    		}
	    	}else if(strcasecmp(cmd,"help")==0){

	    	}
	    }
	    ap_set_content_type(r, "text/html; charset=ISO-8859-1");
	    ap_rputs(DOCTYPE_HTML_3_2
	                    "<html><head>\n<title>Flashapp Server</title>\n</head><body>\n",
	                    r);
	    ap_rputs("<h1>Run Command </h1>\n", r);
	    ap_rputs("<dl>", r);
	    ap_rvputs(r, "<dt>Current Time: ",
	             ap_ht_time(r->pool, apr_time_now(), "%A, %d-%b-%Y %H:%M:%S %Z", 0),"</dt>\n", NULL);
	    if(rv==APR_SUCCESS){
	    	ap_rvputs(r, "<dt>Cmd: ",cmd," run Success </dt>\n", NULL);
	    }else{
	    	ap_rvputs(r, "<dt>Cmd: ",cmd," run Failure </dt>\n", NULL);
	    }
	    ap_rputs("</dl>", r);
	    ap_rputs("</body></html>\n", r);
	}
	return rv;
}

