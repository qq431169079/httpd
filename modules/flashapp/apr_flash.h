/* 
**  apr_flashapp.h -- Apache  flashapp
*/ 

#include "util_time.h"
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_connection.h"
#include "http_request.h"
#include "http_core.h"
#include "http_log.h"
#include "apr_time.h"
#include "apr_lib.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "apr_strmatch.h"
#include "apr_errno.h"
#include "apr_memcache2.h"
#include "apr_hashcluster.h"
#include "ap_mpm.h"
#include "apr_md5.h"
#include "apr_xml.h"
#include "apr_flash_http.h"
#include <json/json.h>
#include <arpa/inet.h>
#include <mysql/mysql.h>
#include <sys/msg.h>
#include <ctype.h>



//#define HAS_CHECK_LICENCE //检测licence
#define USE_LOG_SERVER //使用logserver 模式，不合并log
//#define NO_LOG  //不打印调试信息
//#define USER_LOG_SERVER_TEST  //测试服务器日志
#define USE_MYSQL //使用mysql

#pragma pack (1)
//////////////////////////////////////
//**X-Flashapp-Proxy flashapp 代理转发头
//**X-Flashapp-Pass  flashapp 直接通过不处理
//**X-Flashapp-Connect flashapp 允许所有connetc 端口通过
//////////////////////////////////

typedef struct proxyinfo
{
	struct in_addr paddr;
	in_port_t pport;
	//apr_port_t pport;
} proxyinfo;

//服务模式  sdk  飞速  数字图书馆 cdn
typedef enum _SERVER_MODE_ {MODE_SDK,MODE_USER,MODE_DLIBRARY,MODE_NOPROXY} SERVER_MODE;
//sdk验证  原始 最新  兰讯  无数据库
typedef enum _AUTH_MODE_ {MODE_OLD,MODE_NORMAL,MODE_LANXUN,MODE_NOSQL} AUTH_MODE;

//全局配置
typedef struct flash_conf_t {
    int enable_all;//开启所有
    int enable_ipport;//开启 ipport 过滤器哦哦
    int enable_pagespeed;//开启控制 pagespeed 过滤
    int enable_logs;//开启日志
    int enable_usersetting;//开启用户设置
    int enable_otherproxy;// 开启到 其他代理 的设置
    int enable_nosetproxy;// 客户端不用设置代理， 直接设置dns 或者 host 指向
    int enable_serviceinvalid;// 服务器是否无效
    int enable_forwardedfor;//打开透明代理
    int enable_allconnect;//允许所有端口的connect 经过
    int enable_ziproxyaftersquid;//ziproxy 在squid 之后
    int enable_usedforpc;//允许pc 访问 直接穿透ziproxy js 优化取消等 防止页面访问出问题 去掉本地验证
    int enable_trashcheck;//允许检测垃圾访问
    int max_visitperuser;//最大访问次数

    SERVER_MODE server_mode;//服务器运行模式 sdk  user
    const char * spf_logsum_path;// sum日志文件路径
    const char * spf_logall_path;// all日志文件路径
    const char * spf_ip2domain_path;// domain ip文件路径
    const char * spf_memcache_slist;//memcache 服务器配置
    const char * spf_mysql_slist;//mysql 服务器配置
    const char * spf_lice_url;// lic文件路径
    const char * spf_head_content;// 头插入内容
    const char * spf_video_proxy;//视频代理地址
    const char * spf_audio_proxy;//音频代理地址
    const char * spf_squid_proxy;//squid代理地址
    const char * spf_ziproxy_proxy;//ziproxy代理地址
    const char * spf_pagespeed_cache;//pagespeed cache path
    apr_file_t *log_sumfd;//sum日志文件fd
    apr_file_t *log_allfd;//all日志文件fd
    apr_proc_t log_proc;//日志进程信息spf_ip2domain_path

    apr_memcache2_t *spf_memc;//memcache
    apr_hashcluster_t *spf_squid;//squid cluster
    apr_thread_mutex_t *spf_mysqllock;//同意个进程不通线程共享同一个连接 锁
#ifdef USE_MYSQL
    MYSQL *spf_mysql;//mysql
#endif
    apr_hash_t *spf_domain_hash;//domain rewrite  哈希表包含哈希表，第一个哈希表 是个分组 第二个哈希表  映射域名  原始域名
    apr_hash_t *spf_cache_hash;//static file cache  哈希表包含哈希表， 第一个哈希表按域名 第二个哈希表  uri  本地路径

    apr_hash_t *spf_json_hash;//domain json  哈希表 里哈希表， 按域名 ip 分组
    apr_array_header_t *spf_squid_domainarry;//squid  转发domain
    apr_array_header_t *spf_squid_typearry;//squid  转发type
    apr_array_header_t *spf_forbid_connect_port;//connect 禁用的端口
    apr_array_header_t *spf_forbid_agentarry;// 禁用的agent 列表
    apr_array_header_t *spf_forbid_urlarry;// 禁用url 列表

} flash_conf_t;

//每个连接的配置
typedef struct flash_conf_conn_t{
	 int enable_check;//是否做过ip port 协议检测
	 int enable_request;//是否是请求
	 proxyinfo proxy;
}flash_conf_conn_t;

typedef enum flash_image_type_t {
	NO_CHECK,
	NO_IMG,
	IMG_PNG,
	IMG_GIF,
	IMG_JPEG
}flash_image_type_t;

typedef struct image_cache_t{
flash_image_type_t type_image;//图片类型
apr_int64_t all_len;//总长度
apr_int64_t now_len;//写入长度
char * spf_all_cache;//图片缓存
}image_cache_t;

typedef enum _IMAGE_QUALITY_ {IQ_LOW =30,IQ_MID =50,IQ_HIGH =80,
	IQ_HIGH_1 = 85, IQ_HIGH_2 = 90, IQ_HIGH_3 = 95, IQ_NO=100} IMAGE_QUALITY;

typedef struct user_info_t{
	int enable_settoken;//sdk 是否写入新的token
	int enable_used;//是否使用服务
	int check_result;//sdk 用户检测结果
	int enable_passthrough;//直接通过不加载任何 不产生日志 不往后分发
	int access_urlproxy;//是否通过url 代理访问
	int sdk_stepmode;//sdk 的验证过程
	int enable_pagespeed;//是否启动pagespeed
	char *spf_appid;//sdk app id
	char *spf_pkgid;//sdk pkg id
	char *spf_devid;// dev id
	char *spf_tagent;// process agent
	char *spf_nettype;// 网络类型1-Wifi 2-2G
	char *spf_platformtype;// 平台类型1-Android 2-IOS
	char *spf_imgype;// 图片处理类型日志使用
	char *spf_codetoken;// 获取的code 或者 token

	char *spf_urlshort;// url缩略的url key
	char *spf_urlshortparam;//url缩略的参数
	//
	char *spf_timestamp;// 获取的时间戳
	char *spf_devname;// 获取的设备名字
	char *spf_osversion;// 获取的平台版本
	char *spf_mccnc;// 获取的国家，运营商编码
	char *spf_channel;// 获取的预留

	IMAGE_QUALITY image_quality; //图片质量等级 pagespeed 使用
	proxyinfo proxy;//端口信息
	SERVER_MODE server_mode;
	AUTH_MODE   auth_mode;

}user_info_t;

//每个请求的配置
typedef struct flash_conf_req_t{
	 apr_size_t in_len;//原始长度 头获取的
	 apr_size_t in_lenadd;//原始长度累加
	 apr_size_t out_len;//目前长度
	 apr_time_t s_time;//开始时间
	 apr_time_t e_time;//结束时间
	 apr_memcache2_t *spf_memc;
	 apr_hashcluster_t *spf_squid;
	 apr_thread_mutex_t *spf_mysqllock;//同意个进程不通线程共享同一个连接 锁
#ifdef USE_MYSQL
	 MYSQL *spf_mysql;
#endif
	 apr_hash_t *spf_domain_hash;//当前域名分组的  域名映射 hash 表
	 apr_hash_t *spf_cache_hash;//当前域名分组的 静态缓存 hash 表  uri  对应本地 path
	 apr_hash_t *spf_json_hash;//domain json  哈希表 里哈希表， 按域名 ip 分组
	 user_info_t user_info;//用户信息
	 image_cache_t image_c;//图片信息
}flash_conf_req_t;

//squid host 列表
typedef struct flash_squid_host_t{
	char *spf_host;
}flash_squid_host_t;

//squid type 列表
typedef struct flash_squid_type_t{
	char *spf_type;
}flash_squid_type_t;

//connect port 列表
typedef struct flash_connect_port_t{
	int icport;
}flash_connect_port_t;

//forbid agent 列表
typedef struct flash_forbid_agent_t{
	char *spf_agent;
}flash_forbid_agent_t;

//forbid url 列表
typedef struct flash_forbid_url_t{
	char *spf_url;
}flash_forbid_url_t;

//appinfo
typedef struct flash_appinfo_t{
	char sf_appkey[33];
	char sf_pkgid[33];
	char sf_pkgname[200];
}flash_appinfo_t;

//日志 消息对类结构
typedef struct flash_once_log_t{
	apr_time_t accessTime;//时间
	char userid[65];//用户id
	char appid[65];//应用id
	char pkgid[65];//包id
	char requestMethod[11];//请求方法
	char appAgent[129];//agent
	char url[513];//请求url
	char refer[513];//
	char dip[65];//服务器ip
	char sip[65];//客户ip
	char requestType[65];//请求类型
	char nettype[11];//网络类型 3g  2g  wifi
	char platformtype[11];//平台类型   android  ios
	char imgtype[11];//图片压缩 的参数
	int dport;//分配端口
}flash_once_log_t;

typedef struct flash_summary_log_t{
		int usec;//时间
		int count;//次数
		apr_size_t orilength;//原始长度
		apr_size_t ziplength;//压缩后长度
		flash_once_log_t content;//数据详细内容
}flash_summary_log_t;

#define ONCE_LOG_LONG 4096

typedef struct flash_msg_item_t{
	long msg_type;
	flash_summary_log_t summary_log;
} flash_msg_item_t;

#pragma pack()
//日志
#define FLASHLOG_MARK	APLOG_MARK,APLOG_DEBUG,0
typedef enum _LOG_TYPE_ {S_LOG,C_LOG,R_LOG,P_LOG} LOG_TYPE;

void flash_log_printf(const char *file, int line, int level,
        apr_status_t status,LOG_TYPE itype,const void * vtype ,const char *fmt, ...)
			    __attribute__((format(printf,7,8)));

void flash_log_printf_headers(request_rec *r, const apr_table_t *headers , const char *pinfo);
apr_status_t get_ipandport(const char *data,apr_size_t len,char **pbdata,flash_conf_conn_t *cfc,conn_rec *c);
apr_status_t add_headers_pagespeed(ap_filter_t *filter);
apr_status_t get_headers_length(request_rec *r,flash_conf_req_t *cfr);
apr_status_t start_log_proc(apr_pool_t *plog,server_rec *s,flash_conf_t *cf);
apr_status_t log_collection(request_rec *r,flash_conf_req_t *cfr,flash_conf_t *cf);
apr_status_t process_authory(request_rec *r,flash_conf_req_t *cfr,flash_conf_t *cf);
apr_status_t process_usersetting(request_rec *r,flash_conf_req_t *cfr);
apr_status_t set_command(request_rec *r,flash_conf_req_t *cfr,apr_status_t flag);
apr_status_t process_content_from_out(ap_filter_t *filter, apr_bucket_brigade *bb);
apr_status_t process_content_from_in(ap_filter_t *filter, apr_bucket_brigade *bb,ap_input_mode_t eMode,apr_read_type_e eBlock,apr_off_t nBytes);
apr_status_t detect_flashapp_cache(request_rec *r,flash_conf_req_t *cfr,flash_conf_t *cf);
apr_status_t set_xflashapp_proxy(request_rec *r,flash_conf_req_t *cfr,flash_conf_t *cf);
apr_status_t set_xonline_host_proxy(request_rec *r);
apr_status_t set_third_party_proxy(request_rec *r);
apr_status_t process_content_video_audio(ap_filter_t *filter, apr_bucket_brigade *bb,flash_conf_t *cf);
apr_status_t process_content_inserthead(ap_filter_t *filter, apr_bucket_brigade *bb,const char *pheadc);
apr_status_t process_content_replacehost(ap_filter_t *filter, apr_bucket_brigade *bb);
APR_DECLARE_NONSTD(apr_status_t) child_proc_close(void *data);
apr_status_t init_json_domain(apr_pool_t *p,flash_conf_t *cf,server_rec *s);
apr_status_t flashapp_url_proxy(request_rec *r,flash_conf_req_t *cfr,flash_conf_t *cf);
apr_status_t flashapp_check_nodeflate(request_rec *r);
apr_status_t process_headers_replacehost(ap_filter_t *filter);
apr_status_t clear_trash_header(request_rec *r,flash_conf_req_t *cfr);



apr_status_t init_mysql(apr_pool_t *p,const char* serverinfo,MYSQL **pmysql);
apr_status_t init_memcache(apr_pool_t *p,const char* hosts,apr_memcache2_t **mc);
apr_status_t init_hashcluster(apr_pool_t *p,const char* hosts,apr_hashcluster_t **hc);
apr_status_t flashapp_command_run(request_rec *r,flash_conf_t *cf);
apr_status_t check_server_license(apr_pool_t *p,flash_conf_t *cf,server_rec *s);
