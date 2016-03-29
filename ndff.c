/*
 * ndff.c
 *
 * Copyright 2002-2006 Damien Miller <djm@mindrot.org> All rights reserved.
 * Copyright (C) 2011-15 - ntop.org
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2014 - Matteo Bogo <matteo.bogo@gmail.com> (JSON support)
 * Copyright (C) 2016 Teppei Fukuda
 * Copyright (C) 2016 DeNA Co., Ltd.
 *
 *    Distributed under The GNU General Public License Version 3. 
 *    (See accompanying file LICENSE or copy at
 *    http://www.gnu.org/licenses/)
 */

#ifdef linux
#define _GNU_SOURCE
#include <sched.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#ifdef WIN32
#include <winsock2.h> /* winsock.h is included automatically */
#include <process.h>
#include <io.h>
#include <getopt.h>
#define getopt getopt____
#else
#include <unistd.h>
#include <netinet/in.h>
#endif
#include <string.h>
#include <stdarg.h>
#include <iconv.h>
#include <search.h>
#include <pcap.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <ctype.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>

#include "config.h"
#include <libndpi/ndpi_api.h>

#ifdef HAVE_LIBMSGPACKC
#include <msgpack.h>
#endif

#ifdef HAVE_LIBJSON_C
#include <json.h>
#endif


/* Timeouts */
#define TCP_TIMEOUT     3600 
#define TCP_RST_TIMEOUT     120
#define TCP_FIN_TIMEOUT     300
#define UDP_TIMEOUT     300
#define ICMP_TIMEOUT        300
#define GENERAL_TIMEOUT     3600
#define MAXIMUM_LIFETIME    (3600*24*7)

#define MAX_NUM_READER_THREADS     16
#define IDLE_SCAN_PERIOD           10 /* msec (use detection_tick_resolution = 1000) */
#define IDLE_SCAN_BUDGET         1024
#define NUM_ROOTS                 512
#define GTP_U_V1_PORT            2152
#define TZSP_PORT               37008
#define MAX_NDPI_FLOWS      200000000

#ifndef ETH_P_IP
#define ETH_P_IP               0x0800 	/* IPv4 */
#endif

#ifndef ETH_P_IPv6
#define ETH_P_IPV6	       0x86dd	/* IPv6 */
#endif

#define SLARP                  0x8035   /* Cisco Slarp */
#define CISCO_D_PROTO          0x2000	/* Cisco Discovery Protocol */

#define VLAN                   0x8100
#define MPLS_UNI               0x8847
#define MPLS_MULTI             0x8848
#define PPPoE                  0x8864
#define SNAP                   0xaa

/* mask for FCF */
#define	WIFI_DATA                        0x2    /* 0000 0010 */
#define FCF_TYPE(fc)     (((fc) >> 2) & 0x3)    /* 0000 0011 = 0x3 */
#define FCF_SUBTYPE(fc)  (((fc) >> 4) & 0xF)    /* 0000 1111 = 0xF */
#define FCF_TO_DS(fc)        ((fc) & 0x0100)
#define FCF_FROM_DS(fc)      ((fc) & 0x0200)

/* mask for Bad FCF presence */
#define BAD_FCS                         0x50    /* 0101 0000 */

/**
 * @brief Set main components necessary to the detection
 */
static void setup_detection(u_int16_t thread_id);
static int setup_socket(u_int16_t thread_id);

/**
 * Client parameters
 */
static char *_pcap_file[MAX_NUM_READER_THREADS]; /**< Ingress pcap file/interafaces */
static FILE *playlist_fp[MAX_NUM_READER_THREADS] = { NULL }; /**< Ingress playlist */
static FILE *results_file = NULL;
static char *results_path = NULL;
static char *_server_addr = NULL; /**< server ip address */
static int _server_port = 24224; /**< server port */
static char *_tag = "ndpi.flow"; /**< tag for fluentd */
static char *_bpf_filter      = NULL; /**< bpf filter  */
static char *_protoFilePath   = NULL; /**< Protocol file path  */
static u_int8_t live_capture = 0;
static u_int8_t undetected_flows_deleted = 0;
/**
 * User preferences
 */
static u_int8_t enable_protocol_guess = 1, verbose = 0, nDPI_traceLevel = 0, json_flag = 0, msgpack_flag = 0, dryrun_flag = 0;
static u_int16_t decode_tunnels = 0;
static u_int8_t shutdown_app = 0, quiet_mode = 0;
static u_int8_t num_threads = 1;
static u_int32_t current_ndpi_memory = 0, max_ndpi_memory = 0;
static char* server;
#ifdef linux
static int core_affinity[MAX_NUM_READER_THREADS];
#endif

static struct timeval pcap_start, pcap_end;

/**
 * Detection parameters
 */
static u_int32_t detection_tick_resolution = 1000;

static u_int32_t num_flows;

struct reader_thread {
    struct ndpi_detection_module_struct *ndpi_struct;
    void *ndpi_flows_root[NUM_ROOTS];
    char _pcap_error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *_pcap_handle;
    u_int64_t last_time;
    u_int64_t last_idle_scan_time;
    u_int32_t idle_scan_idx;
    u_int32_t num_idle_flows;
    pthread_t pthread;
    int _pcap_datalink_type;
    
    struct ndpi_flow *idle_flows[IDLE_SCAN_BUDGET];
};

static struct reader_thread ndpi_thread_info[MAX_NUM_READER_THREADS];

/**
 * @brief ID tracking
 */
typedef struct ndpi_id {
    u_int8_t ip[4];				// Ip address
    struct ndpi_id_struct *ndpi_id;		// nDpi worker structure
} ndpi_id_t;

static u_int32_t size_id_struct = 0;		// ID tracking structure size

// flow tracking
typedef struct ndpi_flow {
    u_int32_t lower_ip;
    u_int32_t upper_ip;
    u_int16_t lower_port;
    u_int16_t upper_port;
    u_int8_t detection_completed, protocol;
    u_int16_t vlan_id;
    struct ndpi_flow_struct *ndpi_flow;
    char lower_name[48], upper_name[48];
    u_int8_t ip_version;
    u_int64_t first_seen;
    u_int64_t last_seen;
    u_int64_t expires_at;
    u_int64_t out_bytes;
    u_int64_t in_bytes;
    u_int32_t out_pkts;
    u_int32_t in_pkts;
    u_int8_t src_to_dst_direction;
    u_int8_t fin_rst_received;
    
    // result only, not used for flow identification
    ndpi_protocol detected_protocol;
    
    char host_server_name[192];
    
    struct {
        char client_certificate[48], server_certificate[48];
    } ssl;
    
    void *src_id, *dst_id;
} ndpi_flow_t;


static u_int32_t size_flow_struct = 0;


static char _sockfd[MAX_NUM_READER_THREADS];

static void help(u_int long_help) {
    printf("ndff -i <file|device> [-s <server>] [-m <json|msgpack>] [-f <filter>]\n"
           "          [-p <port>][-P <protos>][-t <tag>][-q][-d][-D][-h][-T][-v <level>]\n"
           "          [-n <threads>] [-w <file>] \n\n"
           "Usage:\n"
           "  -i <file.pcap|device>     | Specify a pcap file/playlist to read packets from or a device for live capture (comma-separated list)\n"
           "  -m <json|msgpack>         | Specify a protocol to send messages to the server (json or msgpack)\n"
           "  -f <BPF filter>           | Specify a BPF filter for filtering selected traffic\n"
           "  -s <server>               | Specify a server for fluentd (If not, ndff runs in the dry-run mode)\n"
           "  -p <port>                 | Specify a port for fluentd (default: 24224)\n"
           "  -P <file>.protos          | Specify a protocol file (eg. protos.txt)\n"
           "  -n <num threads>          | Number of threads. Default: number of interfaces in -i. Ignored with pcap files.\n"
#ifdef linux
           "  -g <id:id...>             | Thread affinity mask (one core id per thread)\n"
#endif
           "  -d                        | Daemonize (run in background)\n"
           "  -D                        | Disable protocol guess and use only DPI\n"
           "  -q                        | Quiet mode\n"
           "  -t                        | Specify a tag for fluentd (default: ndpi.flow)\n"
           "  -T                        | Dissect GTP/TZSP tunnels\n"
           "  -r                        | Print nDPI version and git revision\n"
           "  -w <path>                 | Write test output on the specified file. This is useful for\n"
           "                            | testing purposes in order to compare results across runs\n"
           "  -h                        | This help\n"
           "  -v <1|2>                  | Verbose 'unknown protocol' packet print. 1=verbose, 2=very verbose\n");
    
    if(long_help) {
        printf("\n\nSupported protocols:\n");
        num_threads = 1;
        setup_detection(0);
        ndpi_dump_protocols(ndpi_thread_info[0].ndpi_struct);
    }
    
    exit(!long_help);
}

/* ***************************************************** */

void output(int priority, const char *format, ... ) {
    va_list arg;

    va_start(arg, format);
    if(!quiet_mode){
        va_list arg2;
        va_copy (arg2, arg);
        vprintf(format, arg2);
        va_end(arg2);
    }
    vsyslog(priority, format, arg);
    va_end(arg);
}

/* ***************************************************** */

static void parse_options(int argc, char **argv) {
    char *__pcap_file = NULL, *bind_mask = NULL;
    int thread_id, opt;
#ifdef linux
    u_int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
#endif
    
    while ((opt = getopt(argc, argv, "dDf:g:i:hp:P:l:s:t:Tv:V:n:rp:m:w:q")) != EOF) {
        switch (opt) {
            case 'd':
                if (daemon(0, 0) != 0) {
                    output(LOG_ERR, "%s\n", "[ERROR] daemonize failed");
                    exit(1);
                }
                break;

            case 'D':
                enable_protocol_guess = 0;
                break;
                
            case 'i':
                _pcap_file[0] = optarg;
                break;
                
            case 'f':
                _bpf_filter = optarg;
                break;
                
            case 'g':
                bind_mask = optarg;
                break;
                
            case 'n':
                num_threads = atoi(optarg);
                break;
                
            case 'p':
                _server_port = atoi(optarg);
                break;
                
            case 'P':
                _protoFilePath = optarg;
                break;
                
            case 's':
                _server_addr = optarg;
                break;
                
            case 't':
                _tag = optarg;
                break;
                
            case 'T':
                decode_tunnels = 1;
                break;
                
            case 'r':
                printf("%s\n- nDPI (%s)\n", PACKAGE_STRING, ndpi_revision());
                exit(0);
                
            case 'v':
                verbose = atoi(optarg);
                break;
                
            case 'V':
                printf("%d\n",atoi(optarg) );
                nDPI_traceLevel  = atoi(optarg);
                break;
                
            case 'h':
                help(1);
                break;

            case 'm':
                if(strcmp(optarg, "json") == 0){
#ifndef HAVE_LIBJSON_C
	                output(LOG_WARNING, "%s\n", "[WARN] this copy of ndff has been compiled without JSON-C: json export disabled");
#else
                        json_flag = 1;
#endif
                }else if(strcmp((char *)optarg, "msgpack") == 0){
#ifndef HAVE_LIBMSGPACKC
	                output(LOG_WARNING, "%s\n", "[WARN] this copy of ndff has been compiled without msgpack-c: msgpack export disabled");
#else
                    msgpack_flag = 1;
#endif
                }else{
                    help(0);
                }
                break;
                
            case 'w':
                results_path = strdup(optarg);
                if((results_file = fopen(results_path, "w")) == NULL) {
                    output(LOG_ERR, "[ERROR] Unable to write in file %s: quitting\n", results_path);
                    return;
                }
                break;
                
            case 'q':
                quiet_mode = 1;
                break;
                
            default:
                help(0);
                break;
        }
    }
    
    // check parameters
    if(_pcap_file[0] == NULL || strcmp(_pcap_file[0], "") == 0) {
        help(0);
    }else if(_server_addr == NULL || strcmp(_server_addr, "") == 0) {
        output(LOG_WARNING, "%s\n", "[WARN] No server is specified. This is dry-run mode.");
        dryrun_flag = 1;
    }else if(!json_flag && !msgpack_flag){
        output(LOG_WARNING, "%s\n", "[WARN] No protocol is specified. This is dry-run mode.");
        dryrun_flag = 1;
    }
    
    if(strchr(_pcap_file[0], ',')) { /* multiple ingress interfaces */
        num_threads = 0; /* setting number of threads = number of interfaces */
        __pcap_file = strtok(_pcap_file[0], ",");
        while (__pcap_file != NULL && num_threads < MAX_NUM_READER_THREADS) {
            _pcap_file[num_threads++] = __pcap_file;
            __pcap_file = strtok(NULL, ",");
        }
    } else {
        if(num_threads > MAX_NUM_READER_THREADS) num_threads = MAX_NUM_READER_THREADS;
        for(thread_id = 1; thread_id < num_threads; thread_id++)
            _pcap_file[thread_id] = _pcap_file[0];
    }
    
#ifdef linux
    for(thread_id = 0; thread_id < num_threads; thread_id++)
        core_affinity[thread_id] = -1;
    
    if(num_cores > 1 && bind_mask != NULL) {
        char *core_id = strtok(bind_mask, ":");
        thread_id = 0;
        while (core_id != NULL && thread_id < num_threads) {
            core_affinity[thread_id++] = atoi(core_id) % num_cores;
            core_id = strtok(NULL, ":");
        }
    }
#endif
}

/* ***************************************************** */

static void debug_printf(u_int32_t protocol, void *id_struct,
                         ndpi_log_level_t log_level,
                         const char *format, ...) {
    va_list va_ap;
#ifndef WIN32
    struct tm result;
#endif
    
    if(log_level <= nDPI_traceLevel) {
        char buf[8192], out_buf[8192];
        char theDate[32];
        const char *extra_msg = "";
        time_t theTime = time(NULL);
        
        va_start (va_ap, format);
        
        if(log_level == NDPI_LOG_ERROR)
            extra_msg = "ERROR: ";
        else if(log_level == NDPI_LOG_TRACE)
            extra_msg = "TRACE: ";
        else
            extra_msg = "DEBUG: ";
        
        memset(buf, 0, sizeof(buf));
        strftime(theDate, 32, "%d/%b/%Y %H:%M:%S", localtime_r(&theTime,&result) );
        vsnprintf(buf, sizeof(buf)-1, format, va_ap);
        
        snprintf(out_buf, sizeof(out_buf), "%s %s%s", theDate, extra_msg, buf);
        printf("%s", out_buf);
        fflush(stdout);
    }
    
    va_end(va_ap);
}

/* ***************************************************** */

static void *malloc_wrapper(size_t size) {
    current_ndpi_memory += size;
    
    if(current_ndpi_memory > max_ndpi_memory)
        max_ndpi_memory = current_ndpi_memory;
    
    return malloc(size);
}

/* ***************************************************** */

static void free_wrapper(void *freeable) {
    free(freeable);
}

/* ***************************************************** */

static char* ipProto2Name(u_short proto_id) {
    static char proto[8];
    
    switch(proto_id) {
        case IPPROTO_TCP:
            return("TCP");
            break;
        case IPPROTO_UDP:
            return("UDP");
            break;
        case IPPROTO_ICMP:
            return("ICMP");
            break;
        case IPPROTO_ICMPV6:
            return("ICMPV6");
            break;
        case 112:
            return("VRRP");
            break;
        case IPPROTO_IGMP:
            return("IGMP");
            break;
    }
    
    snprintf(proto, sizeof(proto), "%u", proto_id);
    return(proto);
}

/* ***************************************************** */

/*
 * A faster replacement for inet_ntoa().
 */
char* intoaV4(unsigned int addr, char* buf, u_short bufLen) {
    char *cp, *retStr;
    uint byte;
    int n;
    
    cp = &buf[bufLen];
    *--cp = '\0';
    
    n = 4;
    do {
        byte = addr & 0xff;
        *--cp = byte % 10 + '0';
        byte /= 10;
        if(byte > 0) {
            *--cp = byte % 10 + '0';
            byte /= 10;
            if(byte > 0)
                *--cp = byte + '0';
        }
        *--cp = '.';
        addr >>= 8;
    } while (--n > 0);
    
    /* Convert the string to lowercase */
    retStr = (char*)(cp+1);
    
    return(retStr);
}

/* ***************************************************** */

static void print_flow(u_int16_t thread_id, struct ndpi_flow *flow) {
    FILE *out = results_file ? results_file : stdout;

    fprintf(out, "\t%u", ++num_flows);

    char *src_name, *dst_name;
    u_int16_t src_port, dst_port;
    if(flow->src_to_dst_direction) {
        src_name = flow->lower_name, dst_name = flow->upper_name;
        src_port = flow->lower_port, dst_port = flow->upper_port;
    } else {
        src_name = flow->upper_name, dst_name = flow->lower_name;
        src_port = flow->upper_port, dst_port = flow->lower_port;
    }

    fprintf(out, "\t%s %s%s%s:%u <-> %s%s%s:%u ",
		    ipProto2Name(flow->protocol),
		    (flow->ip_version == 6) ? "[" : "",
		    src_name, 
		    (flow->ip_version == 6) ? "]" : "",
		    ntohs(src_port),
		    (flow->ip_version == 6) ? "[" : "",
		    dst_name, 
		    (flow->ip_version == 6) ? "]" : "",
		    ntohs(dst_port));

    if(flow->vlan_id > 0) fprintf(out, "[VLAN: %u]", flow->vlan_id);

    if(flow->detected_protocol.master_protocol) {
	    char buf[64];

	    fprintf(out, "[proto: %u.%u/%s]",
			    flow->detected_protocol.master_protocol, flow->detected_protocol.protocol,
			    ndpi_protocol2name(ndpi_thread_info[thread_id].ndpi_struct,
				    flow->detected_protocol, buf, sizeof(buf)));
    } else
	    fprintf(out, "[proto: %u/%s]",
			    flow->detected_protocol.protocol,
			    ndpi_get_proto_name(ndpi_thread_info[thread_id].ndpi_struct, flow->detected_protocol.protocol));

    fprintf(out, "[Up: %u pkts/%llu bytes, Down: %u pkts/%llu bytes]",
		    flow->out_pkts, (long long unsigned int)flow->out_bytes,
		    flow->in_pkts, (long long unsigned int)flow->in_bytes);

    if(flow->host_server_name[0] != '\0') fprintf(out, "[Host: %s]", flow->host_server_name);
    if(flow->ssl.client_certificate[0] != '\0') fprintf(out, "[SSL client: %s]", flow->ssl.client_certificate);
    if(flow->ssl.server_certificate[0] != '\0') fprintf(out, "[SSL server: %s]", flow->ssl.server_certificate);

    fprintf(out, "\n");
}

/* ***************************************************** */

static int isgraph_string(char* c) {
    int i;
    for(i = 0; i < strlen(c); i++){
        if(!isgraph(c[i])){
            return 0;
        }
    }
    return 1;
}

/* ***************************************************** */

static void write_socket(u_int16_t thread_id, char *buf, int length){
    int n, retry_count = 0;
    for(retry_count = 0; retry_count < 3; retry_count++){
        n = write(_sockfd[thread_id], buf, length);
        if(n == length){
            break;
        }
        output(LOG_WARNING, "%s\n", "[WARN] Failed to connect to server - retrying in 5 sec...");
        sleep(5);
        close(_sockfd[thread_id]);
        setup_socket(thread_id);
    }
    if(retry_count >= 3){
        output(LOG_ERR, "%s\n", "[ERROR] Maximum connection retry count has been exceeded");
        exit(1);
    }
}

/* ***************************************************** */

#ifdef HAVE_LIBMSGPACKC
static int get_map_size(struct ndpi_flow *flow) {
    int size = 13;
    if(flow->detected_protocol.master_protocol) size++;
    if(isgraph_string(flow->host_server_name)) size++;
    if((flow->ssl.client_certificate[0] != '\0') || (flow->ssl.server_certificate[0] != '\0')) size++;
    return size;
}

/* ***************************************************** */

static void msgpack_pack_string(msgpack_packer pk, char *string) {
    msgpack_pack_str(&pk, strlen(string));
    msgpack_pack_str_body(&pk, string, strlen(string));
}

/* ***************************************************** */

static void msgpack_pack_kv(msgpack_packer pk, char *key, char *value) {
    msgpack_pack_string(pk, key);
    msgpack_pack_string(pk, value);
}

/* ***************************************************** */

static void send_msgpack(u_int16_t thread_id, struct ndpi_flow *flow) {
    msgpack_sbuffer sbuf;
    msgpack_sbuffer_init(&sbuf);

    msgpack_packer pk;
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);

    char *src_name, *dst_name;
    u_int16_t src_port, dst_port;

    if(flow->src_to_dst_direction) {
        src_name = flow->lower_name, dst_name = flow->upper_name;
        src_port = flow->lower_port, dst_port = flow->upper_port;
    } else {
        src_name = flow->upper_name, dst_name = flow->lower_name;
        src_port = flow->upper_port, dst_port = flow->lower_port;
    }

    msgpack_pack_array(&pk, 3);
    
    msgpack_pack_string(pk, _tag);
    msgpack_pack_uint64(&pk, flow->first_seen / detection_tick_resolution);
    msgpack_pack_map(&pk, get_map_size(flow));

    msgpack_pack_kv(pk, "protocol", ipProto2Name(flow->protocol));

    msgpack_pack_kv(pk, "src_addr", src_name);

    msgpack_pack_string(pk, "src_port");
    msgpack_pack_uint16(&pk, ntohs(src_port));

    msgpack_pack_kv(pk, "dst_addr", dst_name);

    msgpack_pack_string(pk, "dst_port");
    msgpack_pack_uint16(&pk, ntohs(dst_port));

    if(flow->detected_protocol.master_protocol){
        msgpack_pack_string(pk, "master_protocol");
        msgpack_pack_int(&pk, flow->detected_protocol.master_protocol);
    }

    msgpack_pack_string(pk, "detected_protocol");
    msgpack_pack_int(&pk, flow->detected_protocol.protocol);
    
    if(flow->detected_protocol.master_protocol) {
        char tmp[256];
        
        snprintf(tmp, sizeof(tmp), "%s.%s",
                 ndpi_get_proto_name(ndpi_thread_info[thread_id].ndpi_struct, flow->detected_protocol.master_protocol),
                 ndpi_get_proto_name(ndpi_thread_info[thread_id].ndpi_struct, flow->detected_protocol.protocol));
        
        msgpack_pack_kv(pk,"protocol_name", tmp);
    } else
	msgpack_pack_kv(pk,"protocol_name", ndpi_get_proto_name(ndpi_thread_info[thread_id].ndpi_struct,
				    flow->detected_protocol.protocol));
    
    msgpack_pack_string(pk, "out_pkts");
    msgpack_pack_int(&pk, flow->out_pkts);
    msgpack_pack_string(pk, "out_bytes");
    msgpack_pack_int(&pk, flow->out_bytes);
    msgpack_pack_string(pk, "in_pkts");
    msgpack_pack_int(&pk, flow->in_pkts);
    msgpack_pack_string(pk, "in_bytes");
    msgpack_pack_int(&pk, flow->in_bytes);
    msgpack_pack_string(pk, "first_switched");
    msgpack_pack_int64(&pk, flow->first_seen / detection_tick_resolution);
    msgpack_pack_string(pk, "last_switched");
    msgpack_pack_int64(&pk, flow->last_seen / detection_tick_resolution);
    
    if(isgraph_string(flow->host_server_name)){
        msgpack_pack_kv(pk, "server_name", flow->host_server_name);
    }
    
    if((flow->ssl.client_certificate[0] != '\0') || (flow->ssl.server_certificate[0] != '\0')) {
        msgpack_pack_string(pk, "ssl");
        if((flow->ssl.client_certificate[0] != '\0') && (flow->ssl.server_certificate[0] != '\0')) {
            msgpack_pack_map(&pk, 2);
        }else{
            msgpack_pack_map(&pk, 1);
        }
        if(flow->ssl.client_certificate[0] != '\0')
            msgpack_pack_kv(pk, "client", flow->ssl.client_certificate);
        
        if(flow->ssl.server_certificate[0] != '\0')
            msgpack_pack_kv(pk, "server", flow->ssl.server_certificate);
    }
    
    write_socket(thread_id, sbuf.data, sbuf.size);
    msgpack_sbuffer_destroy(&sbuf);
}
#endif

/* ***************************************************** */

#ifdef HAVE_LIBJSON_C
static void send_json(u_int16_t thread_id, struct ndpi_flow *flow) {
    json_object *jObj;
    
    jObj = json_object_new_object();
    json_object *jarray = json_object_new_array();

    char *src_name, *dst_name;
    u_int16_t src_port, dst_port;

    if(flow->src_to_dst_direction) {
        src_name = flow->lower_name, dst_name = flow->upper_name;
        src_port = flow->lower_port, dst_port = flow->upper_port;
    } else {
        src_name = flow->upper_name, dst_name = flow->lower_name;
        src_port = flow->upper_port, dst_port = flow->lower_port;
    }
    
    json_object_object_add(jObj,"protocol",json_object_new_string(ipProto2Name(flow->protocol)));
    json_object_object_add(jObj,"src_addr",json_object_new_string(src_name));
    json_object_object_add(jObj,"src_port",json_object_new_int(ntohs(src_port)));
    json_object_object_add(jObj,"dst_addr",json_object_new_string(dst_name));
    json_object_object_add(jObj,"dst_port",json_object_new_int(ntohs(dst_port)));

    if(flow->detected_protocol.master_protocol)
        json_object_object_add(jObj,"master_protocol",json_object_new_int(flow->detected_protocol.master_protocol));
    
    json_object_object_add(jObj,"detected_protocol",json_object_new_int(flow->detected_protocol.protocol));
    
    if(flow->detected_protocol.master_protocol) {
        char tmp[256];
        
        snprintf(tmp, sizeof(tmp), "%s.%s",
                 ndpi_get_proto_name(ndpi_thread_info[thread_id].ndpi_struct, flow->detected_protocol.master_protocol),
                 ndpi_get_proto_name(ndpi_thread_info[thread_id].ndpi_struct, flow->detected_protocol.protocol));
        
        json_object_object_add(jObj,"protocol_name",
                               json_object_new_string(tmp));
    } else
        json_object_object_add(jObj,"protocol_name",
                               json_object_new_string(ndpi_get_proto_name(ndpi_thread_info[thread_id].ndpi_struct,
                                                                          flow->detected_protocol.protocol)));
    
    json_object_object_add(jObj,"out_pkts",json_object_new_int(flow->out_pkts));
    json_object_object_add(jObj,"out_bytes",json_object_new_int(flow->out_bytes));
    json_object_object_add(jObj,"in_pkts",json_object_new_int(flow->in_pkts));
    json_object_object_add(jObj,"in_bytes",json_object_new_int(flow->in_bytes));
    json_object_object_add(jObj,"first_switched",  json_object_new_int64((signed)(flow->first_seen / detection_tick_resolution)));
    json_object_object_add(jObj,"last_switched",  json_object_new_int64((signed)(flow->first_seen / detection_tick_resolution)));
    
    if(isgraph_string(flow->host_server_name)){
        json_object_object_add(jObj,"server_name",json_object_new_string(flow->host_server_name));
    }
    
    if((flow->ssl.client_certificate[0] != '\0') || (flow->ssl.server_certificate[0] != '\0')) {
        json_object *sjObj = json_object_new_object();
        
        if(flow->ssl.client_certificate[0] != '\0')
            json_object_object_add(sjObj, "client", json_object_new_string(flow->ssl.client_certificate));
        
        if(flow->ssl.server_certificate[0] != '\0')
            json_object_object_add(sjObj, "server", json_object_new_string(flow->ssl.server_certificate));
        
        json_object_object_add(jObj, "ssl", sjObj);
    }
    
    json_object_array_add(jarray, json_object_new_string(_tag));
    json_object_array_add(jarray, json_object_new_int64((signed)(flow->first_seen / detection_tick_resolution)));
    json_object_array_add(jarray, jObj);
    
    char* body = (char *)json_object_to_json_string(jarray);
    write_socket(thread_id, body, strlen(body));

    json_object_put(jarray);
}
#endif

/* ***************************************************** */

static void send_flow(u_int16_t thread_id, struct ndpi_flow *flow) {
    if(json_flag){
#ifdef HAVE_LIBJSON_C
        send_json(thread_id, flow);
#endif
    }else if(msgpack_flag){
#ifdef HAVE_LIBMSGPACKC
        send_msgpack(thread_id, flow);
#endif
    }
}


/* ***************************************************** */

static void free_ndpi_flow(struct ndpi_flow *flow) {
    if(flow->ndpi_flow) { ndpi_free_flow(flow->ndpi_flow); flow->ndpi_flow = NULL; }
    if(flow->src_id)    { ndpi_free(flow->src_id); flow->src_id = NULL; }
    if(flow->dst_id)    { ndpi_free(flow->dst_id); flow->dst_id = NULL; }
    
}

/* ***************************************************** */

static void ndpi_flow_freer(void *node) {
    struct ndpi_flow *flow = (struct ndpi_flow*)node;
    
    free_ndpi_flow(flow);
    ndpi_free(flow);
}

/* ***************************************************** */

static void node_print_unknown_proto_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
    struct ndpi_flow *flow = *(struct ndpi_flow**)node;
    u_int16_t thread_id = *((u_int16_t*)user_data);
    
    if(flow->detected_protocol.protocol != NDPI_PROTOCOL_UNKNOWN) return;
    
    if((which == ndpi_preorder) || (which == ndpi_leaf)) /* Avoid walking the same node multiple times */
        print_flow(thread_id, flow);
}

/* ***************************************************** */

static void node_print_known_proto_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
    struct ndpi_flow *flow = *(struct ndpi_flow**)node;
    u_int16_t thread_id = *((u_int16_t*)user_data);
    
    if(flow->detected_protocol.protocol == NDPI_PROTOCOL_UNKNOWN) return;
    
    if((which == ndpi_preorder) || (which == ndpi_leaf)) /* Avoid walking the same node multiple times */
        print_flow(thread_id, flow);
}

/* ***************************************************** */

static u_int16_t node_guess_undetected_protocol(u_int16_t thread_id, struct ndpi_flow *flow) {
    flow->detected_protocol = ndpi_guess_undetected_protocol(ndpi_thread_info[thread_id].ndpi_struct,
                                                             flow->protocol,
                                                             ntohl(flow->lower_ip),
                                                             ntohs(flow->lower_port),
                                                             ntohl(flow->upper_ip),
                                                             ntohs(flow->upper_port));
    
    return(flow->detected_protocol.protocol);
}

/* ***************************************************** */

static void node_proto_guess_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
    struct ndpi_flow *flow = *(struct ndpi_flow **) node;
    u_int16_t thread_id = *((u_int16_t *) user_data);
    
    if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
        if(enable_protocol_guess) {
            if(flow->detected_protocol.protocol == NDPI_PROTOCOL_UNKNOWN) {
                node_guess_undetected_protocol(thread_id, flow);
            }
        }
        
    }
}

/* ***************************************************** */

static void node_idle_scan_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
    struct ndpi_flow *flow = *(struct ndpi_flow **) node;
    u_int16_t thread_id = *((u_int16_t *) user_data);
    
    if(ndpi_thread_info[thread_id].num_idle_flows == IDLE_SCAN_BUDGET) /* TODO optimise with a budget-based walk */
        return;
    
    if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
        if(flow->expires_at < ndpi_thread_info[thread_id].last_time) {
            /* update stats */
            node_proto_guess_walker(node, which, depth, user_data);
            
            if((flow->detected_protocol.protocol == NDPI_PROTOCOL_UNKNOWN) && !undetected_flows_deleted)
                undetected_flows_deleted = 1;

            if(verbose > 1)  print_flow(thread_id, flow);
            if(!dryrun_flag) send_flow(thread_id, flow);
            
            free_ndpi_flow(flow);
            
            /* adding to a queue (we can't delete it from the tree inline ) */
            ndpi_thread_info[thread_id].idle_flows[ndpi_thread_info[thread_id].num_idle_flows++] = flow;
        }
    }
}


/* ***************************************************** */

static void node_expire_all_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
    struct ndpi_flow *flow = *(struct ndpi_flow **) node;
    u_int16_t thread_id = *((u_int16_t *) user_data);
    
    if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
        node_proto_guess_walker(node, which, depth, user_data);

        if(verbose > 1)  print_flow(thread_id, flow);
        if(!dryrun_flag) send_flow(thread_id, flow);

        free_ndpi_flow(flow);
    }
}


/* ***************************************************** */

static int node_cmp(const void *a, const void *b) {
    struct ndpi_flow *fa = (struct ndpi_flow*)a;
    struct ndpi_flow *fb = (struct ndpi_flow*)b;
    
    if(fa->vlan_id   < fb->vlan_id  )   return(-1); else { if(fa->vlan_id   > fb->vlan_id  )   return(1); }
    if(fa->lower_ip   < fb->lower_ip  ) return(-1); else { if(fa->lower_ip   > fb->lower_ip  ) return(1); }
    if(fa->lower_port < fb->lower_port) return(-1); else { if(fa->lower_port > fb->lower_port) return(1); }
    if(fa->upper_ip   < fb->upper_ip  ) return(-1); else { if(fa->upper_ip   > fb->upper_ip  ) return(1); }
    if(fa->upper_port < fb->upper_port) return(-1); else { if(fa->upper_port > fb->upper_port) return(1); }
    if(fa->protocol   < fb->protocol  ) return(-1); else { if(fa->protocol   > fb->protocol  ) return(1); }
    
    return(0);
}

/* ***************************************************** */

static void remove_idle_flows(u_int16_t thread_id){
    /* remove idle flows (unfortunately we cannot do this inline) */
    while (ndpi_thread_info[thread_id].num_idle_flows > 0) {
        /* search and delete the idle flow from the "ndpi_flow_root" (see struct reader thread) - here flows are the node of a b-tree */
        ndpi_tdelete(ndpi_thread_info[thread_id].idle_flows[--ndpi_thread_info[thread_id].num_idle_flows], &ndpi_thread_info[thread_id].ndpi_flows_root[ndpi_thread_info[thread_id].idle_scan_idx], node_cmp);

        /* free the memory associated to idle flow in "idle_flows" - (see struct reader thread)*/
        free_ndpi_flow(ndpi_thread_info[thread_id].idle_flows[ndpi_thread_info[thread_id].num_idle_flows]);
        ndpi_free(ndpi_thread_info[thread_id].idle_flows[ndpi_thread_info[thread_id].num_idle_flows]);
    }
}

/* ***************************************************** */

static struct ndpi_flow *get_ndpi_flow(u_int16_t thread_id,
                                       const u_int8_t version,
                                       u_int16_t vlan_id,
                                       const struct ndpi_iphdr *iph,
                                       const struct ndpi_ipv6hdr *iph6,
                                       u_int16_t ip_offset,
                                       u_int16_t ipsize,
                                       u_int16_t l4_packet_len,
                                       struct ndpi_tcphdr **tcph,
                                       struct ndpi_udphdr **udph,
                                       u_int16_t *sport, u_int16_t *dport,
                                       struct ndpi_id_struct **src,
                                       struct ndpi_id_struct **dst,
                                       u_int8_t *proto,
                                       u_int8_t **payload,
                                       u_int16_t *payload_len,
                                       u_int8_t *src_to_dst_direction) {
    u_int32_t idx, l4_offset;
    u_int32_t lower_ip;
    u_int32_t upper_ip;
    u_int16_t lower_port;
    u_int16_t upper_port;
    struct ndpi_flow flow;
    void *ret;
    u_int8_t *l3, *l4;
    
    /*
     Note: to keep things simple
     we handle IPv6 a-la-IPv4.
     */
    if(version == 4) {
        if(ipsize < 20)
            return NULL;
        
        if((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len)
           || (iph->frag_off & htons(0x1FFF)) != 0)
            return NULL;
        
        l4_offset = iph->ihl * 4;
        l3 = (u_int8_t*)iph;
    } else {
        l4_offset = sizeof(struct ndpi_ipv6hdr);
        l3 = (u_int8_t*)iph6;
    }
    
    if(iph->saddr < iph->daddr) {
        lower_ip = iph->saddr;
        upper_ip = iph->daddr;
        *src_to_dst_direction = 1;
    } else {
        lower_ip = iph->daddr;
        upper_ip = iph->saddr;
        *src_to_dst_direction = 0;
    }
    
    *proto = iph->protocol;
    l4 = ((u_int8_t *) l3 + l4_offset);
    
    if(iph->protocol == 6 && l4_packet_len >= 20) {
        u_int tcp_len;
        
        // tcp
        *tcph = (struct ndpi_tcphdr *)l4;
        *sport = ntohs((*tcph)->source), *dport = ntohs((*tcph)->dest);
        
        if(iph->saddr < iph->daddr) {
            lower_port = (*tcph)->source, upper_port = (*tcph)->dest;
        } else {
            lower_port = (*tcph)->dest;
            upper_port = (*tcph)->source;
            
            if(iph->saddr == iph->daddr) {
                if(lower_port > upper_port) {
                    u_int16_t p = lower_port;
                    
                    lower_port = upper_port;
                    upper_port = p;
                }
            }
        }
        
        tcp_len = ndpi_min(4*(*tcph)->doff, l4_packet_len);
        *payload = &l4[tcp_len];
        *payload_len = ndpi_max(0, l4_packet_len-4*(*tcph)->doff);
    } else if(iph->protocol == 17 && l4_packet_len >= 8) {
        // udp
        *udph = (struct ndpi_udphdr *)l4;
        *sport = ntohs((*udph)->source), *dport = ntohs((*udph)->dest);    
        *payload = &l4[sizeof(struct ndpi_udphdr)];
        *payload_len = ndpi_max(0, l4_packet_len-sizeof(struct ndpi_udphdr));
        
        if(iph->saddr < iph->daddr) {
            lower_port = (*udph)->source, upper_port = (*udph)->dest;
        } else {
            lower_port = (*udph)->dest, upper_port = (*udph)->source;
            
            
            if(iph->saddr == iph->daddr) {
                if(lower_port > upper_port) {
                    u_int16_t p = lower_port;
                    
                    lower_port = upper_port;
                    upper_port = p;
                }
            }
        }
        
        *sport = ntohs(lower_port), *dport = ntohs(upper_port);
    } else {
        // non tcp/udp protocols
        lower_port = 0;
        upper_port = 0;
    }
    
    flow.protocol = iph->protocol, flow.vlan_id = vlan_id;
    flow.lower_ip = lower_ip, flow.upper_ip = upper_ip;
    flow.lower_port = lower_port, flow.upper_port = upper_port;
    
    idx = (vlan_id + lower_ip + upper_ip + iph->protocol + lower_port + upper_port) % NUM_ROOTS;
    ret = ndpi_tfind(&flow, &ndpi_thread_info[thread_id].ndpi_flows_root[idx], node_cmp);
    
    if(ret == NULL) {
        struct ndpi_flow *newflow = (struct ndpi_flow*)malloc(sizeof(struct ndpi_flow));

        if(newflow == NULL) {
            output(LOG_ERR, "[ERROR] %s(1): not enough memory\n", __FUNCTION__);
            return(NULL);
        }

        memset(newflow, 0, sizeof(struct ndpi_flow));
        newflow->protocol = iph->protocol, newflow->vlan_id = vlan_id;
        newflow->lower_ip = lower_ip, newflow->upper_ip = upper_ip;
        newflow->lower_port = lower_port, newflow->upper_port = upper_port;
        newflow->ip_version = version;
        newflow->src_to_dst_direction = *src_to_dst_direction;

        if(version == 4) {
            inet_ntop(AF_INET, &lower_ip, newflow->lower_name, sizeof(newflow->lower_name));
            inet_ntop(AF_INET, &upper_ip, newflow->upper_name, sizeof(newflow->upper_name));
        } else {
            inet_ntop(AF_INET6, &iph6->ip6_src, newflow->lower_name, sizeof(newflow->lower_name));
            inet_ntop(AF_INET6, &iph6->ip6_dst, newflow->upper_name, sizeof(newflow->upper_name));
        }

        if((newflow->ndpi_flow = malloc_wrapper(size_flow_struct)) == NULL) {
            output(LOG_ERR, "[ERROR] %s(2): not enough memory\n", __FUNCTION__);
            free(newflow);
            return(NULL);
        } else
            memset(newflow->ndpi_flow, 0, size_flow_struct);

        if((newflow->src_id = malloc_wrapper(size_id_struct)) == NULL) {
            output(LOG_ERR, "[ERROR] %s(3): not enough memory\n", __FUNCTION__);
            free(newflow);
            return(NULL);
        } else
            memset(newflow->src_id, 0, size_id_struct);

        if((newflow->dst_id = malloc_wrapper(size_id_struct)) == NULL) {
            output(LOG_ERR, "[ERROR] %s(4): not enough memory\n", __FUNCTION__);
            free(newflow);
                return(NULL);
            } else
                memset(newflow->dst_id, 0, size_id_struct);
            
            ndpi_tsearch(newflow, &ndpi_thread_info[thread_id].ndpi_flows_root[idx], node_cmp); /* Add */
            
            *src = newflow->src_id, *dst = newflow->dst_id;
            
            return newflow;
    } else {
        struct ndpi_flow *flow = *(struct ndpi_flow**)ret;
        
        if(flow->lower_ip == lower_ip && flow->upper_ip == upper_ip
           && flow->lower_port == lower_port && flow->upper_port == upper_port)
            *src = flow->src_id, *dst = flow->dst_id;
        else
            *src = flow->dst_id, *dst = flow->src_id;

        return flow;
    }
}

/* ***************************************************** */

static struct ndpi_flow *get_ndpi_flow6(u_int16_t thread_id,
                                        u_int16_t vlan_id,
                                        const struct ndpi_ipv6hdr *iph6,
                                        u_int16_t ip_offset,
                                        struct ndpi_tcphdr **tcph,
                                        struct ndpi_udphdr **udph,
                                        u_int16_t *sport, u_int16_t *dport,
                                        struct ndpi_id_struct **src,
                                        struct ndpi_id_struct **dst,
                                        u_int8_t *proto,
                                        u_int8_t **payload,
                                        u_int16_t *payload_len,
                                        u_int8_t *src_to_dst_direction) {
    struct ndpi_iphdr iph;
    
    memset(&iph, 0, sizeof(iph));
    iph.version = 4;
    iph.saddr = iph6->ip6_src.u6_addr.u6_addr32[2] + iph6->ip6_src.u6_addr.u6_addr32[3];
    iph.daddr = iph6->ip6_dst.u6_addr.u6_addr32[2] + iph6->ip6_dst.u6_addr.u6_addr32[3];
    iph.protocol = iph6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    
    if(iph.protocol == 0x3C /* IPv6 destination option */) {
        u_int8_t *options = (u_int8_t*)iph6 + sizeof(const struct ndpi_ipv6hdr);
        
        iph.protocol = options[0];
    }
    
    return(get_ndpi_flow(thread_id, 6, vlan_id, &iph, iph6, ip_offset,
                         sizeof(struct ndpi_ipv6hdr),
                         ntohs(iph6->ip6_ctlun.ip6_un1.ip6_un1_plen),
                         tcph, udph, sport, dport,
                         src, dst, proto, payload, payload_len, src_to_dst_direction));
}

/* ***************************************************** */

static int setup_socket(u_int16_t thread_id) {
    int len, ret, result, sockfd;
    struct sockaddr_in address;
    
    /*クライアント用ソケット作成*/
    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        output(LOG_ERR, "%s\n", "[ERROR] Could not create socket");
        close(sockfd);
        return 0;
    }
    
    /*サーバ側と同じ名前でソケットの名前を指定*/
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(_server_addr);
    if (address.sin_addr.s_addr == 0xffffffff) {
        struct addrinfo hints;
        struct addrinfo *result;
        
        memset(&hints, 0, sizeof(struct addrinfo));
        if((ret = getaddrinfo(_server_addr, NULL, &hints, &result)) != 0){
            output(LOG_ERR, "[ERROR] %s\n", gai_strerror(ret));
            close(sockfd);
            return 0;
        }
        address.sin_addr.s_addr = ((struct sockaddr_in *)(result->ai_addr))->sin_addr.s_addr;
	freeaddrinfo(result);
    }
    address.sin_port = htons(_server_port);
    len = sizeof(address);
    
    /*クライアントのソケットとサーバのソケットの接続*/
    if((connect(sockfd, (struct sockaddr *)&address, len)) == -1){
        output(LOG_ERR, "%s\n", "[ERROR] Could not connect to server");
        close(sockfd);
        return 0;
    }
    _sockfd[thread_id] = sockfd;
    return 1;
}

/* ***************************************************** */

static void setup_detection(u_int16_t thread_id) {
    NDPI_PROTOCOL_BITMASK all;
    
    memset(&ndpi_thread_info[thread_id], 0, sizeof(ndpi_thread_info[thread_id]));
    
    // init global detection structure
    ndpi_thread_info[thread_id].ndpi_struct = ndpi_init_detection_module(detection_tick_resolution,
                                                                         malloc_wrapper, free_wrapper, NULL);
    if(ndpi_thread_info[thread_id].ndpi_struct == NULL) {
        output(LOG_ERR, "%s\n", "[ERROR] global structure initialization failed");
        exit(-1);
    }
    
    /* ndpi_thread_info[thread_id].ndpi_struct->http_dont_dissect_response = 1; */
    
    // enable all protocols
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_thread_info[thread_id].ndpi_struct, &all);
    
    // allocate memory for id and flow tracking
    size_id_struct = sizeof(struct ndpi_id_struct);
    size_flow_struct = sizeof(struct ndpi_flow_struct);
    
    if(_protoFilePath != NULL)
        ndpi_load_protocols_file(ndpi_thread_info[thread_id].ndpi_struct, _protoFilePath);
}

/* ***************************************************** */

static void terminate_detection(u_int16_t thread_id) {
    int i;
    
    for(i=0; i<NUM_ROOTS; i++) {
        /* expire all flows */
        ndpi_twalk(ndpi_thread_info[thread_id].ndpi_flows_root[i], node_expire_all_walker, &thread_id);

        ndpi_tdestroy(ndpi_thread_info[thread_id].ndpi_flows_root[i], ndpi_flow_freer);
        ndpi_thread_info[thread_id].ndpi_flows_root[i] = NULL;
    }
    
    ndpi_exit_detection_module(ndpi_thread_info[thread_id].ndpi_struct, free_wrapper);
}

/* ***************************************************** */

static void flow_update_expiry(struct ndpi_flow *flow, 
                                       struct ndpi_tcphdr *tcph,
                                       struct ndpi_udphdr *udph,
                                       u_int8_t proto) {
    /* Flows over maximum life seconds */
    if (flow->last_seen - flow->first_seen > MAXIMUM_LIFETIME * detection_tick_resolution) {
        flow->expires_at = 0;
    }else if (proto == IPPROTO_TCP) {
        /* TCP flows */
        if (tcph->rst) { 
            /* Reset TCP flows */
            flow->fin_rst_received = 1;
            flow->expires_at = flow->last_seen + TCP_RST_TIMEOUT * detection_tick_resolution;
        }else if (tcph->fin){ 
            /* Finished TCP flows */
            flow->fin_rst_received = 1;
            flow->expires_at = flow->last_seen + TCP_FIN_TIMEOUT * detection_tick_resolution;
        }else if (!flow->fin_rst_received) { 
            /* TCP flows */
            flow->expires_at = flow->last_seen + TCP_TIMEOUT * detection_tick_resolution;
        }
    }else if (proto == IPPROTO_UDP) {
        /* UDP flows */
        flow->expires_at = flow->last_seen + UDP_TIMEOUT * detection_tick_resolution;
    }else if ((proto == IPPROTO_ICMP) || (proto == IPPROTO_ICMPV6)) {
        /* ICMP flows */
        flow->expires_at = flow->last_seen + ICMP_TIMEOUT * detection_tick_resolution;
    }else{
        /* Everything else */
        flow->expires_at = flow->last_seen + GENERAL_TIMEOUT * detection_tick_resolution;
    }
}

/* ***************************************************** */

static unsigned int packet_processing(u_int16_t thread_id,
                                      const u_int64_t time,
                                      u_int16_t vlan_id,
                                      const struct ndpi_iphdr *iph,
                                      struct ndpi_ipv6hdr *iph6,
                                      u_int16_t ip_offset,
                                      u_int16_t ipsize, u_int16_t rawsize) {
    struct ndpi_id_struct *src, *dst;
    struct ndpi_flow *flow;
    struct ndpi_flow_struct *ndpi_flow = NULL;
    u_int8_t proto;
    struct ndpi_tcphdr *tcph = NULL;
    struct ndpi_udphdr *udph = NULL;
    u_int16_t sport, dport, payload_len;
    u_int8_t *payload;
    u_int8_t src_to_dst_direction= 1;
    
    if(iph)
        flow = get_ndpi_flow(thread_id, 4, vlan_id, iph, NULL,
                             ip_offset, ipsize,
                             ntohs(iph->tot_len) - (iph->ihl * 4),
                             &tcph, &udph, &sport, &dport,			
                             &src, &dst, &proto,
                             &payload, &payload_len, &src_to_dst_direction);
    else
        flow = get_ndpi_flow6(thread_id, vlan_id, iph6, ip_offset,
                              &tcph, &udph, &sport, &dport,			
                              &src, &dst, &proto,
                              &payload, &payload_len, &src_to_dst_direction);
    
    if(flow != NULL) {
        ndpi_flow = flow->ndpi_flow;
        // Add to the download packets and bytes if the current direction is different from the first direction.
        if(flow->src_to_dst_direction ^ src_to_dst_direction){
            flow->in_pkts++, flow->in_bytes += rawsize;
        }else{
            flow->out_pkts++, flow->out_bytes += rawsize;
        }
        flow->last_seen = time;
        if(flow->first_seen == 0){
            flow->first_seen = time;
        }
    } else {
        return(0);
    }
    
    flow_update_expiry(flow, tcph, udph, proto);
    if(flow->detection_completed) return(0);
    
    flow->detected_protocol = ndpi_detection_process_packet(ndpi_thread_info[thread_id].ndpi_struct, ndpi_flow,
                                                            iph ? (uint8_t *)iph : (uint8_t *)iph6,
                                                            ipsize, time, src, dst);

    if(flow->detected_protocol.protocol != NDPI_PROTOCOL_UNKNOWN){
        flow->detection_completed = 1;
        
        if((flow->detected_protocol.protocol == NDPI_PROTOCOL_UNKNOWN) && (ndpi_flow->num_stun_udp_pkts > 0))
            ndpi_set_detected_protocol(ndpi_thread_info[thread_id].ndpi_struct, ndpi_flow, NDPI_PROTOCOL_STUN, NDPI_PROTOCOL_UNKNOWN);
        
        snprintf(flow->host_server_name, sizeof(flow->host_server_name), "%s", flow->ndpi_flow->host_server_name);
        
        if((proto == IPPROTO_TCP) && (flow->detected_protocol.protocol != NDPI_PROTOCOL_DNS)) {
            snprintf(flow->ssl.client_certificate, sizeof(flow->ssl.client_certificate), "%s", flow->ndpi_flow->protos.ssl.client_certificate);
            snprintf(flow->ssl.server_certificate, sizeof(flow->ssl.server_certificate), "%s", flow->ndpi_flow->protos.ssl.server_certificate);
        }
        
        if(flow->ndpi_flow != NULL) free_ndpi_flow(flow);
        
        if(verbose > 1) {
            if(enable_protocol_guess) {
                if(flow->detected_protocol.protocol == NDPI_PROTOCOL_UNKNOWN) {
                    flow->detected_protocol.protocol = node_guess_undetected_protocol(thread_id, flow),
                    flow->detected_protocol.master_protocol = NDPI_PROTOCOL_UNKNOWN;
                }
            }
        }
    }
    
    if(ndpi_thread_info[thread_id].last_idle_scan_time + IDLE_SCAN_PERIOD < ndpi_thread_info[thread_id].last_time) {
        /* scan for idle flows */
        ndpi_twalk(ndpi_thread_info[thread_id].ndpi_flows_root[ndpi_thread_info[thread_id].idle_scan_idx], node_idle_scan_walker, &thread_id);

        /* remove idle flows */
        remove_idle_flows(thread_id);

        if(++ndpi_thread_info[thread_id].idle_scan_idx == NUM_ROOTS) ndpi_thread_info[thread_id].idle_scan_idx = 0;
        ndpi_thread_info[thread_id].last_idle_scan_time = ndpi_thread_info[thread_id].last_time;
    }
    
    return 0;
}

/* ***************************************************** */

static void close_pcap_file(u_int16_t thread_id) {
    if(ndpi_thread_info[thread_id]._pcap_handle != NULL) {
        pcap_close(ndpi_thread_info[thread_id]._pcap_handle);
        
    }
}

/* ***************************************************** */

static void break_pcap_loop(u_int16_t thread_id) {
    if(ndpi_thread_info[thread_id]._pcap_handle != NULL) {
        pcap_breakloop(ndpi_thread_info[thread_id]._pcap_handle);
    }
}

/* ***************************************************** */

// executed for each packet in the pcap file
void sigproc(int sig) {
    static int called = 0;
    int thread_id;
    
    if(called) return; else called = 1;
    shutdown_app = 1;
    
    for(thread_id=0; thread_id<num_threads; thread_id++)
        break_pcap_loop(thread_id);
}

/* ***************************************************** */

static int get_next_pcap_file_from_playlist(u_int16_t thread_id, char filename[], u_int32_t filename_len) {
    
    if(playlist_fp[thread_id] == NULL) {
        if((playlist_fp[thread_id] = fopen(_pcap_file[thread_id], "r")) == NULL)
            return -1;
    }
    
next_line:
    if(fgets(filename, filename_len, playlist_fp[thread_id])) {
        int l = strlen(filename);
        if(filename[0] == '\0' || filename[0] == '#') goto next_line;
        if(filename[l-1] == '\n') filename[l-1] = '\0';
        return 0;
    } else {
        fclose(playlist_fp[thread_id]);
        playlist_fp[thread_id] = NULL;
        return -1;
    }
}

/* ***************************************************** */

static void configure_pcap_handle(u_int16_t thread_id) {
    ndpi_thread_info[thread_id]._pcap_datalink_type = pcap_datalink(ndpi_thread_info[thread_id]._pcap_handle);
    
    if(_bpf_filter != NULL) {
        struct bpf_program fcode;
        
        if(pcap_compile(ndpi_thread_info[thread_id]._pcap_handle, &fcode, _bpf_filter, 1, 0xFFFFFF00) < 0) {
            output(LOG_ERR, "[ERROR] pcap_compile error: '%s'\n", pcap_geterr(ndpi_thread_info[thread_id]._pcap_handle));
        } else {
            if(pcap_setfilter(ndpi_thread_info[thread_id]._pcap_handle, &fcode) < 0) {
                output(LOG_ERR, "[ERROR] pcap_setfilter error: '%s'\n", pcap_geterr(ndpi_thread_info[thread_id]._pcap_handle));
            } else
                output(LOG_ERR, "[ERROR] Successfully set BPF filter to '%s'\n", _bpf_filter);
        }
    }
}

/* ***************************************************** */

static void open_pcap_file_or_device(u_int16_t thread_id) {
    u_int snaplen = 1536;
    int promisc = 1;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    /* trying to open a live interface */
    if((ndpi_thread_info[thread_id]._pcap_handle = pcap_open_live(_pcap_file[thread_id], snaplen, promisc, 500, errbuf)) == NULL) {
        
        live_capture = 0;
        num_threads = 1; /* Open pcap files in single threads mode */
        
        /* trying to open a pcap file */
        if((ndpi_thread_info[thread_id]._pcap_handle = pcap_open_offline(_pcap_file[thread_id], ndpi_thread_info[thread_id]._pcap_error_buffer)) == NULL) {
            char filename[256];
            
            /* trying to open a pcap playlist */
            if(get_next_pcap_file_from_playlist(thread_id, filename, sizeof(filename)) != 0 ||
               (ndpi_thread_info[thread_id]._pcap_handle = pcap_open_offline(filename, ndpi_thread_info[thread_id]._pcap_error_buffer)) == NULL) {
                
                output(LOG_ERR, "[ERROR] could not open pcap file or playlist: %s\n", ndpi_thread_info[thread_id]._pcap_error_buffer);
                exit(-1);
            } else {
                output(LOG_INFO, "[INFO] Reading packets from playlist %s...\n", _pcap_file[thread_id]);

            }
        } else {
            output(LOG_INFO, "[INFO] Reading packets from pcap file %s...\n", _pcap_file[thread_id]);
        }
    } else {
        live_capture = 1;
        output(LOG_INFO, "[INFO] Capturing live traffic from device %s...\n", _pcap_file[thread_id]);
    }
    
    configure_pcap_handle(thread_id);
}

/* ***************************************************** */

static void pcap_packet_callback(u_char *args,
                                 const struct pcap_pkthdr *header,
                                 const u_char *packet) {
    
    /*
     * Declare pointers to packet headers
     */
    
    /* --- Ethernet header --- */
    const struct ndpi_ethhdr *ethernet;
    /* --- Ethernet II header --- */
    const struct ndpi_ethhdr *ethernet_2;
    /* --- LLC header --- */
    const struct ndpi_llc_header *llc;
    
    /* --- Cisco HDLC header --- */
    const struct ndpi_chdlc *chdlc;
    /* --- SLARP frame --- */
    struct ndpi_slarp *slarp;
    /* --- CDP --- */
    struct ndpi_cdp *cdp;
    
    /* --- Radio Tap header --- */
    const struct ndpi_radiotap_header *radiotap;
    /* --- Wifi header --- */
    const struct ndpi_wifi_header *wifi;
    
    /* --- MPLS header --- */
    struct ndpi_mpls_header *mpls;
    
    /** --- IP header --- **/
    struct ndpi_iphdr *iph;
    /** --- IPv6 header --- **/
    struct ndpi_ipv6hdr *iph6;
    
    /* lengths and offsets */
    u_int16_t eth_offset = 0;
    u_int16_t radio_len;
    u_int16_t fc;
    u_int16_t type;
    int wifi_len;
    int llc_off;
    int pyld_eth_len = 0;
    int check;
    u_int32_t fcs;
    
    u_int64_t time;
    u_int16_t ip_offset, ip_len, ip6_offset;
    u_int16_t frag_off = 0, vlan_id = 0;
    u_int8_t proto = 0;
    u_int32_t label;
    
    u_int16_t thread_id = *((u_int16_t*)args);
    
    /* counters */
    u_int8_t malformed_pkts = 0, vlan_packet = 0;
    u_int8_t slarp_pkts = 0, cdp_pkts = 0;
    
    /* Check if capture is live or not */
    if (!live_capture) {
        if (!pcap_start.tv_sec) pcap_start.tv_sec = header->ts.tv_sec, pcap_start.tv_usec = header->ts.tv_usec;
        pcap_end.tv_sec = header->ts.tv_sec, pcap_end.tv_usec = header->ts.tv_usec;
    }
    
    /* setting time */
    time = ((uint64_t) header->ts.tv_sec) * detection_tick_resolution +
    header->ts.tv_usec / (1000000 / detection_tick_resolution);
    
    /* safety check */
    if(ndpi_thread_info[thread_id].last_time > time) {
        /* printf("\nWARNING: timestamp bug in the pcap file (ts delta: %llu, repairing)\n", ndpi_thread_info[thread_id].last_time - time); */
        time = ndpi_thread_info[thread_id].last_time;
    }
    /* update last time value */
    ndpi_thread_info[thread_id].last_time = time;
    
    /*** check Data Link type ***/
    int datalink_type = ndpi_thread_info[thread_id]._pcap_datalink_type;
    
datalink_check:
    switch(datalink_type) {
        case DLT_NULL :
            if(ntohl(*((u_int32_t*)&packet[eth_offset])) == 2)
                type = ETH_P_IP;
            else
                type = ETH_P_IPV6;
            
            ip_offset = 4 + eth_offset;
            
            /* Cisco PPP in HDLC-like framing - 50 */
        case DLT_PPP_SERIAL:
            chdlc = (struct ndpi_chdlc *) &packet[eth_offset];
            ip_offset = sizeof(struct ndpi_chdlc); /* CHDLC_OFF = 4 */
            type = ntohs(chdlc->proto_code);
            break;
            
            /* Cisco PPP with HDLC framing - 104 */
        case DLT_C_HDLC:
            chdlc = (struct ndpi_chdlc *) &packet[eth_offset];
            ip_offset = sizeof(struct ndpi_chdlc); /* CHDLC_OFF = 4 */
            type = ntohs(chdlc->proto_code);
            break;
            
            /* IEEE 802.3 Ethernet - 1 */
        case DLT_EN10MB :
            ethernet = (struct ndpi_ethhdr *) &packet[eth_offset];
            ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
            check = ntohs(ethernet->h_proto);
            
            if(check <= 1500)
                pyld_eth_len = check;
            else if (check >= 1536)
                type = check;
            
            if(pyld_eth_len != 0) {
                /* check for LLC layer with SNAP extension */
                if(packet[ip_offset] == SNAP) {
                    llc = (struct ndpi_llc_header *)(&packet[ip_offset]);
                    type = llc->snap.proto_ID;
                    ip_offset += + 8;
                }
            }
            break;
            
            /* Linux Cooked Capture - 113 */
        case DLT_LINUX_SLL :
            type = (packet[eth_offset+14] << 8) + packet[eth_offset+15];
            ip_offset = 16 + eth_offset;
            break;
            
            /* Radiotap link-layer - 127 */
        case DLT_IEEE802_11_RADIO :
            radiotap = (struct ndpi_radiotap_header *) &packet[eth_offset];
            radio_len = radiotap->len;
            
            /* Check Bad FCS presence */
            if((radiotap->flags & BAD_FCS) == BAD_FCS) {
                malformed_pkts += 1;
                return;
            }
            
            fcs = header->len - 4;
            
            /* Calculate 802.11 header length (variable) */
            wifi = (struct ndpi_wifi_header*)( packet + eth_offset + radio_len);
            fc = wifi->fc;
            
            /* check wifi data presence */
            if(FCF_TYPE(fc) == WIFI_DATA) {
                if((FCF_TO_DS(fc) && FCF_FROM_DS(fc) == 0x0) ||
                   (FCF_TO_DS(fc) == 0x0 && FCF_FROM_DS(fc)))
                    wifi_len = 26; /* + 4 byte fcs */
            } else   /* no data frames */
                break;
            
            /* Check ether_type from LLC */
            llc = (struct ndpi_llc_header*)(packet + eth_offset + wifi_len + radio_len);
            if(llc->dsap == SNAP)
                type = ntohs(llc->snap.proto_ID);
            
            /* Set IP header offset */
            ip_offset = wifi_len + radio_len + sizeof(struct ndpi_llc_header) + eth_offset;
            break;
            
        case DLT_RAW:
            ip_offset = eth_offset = 0;
            break;
            
        default:
            /* printf("Unknown datalink %d\n", datalink_type); */
            return;
    }
    
    /* check ether type */
    if(type == VLAN) {
        vlan_id = ((packet[ip_offset] << 8) + packet[ip_offset+1]) & 0xFFF;
        type = (packet[ip_offset+2] << 8) + packet[ip_offset+3];
        ip_offset += 4;
        vlan_packet = 1;
    } else if(type == MPLS_UNI || type == MPLS_MULTI) {    
        mpls = (struct ndpi_mpls_header *) &packet[ip_offset];
        label = ntohl(mpls->label);
        /* label = ntohl(*((u_int32_t*)&packet[ip_offset])); */
        type = ETH_P_IP, ip_offset += 4;
        
        while((label & 0x100) != 0x100) {
            ip_offset += 4;
            label = ntohl(mpls->label);
        }
    }
    else if(type == SLARP) {
        slarp = (struct ndpi_slarp *) &packet[ip_offset];
        if(slarp->slarp_type == 0x02 || slarp->slarp_type == 0x00 || slarp->slarp_type == 0x01) {
            /* TODO if info are needed */
        }
        slarp_pkts++;
    }
    else if(type == CISCO_D_PROTO) {
        cdp = (struct ndpi_cdp *) &packet[ip_offset];
        cdp_pkts++;
    }    
    else if(type == PPPoE) {
        type = ETH_P_IP;
        ip_offset += 8;
    }
    
    
iph_check:
    /* Check and set IP header size and total packet length */
    iph = (struct ndpi_iphdr *) &packet[ip_offset];
    
    /* just work on Ethernet packets that contain IP */
    if(type == ETH_P_IP && header->caplen >= ip_offset) {
        frag_off = ntohs(iph->frag_off);
        
        proto = iph->protocol;
        if(header->caplen < header->len) {
            static u_int8_t cap_warning_used = 0;
            
            if(cap_warning_used == 0) {
                output(LOG_WARNING, "%s\n", "[WARN] packet capture size is smaller than packet size, DETECTION MIGHT NOT WORK CORRECTLY");
                cap_warning_used = 1;
            }
        }
    }
    
    if(iph->version == 4) {
        ip_len = ((u_short)iph->ihl * 4);
        iph6 = NULL;
        
        if(iph->protocol == 41) {
            ip_offset += ip_len;
            goto iph_check;
        }
        
        if((frag_off & 0x3FFF) != 0) {
            static u_int8_t ipv4_frags_warning_used = 0;
            if(ipv4_frags_warning_used == 0) {
                output(LOG_WARNING, "%s\n", "[WARN] IPv4 fragments has not been supported yet");
                ipv4_frags_warning_used = 1;
            }
            return;
        }
    } else if(iph->version == 6) {
        iph6 = (struct ndpi_ipv6hdr *)&packet[ip_offset];
        proto = iph6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        ip_len = sizeof(struct ndpi_ipv6hdr);
        
        if(proto == 0x3C /* IPv6 destination option */) {
            
            u_int8_t *options = (u_int8_t*)&packet[ip_offset+ip_len];
            proto = options[0];
            ip_len += 8 * (options[1] + 1);
        }
        iph = NULL;
        
    } else {
        static u_int8_t ipv4_warning_used = 0;
        
    v4_warning:
        if(ipv4_warning_used == 0) {
            if(!quiet_mode)
            output(LOG_WARNING, "%s\n", "[WARN] only IPv4/IPv6 packets are supported by ndff, all other packets will be discarded");
            ipv4_warning_used = 1;
        }
        return;
    }
    
    if(decode_tunnels && (proto == IPPROTO_UDP)) {
        struct ndpi_udphdr *udp = (struct ndpi_udphdr *)&packet[ip_offset+ip_len];
        u_int16_t sport = ntohs(udp->source), dport = ntohs(udp->dest);
        
        if((sport == GTP_U_V1_PORT) || (dport == GTP_U_V1_PORT)) {
            /* Check if it's GTPv1 */
            u_int offset = ip_offset+ip_len+sizeof(struct ndpi_udphdr);
            u_int8_t flags = packet[offset];
            u_int8_t message_type = packet[offset+1];
            
            if((((flags & 0xE0) >> 5) == 1 /* GTPv1 */) &&
               (message_type == 0xFF /* T-PDU */)) {
                
                ip_offset = ip_offset+ip_len+sizeof(struct ndpi_udphdr)+8; /* GTPv1 header len */
                if(flags & 0x04) ip_offset += 1; /* next_ext_header is present */
                if(flags & 0x02) ip_offset += 4; /* sequence_number is present (it also includes next_ext_header and pdu_number) */
                if(flags & 0x01) ip_offset += 1; /* pdu_number is present */
                
                iph = (struct ndpi_iphdr *) &packet[ip_offset];
                
                if(iph->version != 4) {
                    goto v4_warning;
                }
            }
        } else if((sport == TZSP_PORT) || (dport == TZSP_PORT)) {
            /* https://en.wikipedia.org/wiki/TZSP */
            u_int offset = ip_offset+ip_len+sizeof(struct ndpi_udphdr);
            u_int8_t version = packet[offset];
            u_int8_t type    = packet[offset+1];
            u_int16_t encapsulates = ntohs(*((u_int16_t*)&packet[offset+2]));
            
            if((version == 1) && (type == 0) && (encapsulates == 1)) {
                u_int8_t stop = 0;
                
                offset += 4;
                
                while((!stop) && (offset < header->caplen)) {
                    u_int8_t tag_type = packet[offset];
                    u_int8_t tag_len;
                    
                    switch(tag_type) {
                        case 0: /* PADDING Tag */
                            tag_len = 1;
                            break;
                        case 1: /* END Tag */
                            tag_len = 1, stop = 1;
                            break;
                        default:
                            tag_len = packet[offset+1];
                            break;
                    }
                    
                    offset += tag_len;
                    
                    if(offset >= header->caplen)
                        return; /* Invalid packet */
                    else {
                        eth_offset = offset;
                        goto datalink_check;
                    }
                }
            }
        }
    }
    
    /* process the packet */
    packet_processing(thread_id, time, vlan_id, iph, iph6,
                      ip_offset, header->len - ip_offset, header->len);
}

/* ******************************************************************** */

static void run_pcap_loop(u_int16_t thread_id) {
    if((!shutdown_app) && (ndpi_thread_info[thread_id]._pcap_handle != NULL))
        pcap_loop(ndpi_thread_info[thread_id]._pcap_handle, -1, &pcap_packet_callback, (u_char*)&thread_id);
}

/* ******************************************************************** */

void *processing_thread(void *_thread_id) {
    long thread_id = (long) _thread_id;
    
#if defined(linux) && defined(HAVE_PTHREAD_SETAFFINITY_NP)
    if(core_affinity[thread_id] >= 0) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(core_affinity[thread_id], &cpuset);
        
        if(pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0)
            fprintf(stderr, "[ERROR] while binding thread %ld to core %d\n", thread_id, core_affinity[thread_id]);
        else {
            output(LOG_INFO, "[INFO] Running thread %ld on core %d...\n", thread_id, core_affinity[thread_id]);
        }
    } else
#endif
        output(LOG_INFO, "[INFO] Running thread %ld...\n", thread_id);
    
pcap_loop:
    run_pcap_loop(thread_id);
    
    if(playlist_fp[thread_id] != NULL) { /* playlist: read next file */
        char filename[256];
        
        if(get_next_pcap_file_from_playlist(thread_id, filename, sizeof(filename)) == 0 &&
           (ndpi_thread_info[thread_id]._pcap_handle = pcap_open_offline(filename, ndpi_thread_info[thread_id]._pcap_error_buffer)) != NULL) {
            configure_pcap_handle(thread_id);
            goto pcap_loop;
        }
    }
    
    return NULL;
}

/* ******************************************************************** */

void run() {
    struct timeval begin, end;
    u_int64_t tot_usec;
    long thread_id;
    
    for(thread_id = 0; thread_id < num_threads; thread_id++) {
        setup_detection(thread_id);
        if(!dryrun_flag) {
            if(setup_socket(thread_id) == 0) exit(1);
        }
        open_pcap_file_or_device(thread_id);
    }
    
    gettimeofday(&begin, NULL);
    
    /* Running processing threads */
    for(thread_id = 0; thread_id < num_threads; thread_id++)
        pthread_create(&ndpi_thread_info[thread_id].pthread, NULL, processing_thread, (void *) thread_id);
    
    /* Waiting for completion */
    for(thread_id = 0; thread_id < num_threads; thread_id++)
        pthread_join(ndpi_thread_info[thread_id].pthread, NULL);
    
    gettimeofday(&end, NULL);
    tot_usec = end.tv_sec*1000000 + end.tv_usec - (begin.tv_sec*1000000 + begin.tv_usec);
    
    for(thread_id = 0; thread_id < num_threads; thread_id++) {
        close_pcap_file(thread_id);
        terminate_detection(thread_id);
    	close(_sockfd[thread_id]);
    }
}

/* ***************************************************** */

int main(int argc, char **argv) {
    int i;
    
    memset(ndpi_thread_info, 0, sizeof(ndpi_thread_info));
    memset(&pcap_start, 0, sizeof(pcap_start));
    memset(&pcap_end, 0, sizeof(pcap_end));
    
    parse_options(argc, argv);
    
    signal(SIGINT, sigproc);
    
    run();
    
    if(results_path) free(results_path);
    if(results_file) fclose(results_file);
    
    return 0;
}

/* ****************************************************** */
