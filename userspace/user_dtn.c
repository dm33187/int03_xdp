#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <bits/stdint-uintn.h>
#include <bits/types.h>
#include <ctype.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <sys/wait.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <arpa/inet.h>

#include "unp.h"
#include "user_dtn.h"

pthread_mutex_t dtn_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t dtn_cond = PTHREAD_COND_INITIALIZER;
static int cdone = 0;
static unsigned int sleep_count = 5;
struct args test;
char aSrc_Ip[32];
union uIP {
	 __u32 y;
       	 unsigned char  a[4];
};

static union uIP src_ip_addr;

void qOCC_Hop_TimerID_Handler(int signum, siginfo_t *info, void *ptr);
static void timerHandler( int sig, siginfo_t *si, void *uc );

FILE * tunLogPtr = 0;
void gettime(time_t *clk, char *ctime_buf)
{
	*clk = time(NULL);
	ctime_r(clk,ctime_buf);
	ctime_buf[24] = ':';
}

timer_t qOCC_Hop_TimerID;
timer_t rTT_TimerID;

struct itimerspec sStartTimer;
struct itimerspec sDisableTimer;

static void timerHandler( int sig, siginfo_t *si, void *uc )
{
	timer_t *tidp;
	tidp = si->si_value.sival_ptr;

	if ( *tidp == qOCC_Hop_TimerID )
		qOCC_Hop_TimerID_Handler(sig, si, uc);
	else
		fprintf(stdout, "Timer handler incorrect***\n");

	return;
}

static int makeTimer( char *name, timer_t *timerID, int expires_usecs)
{
	struct sigevent         te;
	struct sigaction        sa;
	int                     sigNo = SIGRTMIN;
	long 			sec   = ((long)expires_usecs * 1000L) / 1000000000L;
       	long 			nsec  = ((long)expires_usecs * 1000L) % 1000000000L; //going fron micro to nano

	/* Set up signal handler. */
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = timerHandler;
	sigemptyset(&sa.sa_mask);
	if (sigaction(sigNo, &sa, NULL) == -1)
	{
		fprintf(stderr, "Err***: Failed to setup signal handling for %s.\n", name);
		return(-1);
	}

	/* Set and enable alarm */
	te.sigev_notify = SIGEV_SIGNAL;
	te.sigev_signo = sigNo;
	te.sigev_value.sival_ptr = timerID;
	timer_create(CLOCK_REALTIME, &te, timerID);

	sStartTimer.it_value.tv_sec = sec;
	sStartTimer.it_value.tv_nsec = nsec;
	fprintf(stdout,"sec in timer = %ld, nsec = %ld, expires_usec = %d\n", sStartTimer.it_value.tv_sec, sStartTimer.it_value.tv_nsec, expires_usecs);

	return(0);
}

/******HTTP server *****/
#include "fio.h"
#include "http.h"
void initialize_http_service(void);
/**********************/

/* msleep(): Sleep for the requested number of milliseconds. */
int msleep(long msec)
{
	struct timespec ts;
	int res;

	if (msec < 0)
	{
		errno = EINVAL;
		return -1;
	}

	ts.tv_sec = msec / 1000;
	ts.tv_nsec = (msec % 1000) * 1000000;

	do {
		res = nanosleep(&ts, &ts);
	} while (res && errno == EINTR);

	return res;
}

char netDevice[128];
static unsigned long rx_bits_per_sec = 0, tx_bits_per_sec = 0;
static int vDebugLevel = 0; //Print regular messages to log file

#define SIGINT_MSG "SIGINT received.\n"
void sig_int_handler(int signum, siginfo_t *info, void *ptr)
{
	write(STDERR_FILENO, SIGINT_MSG, sizeof(SIGINT_MSG));
	fprintf(tunLogPtr,"Caught SIGINT, exiting...\n");
	fclose(tunLogPtr);
	exit(0);
}

void catch_sigint()
{
	static struct sigaction _sigact;

	memset(&_sigact, 0, sizeof(_sigact));
	_sigact.sa_sigaction = sig_int_handler;
	_sigact.sa_flags = SA_SIGINFO;

	sigaction(SIGINT, &_sigact, NULL);
}

/* start of bpf stuff  ****/
#ifndef PATH_MAX
#define PATH_MAX    4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";

#include <locale.h>
#include <time.h>

//Looks like because of the ringbuf stuff
//#include "../libbpf/src/libbpf.h"

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "common_kern_user.h"
#include "bpf_util.h" /* bpf_num_possible_cpus */

typedef struct {
	int argc;
	char ** argv;
} sArgv_t;

#include "../../c++-int-sink/int-sink/src/shared/int_defs.h"
#include "../../c++-int-sink/int-sink/src/shared/filter_defs.h"

enum ARGS{
	CMD_ARG,
	BPF_MAPS_DIR_ARG,
	MAX_ARG_COUNT
};

struct threshold_maps
{
	int flow_thresholds;
	int hop_thresholds;
	int flow_counters;
};

#define MAX_TUNING_ACTIVITIES_PER_FLOW	10
#define MAX_SIZE_TUNING_STRING		1001
#define NUM_OF_FLOWS_TO_KEEP_TRACK_OF	4
typedef struct {
        int num_tuning_activities;
	char what_was_done[MAX_TUNING_ACTIVITIES_PER_FLOW][MAX_SIZE_TUNING_STRING];
} sFlowCounters_t;

static __u32 flow_sink_time_threshold = 0;
static __u32 Qinfo = 0;
static __u32 ingress_time = 0;
static __u32 egress_time = 0;
static __u32 hop_hop_latency_threshold = 0;
static int vFlowCount = 0;
static sFlowCounters_t sFlowCounters[NUM_OF_FLOWS_TO_KEEP_TRACK_OF];
#define MAP_DIR "/sys/fs/bpf/test_maps"
#if 0
//original stuff
#define HOP_LATENCY_DELTA 20000
#define FLOW_LATENCY_DELTA 50000
#define QUEUE_OCCUPANCY_DELTA 80
#define FLOW_SINK_TIME_DELTA 1000000000
#else
static __u32 vHOP_LATENCY_DELTA = 500000; //was  120000
static __u32 vFLOW_LATENCY_DELTA = 500000; //was 280000
static __u32 vQUEUE_OCCUPANCY_DELTA = 30000; //was 6400
static __u32 vFLOW_SINK_TIME_DELTA = 4000000000;
#endif
#define INT_DSCP (0x17)

#define PERF_PAGE_COUNT 512
#define MAX_FLOW_COUNTERS 512

void sample_func(struct threshold_maps *ctx, int cpu, void *data, __u32 size);
void lost_func(struct threshold_maps *ctx, int cpu, __u64 cnt);
void print_hop_key(struct hop_key *key);
void record_activity(void); 

#define SIGALRM_MSG "SIGALRM received.\n"
int vTimerIsSet = 0;

void qOCC_Hop_TimerID_Handler(int signum, siginfo_t *info, void *ptr)
{
	time_t clk;
	char ctime_buf[27];
	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr, "%s %s: ***Timer Alarm went off*** still having problems with Queue Occupancy and HopDelays. Time to do something***\n",ctime_buf, phase2str(current_phase)); 
	//***Do something here ***//
	vTimerIsSet = 0;
	record_activity();
	fflush(tunLogPtr);
	
	return;
}

void * fDoRunBpfCollectionPerfEventArray2(void * vargp)
{
	time_t clk;
	char ctime_buf[27];
	int timerRc = 0;
	int perf_output_map;
	int int_dscp_map;
	struct perf_buffer *pb;
	struct threshold_maps maps = {};

	memset (&sStartTimer,0,sizeof(struct itimerspec));
	memset (&sDisableTimer,0,sizeof(struct itimerspec));

	timerRc = makeTimer("qOCC_Hop_TimerID", &qOCC_Hop_TimerID, gInterval);
	if (timerRc)
	{
		fprintf(tunLogPtr, "%s %s: Problem creating timer *qOCC_Hop_TimerID*.\n", ctime_buf, phase2str(current_phase));
		return ((char *)1);
	}
	else
		fprintf(tunLogPtr, "%s %s: timer created.\n", ctime_buf, phase2str(current_phase));

open_maps: {
	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"%s %s: Opening maps.\n", ctime_buf, phase2str(current_phase));
	//maps.counters = bpf_obj_get(MAP_DIR "/counters_map");
	fprintf(tunLogPtr,"%s %s: Opening flow_counters_map.\n", ctime_buf, phase2str(current_phase));
	maps.flow_counters = bpf_obj_get(MAP_DIR "/flow_counters_map");
	if (maps.flow_counters < 0) { goto close_maps; }
	fprintf(tunLogPtr,"%s %s: Opening flow_thresholds_map.\n", ctime_buf, phase2str(current_phase));
	maps.flow_thresholds = bpf_obj_get(MAP_DIR "/flow_thresholds_map");
	if (maps.flow_thresholds < 0) { goto close_maps; }
	fprintf(tunLogPtr,"%s %s: Opening hop_thresholds_map.\n", ctime_buf, phase2str(current_phase));
	maps.hop_thresholds = bpf_obj_get(MAP_DIR "/hop_thresholds_map");
	if (maps.hop_thresholds < 0) { goto close_maps; }
	fprintf(tunLogPtr,"%s %s: Opening perf_output_map.\n", ctime_buf, phase2str(current_phase));
	perf_output_map = bpf_obj_get(MAP_DIR "/perf_output_map");
	if (perf_output_map < 0) { goto close_maps; }
	fprintf(tunLogPtr,"%s %s: Opening int_dscp_map.\n", ctime_buf, phase2str(current_phase));
	int_dscp_map = bpf_obj_get(MAP_DIR "/int_dscp_map");
	if (int_dscp_map < 0) { goto close_maps; }
	}
set_int_dscp: {
	fprintf(tunLogPtr,"%s %s: Setting INT DSCP.\n", ctime_buf, phase2str(current_phase));
	__u32 int_dscp = INT_DSCP;
	__u32 zero_value = 0;
	bpf_map_update_elem(int_dscp_map, &int_dscp, &zero_value, BPF_NOEXIST);
    }
open_perf_event: {
	fprintf(tunLogPtr,"%s %s: Opening perf event buffer.\n", ctime_buf, phase2str(current_phase));
#if 0
	struct perf_buffer_opts opts = {
	(perf_buffer_sample_fn)sample_func,
	(perf_buffer_lost_fn)lost_func,
	&maps
	};
#else
	struct perf_buffer_opts opts;
	opts.sample_cb = (perf_buffer_sample_fn)sample_func;
	opts.lost_cb = (perf_buffer_lost_fn)lost_func;
	opts.ctx = &maps;
#endif
	pb = perf_buffer__new(perf_output_map, PERF_PAGE_COUNT, &opts);
	if (pb == 0) { goto close_maps; }
	}
perf_event_loop: {
	fprintf(tunLogPtr,"%s %s: Running perf event loop.\n", ctime_buf, phase2str(current_phase));
	fflush(tunLogPtr);
 	int err = 0;
	do {
	//err = perf_buffer__poll(pb, 500);
	err = perf_buffer__poll(pb, 250);
	}
	while(err >= 0);
	fprintf(tunLogPtr,"%s %s: Exited perf event loop with err %d..\n", ctime_buf, phase2str(current_phase), -err);
	}
close_maps: {
	fprintf(tunLogPtr,"%s %s: Closing maps.\n", ctime_buf, phase2str(current_phase));
	if (maps.flow_counters <= 0) { goto exit_program; }
	close(maps.flow_counters);
	if (maps.flow_thresholds <= 0) { goto exit_program; }
	close(maps.flow_thresholds);
	if (maps.hop_thresholds <= 0) { goto exit_program; }
	close(maps.hop_thresholds);
	if (perf_output_map <= 0) { goto exit_program; }
	close(perf_output_map);
	if (int_dscp_map <= 0) { goto exit_program; }
	close(int_dscp_map);
	if (pb == 0) { goto exit_program; }
	perf_buffer__free(pb);
	}
exit_program: {
	return ((char *)0);
	}
}

static int gFlowCountUsed = 0;
static __u32 curr_hop_key_hop_index = 0;

void EvaluateQOcc_and_HopDelay(__u32 hop_key_hop_index)
{
	time_t clk;
	char ctime_buf[27];
	int vRetTimer;

	if (!vTimerIsSet)
	{
		vRetTimer = timer_settime(qOCC_Hop_TimerID, 0, &sStartTimer, (struct itimerspec *)NULL);
		if (!vRetTimer)
		{
			vTimerIsSet = 1;
			curr_hop_key_hop_index = hop_key_hop_index;
			if (vDebugLevel > 0)
			{
				gettime(&clk, ctime_buf);
				printf("%s %s: ***Timer set to %d microseconds for Queue Occupancy and HopDelay over threshholds***\n",ctime_buf, phase2str(current_phase), gInterval); 
			}
		}
		else
			printf("%s %s: ***could not set Timer, vRetTimer = %d,  errno = to %d***\n",ctime_buf, phase2str(current_phase), vRetTimer, errno); 

	}

	return;
}

void record_activity(void)
{
	char activity[1000];
	time_t clk;
	char ctime_buf[27];

	gettime(&clk, ctime_buf);
	sprintf(activity,"%s %s: ***hop_key.hop_index %X, Doing Something***vFlowcount = %d, num_tuning_activty = %d", ctime_buf, phase2str(current_phase), curr_hop_key_hop_index, vFlowCount, sFlowCounters[vFlowCount].num_tuning_activities + 1);

	fprintf(tunLogPtr,"%s\n",activity); //special case for testing

	strcpy(sFlowCounters[vFlowCount].what_was_done[sFlowCounters[vFlowCount].num_tuning_activities], activity);
	(sFlowCounters[vFlowCount].num_tuning_activities)++;
	if (sFlowCounters[vFlowCount].num_tuning_activities >= MAX_TUNING_ACTIVITIES_PER_FLOW)
		sFlowCounters[vFlowCount].num_tuning_activities = 0;

	gFlowCountUsed = 1;	

	return;
}

void sample_func(struct threshold_maps *ctx, int cpu, void *data, __u32 size)
{
	void *data_end = data + size;
	__u32 data_offset = 0;
	struct hop_key hop_key;
	long long flow_hop_latency_threshold = 0;
	time_t clk;
	char ctime_buf[27];

	if(data + data_offset + sizeof(hop_key) > data_end) return;

	memcpy(&hop_key, data + data_offset, sizeof(hop_key));
	data_offset += sizeof(hop_key);

	struct flow_thresholds flow_threshold_update = {
		0,
		vFLOW_LATENCY_DELTA,
		0,
		vFLOW_SINK_TIME_DELTA,
		0
	};

	hop_key.hop_index = 0;

	if (vDebugLevel > 2)
		fprintf(stdout,"\n******************************************************************\n");

	while (data + data_offset + sizeof(struct int_hop_metadata) <= data_end)
	{
		struct int_hop_metadata *hop_metadata_ptr = data + data_offset;
		data_offset += sizeof(struct int_hop_metadata);

		Qinfo = ntohl(hop_metadata_ptr->queue_info) & 0xffffff;
		ingress_time = ntohl(hop_metadata_ptr->ingress_time);
		egress_time = ntohl(hop_metadata_ptr->egress_time);
		hop_hop_latency_threshold = egress_time - ingress_time;
		if (vDebugLevel > 2)
		{

//			fprintf(stdout, "switch_id = %u\n",ntohl(hop_metadata_ptr->switch_id));
//			fprintf(stdout, "ingress_port_id = %d\n",ntohs(hop_metadata_ptr->ingress_port_id));
//			fprintf(stdout, "egress_port_id = %d\n",ntohs(hop_metadata_ptr->egress_port_id));
//			fprintf(stdout, "hop_latency = %u\n",ntohl(hop_metadata_ptr->hop_latency));
			fprintf(stdout, "Qinfo = %u\n",Qinfo);
			fprintf(stdout, "ingress_time = %u\n",ingress_time);
			fprintf(stdout, "egress_time = %u\n",egress_time);
			fprintf(stdout, "hop_hop_latency_threshold = %u\n",hop_hop_latency_threshold);
			fprintf(stdout, "sizeof struct int_hop-metadata = %lu\n",sizeof(struct int_hop_metadata));
			fprintf(stdout, "sizeof struct hop_key = %lu\n",sizeof(struct hop_key));
		}
#if 1
		if ((hop_hop_latency_threshold > vHOP_LATENCY_DELTA) && (Qinfo > vQUEUE_OCCUPANCY_DELTA))
		{
			EvaluateQOcc_and_HopDelay(hop_key.hop_index);
			if (vDebugLevel > 1)
			{
				gettime(&clk, ctime_buf);
				fprintf(tunLogPtr, "%s %s: ***hop_hop_latency_threshold = %u\n", ctime_buf, phase2str(current_phase), hop_hop_latency_threshold);
				fprintf(tunLogPtr, "%s %s: ***Qinfo = %u\n", ctime_buf, phase2str(current_phase), Qinfo);
			}
		}
		else
			{
				if (vTimerIsSet)
				{
					timer_settime(qOCC_Hop_TimerID, 0, &sDisableTimer, (struct itimerspec *)NULL);
					vTimerIsSet = 0;
				}

				if ((hop_hop_latency_threshold > vHOP_LATENCY_DELTA) || (Qinfo > vQUEUE_OCCUPANCY_DELTA))
				{
					if (vDebugLevel > 1)
					{
						gettime(&clk, ctime_buf);
						if (hop_hop_latency_threshold > vHOP_LATENCY_DELTA)
							fprintf(tunLogPtr, "%s %s: ***hop_hop_latency_threshold = %u\n", ctime_buf, phase2str(current_phase), hop_hop_latency_threshold);
						else
							fprintf(tunLogPtr, "%s %s: ***Qinfo = %u\n", ctime_buf, phase2str(current_phase), Qinfo);
					}
				}
			}
#endif
		struct hop_thresholds hop_threshold_update = {
			ntohl(hop_metadata_ptr->egress_time) - ntohl(hop_metadata_ptr->ingress_time),
			vHOP_LATENCY_DELTA,
			ntohl(hop_metadata_ptr->queue_info) & 0xffffff,
			vQUEUE_OCCUPANCY_DELTA,
			ntohl(hop_metadata_ptr->switch_id)
		};

		bpf_map_update_elem(ctx->hop_thresholds, &hop_key, &hop_threshold_update, BPF_ANY);
		if(hop_key.hop_index == 0) 
		{       
			__u32 ingress_time = ntohl(hop_metadata_ptr->ingress_time);
			flow_threshold_update.sink_time_threshold = ingress_time;; 

			if (vDebugLevel > 2)
				fprintf(stdout, "***flow_sink_time = %u\n", ingress_time - flow_sink_time_threshold);

			if (vDebugLevel > 3)
			{
				if ((ingress_time - flow_sink_time_threshold) > vFLOW_SINK_TIME_DELTA)
				{
					gettime(&clk, ctime_buf);
					fprintf(tunLogPtr, "%s %s: ***flow_sink_time = %u\n", ctime_buf, phase2str(current_phase), ingress_time - flow_sink_time_threshold);
				}
			}

			flow_sink_time_threshold = ingress_time;	
		}
		
		flow_threshold_update.hop_latency_threshold += ntohl(hop_metadata_ptr->egress_time) - ntohl(hop_metadata_ptr->ingress_time);
		flow_hop_latency_threshold += ntohl(hop_metadata_ptr->egress_time) - ntohl(hop_metadata_ptr->ingress_time);
		print_hop_key(&hop_key);
		src_ip_addr.y = ntohl(hop_key.flow_key.src_ip);
		hop_key.hop_index++;

	}

	flow_threshold_update.total_hops = hop_key.hop_index;
	bpf_map_update_elem(ctx->flow_thresholds, &hop_key.flow_key, &flow_threshold_update, BPF_ANY);
	struct counter_set empty_counter = {};
	bpf_map_update_elem(ctx->flow_counters, &(hop_key.flow_key), &empty_counter, BPF_NOEXIST);

	if (vDebugLevel > 2)
		fprintf(stdout, "flow_hop_latency_threshold = %lld\n", flow_hop_latency_threshold);
	
	if (vDebugLevel > 1)
	{
		if (flow_hop_latency_threshold > vFLOW_LATENCY_DELTA)
		{
			gettime(&clk, ctime_buf);
			fprintf(tunLogPtr, "%s %s: ***flow_hop_latency_threshold = %lld\n", ctime_buf, phase2str(current_phase), flow_hop_latency_threshold);
		}

		fflush(tunLogPtr);
	}

	if (gFlowCountUsed)
	{	
		if (++vFlowCount == NUM_OF_FLOWS_TO_KEEP_TRACK_OF) vFlowCount = 0;
		sFlowCounters[vFlowCount].num_tuning_activities = 0;
		gFlowCountUsed = 0;
	}
}

void lost_func(struct threshold_maps *ctx, int cpu, __u64 cnt)
{
	time_t clk;
	char ctime_buf[27];

	//fprintf(stderr, "Missed %llu sets of packet metadata.\n", cnt);
	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr, "%s %s: Missed %llu sets of packet metadata.\n", ctime_buf, phase2str(current_phase), cnt);
	fflush(tunLogPtr);
}
	
void print_flow_key(struct flow_key *key)
{
	fprintf(stdout, "Flow Key:\n");
#if 1
	fprintf(stdout, "\tegress_switch:%X\n", key->switch_id);
	fprintf(stdout, "\tegress_port:%hu\n", key->egress_port);
	fprintf(stdout, "\tvlan_id:%hu\n", key->vlan_id);

	if (src_ip_addr.y)
		fprintf(stdout,"%u.%u.%u.%u", src_ip_addr.a[0], src_ip_addr.a[1], src_ip_addr.a[2], src_ip_addr.a[3]);
#endif
}

void print_hop_key(struct hop_key *key)
{
	if (vDebugLevel > 3 )
	{
		fprintf(stdout, "Hop Key:\n");
		print_flow_key(&(key->flow_key));
		fprintf(stdout, "\thop_index: %X\n", key->hop_index);
	}
}
/* End of bpf stuff ****/

/***** HTTP *************/
void check_req(http_s *h, char aResp[])
{
	FIOBJ r = http_req2str(h);
	time_t clk;
	char ctime_buf[27];
	char aHttpRequest[256];
	char * pReqData = fiobj_obj2cstr(r).data;
	int count = 0;
	char aSettingFromHttp[512];
	char aNumber[16];
	
	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"%s %s: ***Received Data from Http Client***\nData is:\n", ctime_buf, phase2str(current_phase));
	fprintf(tunLogPtr,"%s", pReqData);

	memset(aNumber,0,sizeof(aNumber));

	if (strstr(pReqData,"GET /-t"))
	{
		//Apply tuning
		strcpy(aResp,"Recommended Tuning applied!!!\n");
	
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to apply recommended Tuning***\n", ctime_buf, phase2str(current_phase));
		fprintf(tunLogPtr,"%s %s: ***Applying recommended Tuning now***\n", ctime_buf, phase2str(current_phase));
		sprintf(aHttpRequest,"sh ./user_menu.sh apply_all_recommended_settings");
		system(aHttpRequest);
		goto after_check;
	}

	if (strstr(pReqData,"GET /-d#"))
	{
		int vNewDebugLevel = 0;
		/* Change debug level of Tuning Module */
		char *p = (pReqData + sizeof("GET /-d#")) - 1;
		if (isdigit(*p))
		{
			aNumber[count] = *p;
		}
	
		vNewDebugLevel = atoi(aNumber);
		sprintf(aResp,"Changed debug level of Tuning Module from %d to %d!\n", vDebugLevel, vNewDebugLevel);
		
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to change debug level of Tuning Module from %d to %d***\n", ctime_buf, phase2str(current_phase), vDebugLevel, vNewDebugLevel);
		vDebugLevel = vNewDebugLevel;
		if (vDebugLevel > 1 && src_ip_addr.y)
		{
			Pthread_mutex_lock(&dtn_mutex);
        		strcpy(test.msg, "Hello there!!!\n");
        		test.len = htonl(sleep_count);
        		cdone = 1;
        		Pthread_cond_signal(&dtn_cond);
        		Pthread_mutex_unlock(&dtn_mutex);
		}

		fprintf(tunLogPtr,"%s %s: ***New debug level is %d***\n", ctime_buf, phase2str(current_phase), vDebugLevel);
		goto after_check;
	}

	if (strstr(pReqData,"GET /-ct#flow_sink#"))
	{
		/* Change the value of the flow sink time delta */
		__u32 vNewFlowSinkTimeDelta = 0;
		char *p = (pReqData + sizeof("GET /-ct#flow_sink#")) - 1;
		while (isdigit(*p))
		{
			aNumber[count++] = *p;
			p++;
		}

		vNewFlowSinkTimeDelta = strtoul(aNumber, (char **)0, 10);
		sprintf(aResp,"Changed flow sink time delta from %u to %u!\n", vFLOW_SINK_TIME_DELTA, vNewFlowSinkTimeDelta);
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to change flow sink time delta from %u to %u***\n", ctime_buf, phase2str(current_phase), vFLOW_SINK_TIME_DELTA, vNewFlowSinkTimeDelta);
		vFLOW_SINK_TIME_DELTA = vNewFlowSinkTimeDelta;
		fprintf(tunLogPtr,"%s %s: ***New flow sink time delta value is *%u***\n", ctime_buf, phase2str(current_phase), vFLOW_SINK_TIME_DELTA);
		goto after_check;
	}
			
	if (strstr(pReqData,"GET /-ct#q_occ#"))
	{
		/* Change the value of the queue occupancy delta */
		__u32 vNewQueueOccupancyDelta = 0;
		char *p = (pReqData + sizeof("GET /-ct#q_occ#")) - 1;
		while (isdigit(*p))
		{
			aNumber[count++] = *p;
			p++;
		}

		vNewQueueOccupancyDelta = strtoul(aNumber, (char **)0, 10);
		sprintf(aResp,"Changed queue occupancy delta from %u to %u!\n", vQUEUE_OCCUPANCY_DELTA, vNewQueueOccupancyDelta);
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to change queue occupancy delta from %u to %u***\n", ctime_buf, phase2str(current_phase), vQUEUE_OCCUPANCY_DELTA, vNewQueueOccupancyDelta);
		vQUEUE_OCCUPANCY_DELTA = vNewQueueOccupancyDelta;
		fprintf(tunLogPtr,"%s %s: ***New queue occupancy delta value is *%u***\n", ctime_buf, phase2str(current_phase), vQUEUE_OCCUPANCY_DELTA);
		goto after_check;
	}
			
	if (strstr(pReqData,"GET /-ct#hop_late#"))
	{
		/* Change the value of the hop latency delta */
		__u32 vNewHopLatencyDelta = 0;
		char *p = (pReqData + sizeof("GET /-ct#hop_late#")) - 1;
		while (isdigit(*p))
		{
			aNumber[count++] = *p;
			p++;
		}

		vNewHopLatencyDelta = strtoul(aNumber, (char **)0, 10);
		sprintf(aResp,"Changed hop latency delta from %u to %u!\n", vHOP_LATENCY_DELTA, vNewHopLatencyDelta);
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to change hop latency delta from %u to %u***\n", ctime_buf, phase2str(current_phase), vHOP_LATENCY_DELTA, vNewHopLatencyDelta);
		vHOP_LATENCY_DELTA = vNewHopLatencyDelta;
		fprintf(tunLogPtr,"%s %s: ***New hop latency delta value is *%u***\n", ctime_buf, phase2str(current_phase), vHOP_LATENCY_DELTA);
		goto after_check;
	}
			
	if (strstr(pReqData,"GET /-ct#flow_late#"))
	{
		/* Change the value of the flow latency delta */
		__u32 vNewFlowLatencyDelta = 0;
		char *p = (pReqData + sizeof("GET /-ct#flow_late#")) - 1;
		while (isdigit(*p))
		{
			aNumber[count++] = *p;
			p++;
		}

		vNewFlowLatencyDelta = strtoul(aNumber, (char **)0, 10);
		sprintf(aResp,"Changed flow latency delta from %u to %u!\n", vFLOW_LATENCY_DELTA, vNewFlowLatencyDelta);
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to change flow latency delta from %u to %u***\n", ctime_buf, phase2str(current_phase), vFLOW_LATENCY_DELTA, vNewFlowLatencyDelta);
		vFLOW_LATENCY_DELTA = vNewFlowLatencyDelta;
		fprintf(tunLogPtr,"%s %s: ***New flow latency delta value is *%u***\n", ctime_buf, phase2str(current_phase), vFLOW_LATENCY_DELTA);
		goto after_check;
	}
			
	if (strstr(pReqData,"GET /-b#rx#"))
	{
		/* Change rx ring buffer size */
		char *p = (pReqData + sizeof("GET /-b#rx#")) - 1;
		while (isdigit(*p))
		{
			aNumber[count++] = *p;
			p++;
		}


		sprintf(aResp,"Changed rx ring buffer size of %s to %s!\n", netDevice, aNumber);
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to change RX ring buffer size of %s to %s***\n", ctime_buf, phase2str(current_phase), netDevice, aNumber);
		fprintf(tunLogPtr,"%s %s: ***Changing RX buffer size now***\n", ctime_buf, phase2str(current_phase));
		sprintf(aSettingFromHttp,"ethtool -G %s rx %s", netDevice, aNumber);
		
		fprintf(tunLogPtr,"%s %s: ***Doing *%s***\n", ctime_buf, phase2str(current_phase), aSettingFromHttp);
		system(aSettingFromHttp);
		goto after_check;
	}
			
	if (strstr(pReqData,"GET /-b#tx#"))
	{
		/* Change tx ring buffer size */
		char *p = (pReqData + sizeof("GET /-b#tx#")) - 1;
		while (isdigit(*p))
		{
			aNumber[count++] = *p;
			p++;
		}

		sprintf(aResp,"Changed tx ring buffer size of %s to %s!\n", netDevice, aNumber);
		
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to change TX ring buffer size of %s to %s***\n", ctime_buf, phase2str(current_phase), netDevice, aNumber);
		fprintf(tunLogPtr,"%s %s: ***Changing TX buffer size now***\n", ctime_buf, phase2str(current_phase));
		sprintf(aSettingFromHttp,"ethtool -G %s tx %s", netDevice, aNumber);
		
		fprintf(tunLogPtr,"%s %s: ***Doing *%s***\n", ctime_buf, phase2str(current_phase), aSettingFromHttp);
		system(aSettingFromHttp);
		goto after_check;
	}

	if (strstr(pReqData,"GET /-b#sock_rx_buff#"))
	{
		/* Change OS receive buffer size */
		char *p = (pReqData + sizeof("GET /-b#sock_rx_buff#")) - 1;
		while (isdigit(*p))
		{
			aNumber[count++] = *p;
			p++;
		}

		sprintf(aResp,"Changed the maximum OS receive buffer size for all types of connections to %s!\n", aNumber);
		
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to change the maximum OS receive buffer size for all types of connections to %s***\n", ctime_buf, phase2str(current_phase), aNumber);
		fprintf(tunLogPtr,"%s %s: ***Changing receive buffer size now***\n", ctime_buf, phase2str(current_phase));
		sprintf(aSettingFromHttp,"sysctl -w net.core.rmem_max=%s", aNumber);
		
		fprintf(tunLogPtr,"%s %s: ***Doing *%s***\n", ctime_buf, phase2str(current_phase), aSettingFromHttp);
		system(aSettingFromHttp);
		goto after_check;
	}

	if (strstr(pReqData,"GET /-b#sock_tx_buff#"))
	{
		/* Change OS send buffer size */
		char *p = (pReqData + sizeof("GET /-b#sock_tx_buff#")) - 1;
		while (isdigit(*p))
		{
			aNumber[count++] = *p;
			p++;
		}

		sprintf(aResp,"Changed the maximum OS send buffer size for all types of connections to %s!\n", aNumber);
		
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to change the maximum OS send buffer size for all types of connections to %s***\n", ctime_buf, phase2str(current_phase), aNumber);
		fprintf(tunLogPtr,"%s %s: ***Changing send buffer size now***\n", ctime_buf, phase2str(current_phase));
		sprintf(aSettingFromHttp,"sysctl -w net.core.wmem_max=%s", aNumber);
		
		fprintf(tunLogPtr,"%s %s: ***Doing *%s***\n", ctime_buf, phase2str(current_phase), aSettingFromHttp);
		system(aSettingFromHttp);
		goto after_check;
	}

	{
		strcpy(aResp,"Received something else!!!\n");
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received some kind of request from Http Client***\n", ctime_buf, phase2str(current_phase));
		fprintf(tunLogPtr,"%s %s: ***Applying some kind of request***\n", ctime_buf, phase2str(current_phase));
		/* fall thru */
	}

after_check:

	fflush(tunLogPtr);
return;
}

/* TODO: edit this function to handle HTTP data and answer Websocket requests.*/
static void on_http_request(http_s *h) 
{
	char aTheResp[512];	
  	check_req(h, aTheResp);
	/* set the response and send it (finnish vs. destroy). */
  	http_send_body(h, aTheResp, strlen(aTheResp));
}

/* starts a listeninng socket for HTTP connections. */
void initialize_http_service(void) 
{
	time_t clk;
	char ctime_buf[27];
  	char aListenPort[32];	

	/* listen for inncoming connections */
	sprintf(aListenPort,"%d",gAPI_listen_port);
	if (http_listen(aListenPort, NULL, .on_request = on_http_request) == -1) 
	{
    		/* listen failed ?*/
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***ERROR: facil couldn't initialize HTTP service (already running?)...***\n", ctime_buf, phase2str(current_phase));
		return;
  	}
#if 0
  if (http_listen(fio_cli_get("-p"), fio_cli_get("-b"),
                  .on_request = on_http_request,
                  .max_body_size = fio_cli_get_i("-maxbd") * 1024 * 1024,
                  .ws_max_msg_size = fio_cli_get_i("-max-msg") * 1024,
                  .public_folder = fio_cli_get("-public"),
                  .log = fio_cli_get_bool("-log"),
                  .timeout = fio_cli_get_i("-keep-alive"),
                  .ws_timeout = fio_cli_get_i("-ping")) == -1) {
    /* listen failed ?*/
    perror("ERROR: facil couldn't initialize HTTP service (already running?)");
    exit(1);
  }
#endif
}

void * fDoRunHttpServer(void * vargp)
{
	//int * fd = (int *) vargp;
	time_t clk;
	char ctime_buf[27];

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"%s %s: ***Starting Http Server ...***\n", ctime_buf, phase2str(current_phase));
	fflush(tunLogPtr);
	initialize_http_service();
	/* start facil */
	fio_start(.threads = 1, .workers = 0);
	return ((char *)0);
}

void * fDoRunGetThresholds(void * vargp)
{
	//int * fd = (int *) vargp;
	time_t clk;
	char ctime_buf[27];
	
	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"%s %s: ***Starting Check Threshold thread ...***\n", ctime_buf, phase2str(current_phase));
	fflush(tunLogPtr);
	char buffer[128];
	FILE *pipe;
	int before = 0;
	int now = 0;
	time_t secs_passed = 1;
	unsigned long rx_missed_errs_before, rx_missed_errs_now, rx_missed_errs_tot;
	unsigned long rx_before, rx_now, rx_bytes_tot;
	unsigned long tx_before, tx_now, tx_bytes_tot;
	char try[1024];
	int stage = 0;

	rx_missed_errs_before = rx_missed_errs_now = rx_missed_errs_tot = 0;
	rx_before =  rx_now = rx_bytes_tot = rx_bits_per_sec = 0;
	tx_before =  tx_now =  tx_bytes_tot = tx_bits_per_sec = 0;

	sprintf(try,"bpftrace -e \'BEGIN { @name;} kprobe:dev_get_stats { $nd = (struct net_device *) arg0; @name = $nd->name; } kretprobe:dev_get_stats /@name == \"%s\"/ { $rtnl = (struct rtnl_link_stats64 *) retval; $rx_bytes = $rtnl->rx_bytes; $tx_bytes = $rtnl->tx_bytes; $rx_missed_errors = $rtnl->rx_missed_errors; printf(\"%s %s %s\\n\", $tx_bytes, $rx_bytes, $rx_missed_errors); time(\"%s\"); exit(); } END { clear(@name); }\'",netDevice,"%lu","%lu","%lu","%S");
	/* fix for kfunc below too */
	/*sprintf(try,"bpftrace -e \'BEGIN { @name;} kfunc:dev_get_stats { $nd = (struct net_device *) args->dev; @name = $nd->name; } kretfunc:dev_get_stats /@name == \"%s\"/ { $nd = (struct net_device *) args->dev; $rtnl = (struct rtnl_link_stats64 *) args->storage; $rx_bytes = $rtnl->rx_bytes; $tx_bytes = $rtnl->tx_bytes; printf(\"%s %s\\n\", $tx_bytes, $rx_bytes); time(\"%s\"); exit(); } END { clear(@name); }\'",netDevice,"%lu","%lu","%S");*/

start:
	secs_passed = 0;
	//before = time((time_t *)0);
	pipe = popen(try,"r");
	if (!pipe)
	{
		printf("popen failed!\n");
		return ((char *) 0);
	}
	// read for 2 lines of process:
	while (!feof(pipe))
	{
		// use buffer to read and add to result
		if (fgets(buffer, 128, pipe) != NULL);
		else
			{
				printf("Not working****\n");
				return ((char *) 0);
			}

 		if (fgets(buffer, 128, pipe) != NULL)
		{
			sscanf(buffer,"%lu %lu %lu", &tx_before, &rx_before, &rx_missed_errs_before);
			fgets(buffer, 128, pipe);
			sscanf(buffer,"%d", &before);
			pclose(pipe);

			//sleep(1);
			pipe = popen(try,"r");
			if (!pipe)
			{
				printf("popen failed!\n");
				return ((char *) 0);
			}
			//now = time((time_t *)0);
			stage = 1;
			break;
		}
		else
			{
				printf("Not working****\n");
				return ((char *) 0);
			}
	}

	while (!feof(pipe) && stage)
	{
		// use buffer to read and add to result
		if (fgets(buffer, 128, pipe) != NULL);
		else
			{
				printf("Not working****\n");
				return ((char *) 0);
			}
		if (fgets(buffer, 128, pipe) != NULL)
		{
			sscanf(buffer,"%lu %lu %lu", &tx_now, &rx_now, &rx_missed_errs_now);
			fgets(buffer, 128, pipe);
			sscanf(buffer,"%d", &now);

			tx_bytes_tot =  tx_now - tx_before;
			rx_bytes_tot =  rx_now - rx_before;
			rx_missed_errs_tot = rx_missed_errs_now - rx_missed_errs_before; 

			if (now < before) //seconds started over
			{
				secs_passed = (60 - before) + now;
			}
			else
				secs_passed = now - before;

			if (!secs_passed) 
				secs_passed = 1;
#if 1
			tx_bits_per_sec = ((8 * tx_bytes_tot) / 1024) / secs_passed;
			rx_bits_per_sec = ((8 * rx_bytes_tot) / 1024) / secs_passed;;
			pclose(pipe);

			if (vDebugLevel > 2)
			{
				printf("DEV %s: TX : %lu kb/s RX : %lu kb/s, RX_MISD_ERRS/s : %lu, secs_passed %lu\n", netDevice, tx_bits_per_sec, rx_bits_per_sec, rx_missed_errs_tot/secs_passed, secs_passed);
			}
			break;
}
#else
			tx_bits_per_sec = ((tx_bytes_tot) / 1024) / secs_passed; //really bytes per sec
			rx_bits_per_sec = ((rx_bytes_tot) / 1024) / secs_passed; //really bytes per sec
			pclose(pipe);
			printf("RX eno2: %lu KB/s TX eno2: %lu KB/s\n", rx_bits_per_sec, tx_bits_per_sec);
//			stage = 0;
			break;
#endif
			else
				{
					printf("Not working****\n");
					return ((char *) 0);
				}
		}

		if (stage)
		{
			stage = 0;
			goto start;
		}

		printf("Problems*** stage not set...\n");

return ((char *) 0);
}

void * fDoRunFindHighestRtt(void * vargp)
{
	//int * fd = (int *) vargp;
	time_t clk;
	char ctime_buf[27];
	char buffer[128];
	FILE *pipe;
	char try[1024];
	unsigned long rtt = 0, highest_rtt = 0;

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"%s %s: ***Starting Finding Highest RTT thread ...***\n", ctime_buf, phase2str(current_phase));
	fflush(tunLogPtr);
        
	sprintf(try,"sudo bpftrace -e \'BEGIN { @ca_rtt_us;} kprobe:tcp_ack_update_rtt { @ca_rtt_us = arg4; } kretprobe:tcp_ack_update_rtt /pid != 0/ { printf(\"%s\\n\", @ca_rtt_us); } interval:s:5 {  exit(); } END { clear(@ca_rtt_us); }\'", "%lu");

rttstart:
		highest_rtt = 0;
		pipe = popen(try,"r");
		if (!pipe)
		{
			printf("popen failed!\n");
			return (char *) -1;
		}

		//get the first line and forget about it
		if (fgets(buffer, 128, pipe) != NULL);
		else
		{
			printf(" Not finished****\n");
			pclose(pipe);
			return (char *) -2;
		}

		// read until process exits after "interval" seconds above
		while (!feof(pipe))
		{
			// use buffer to read and add to result
			if (fgets(buffer, 128, pipe) != NULL);
			else
			{
				goto finish_up;
				return (char *)-2;
			}
			sscanf(buffer,"%lu", &rtt);
			if (rtt > highest_rtt)
				highest_rtt = rtt;

			if (vDebugLevel > 3)
				printf("**rtt = %luus, highest rtt = %luus\n",rtt, highest_rtt);
		}
finish_up:
		pclose(pipe);

		if (highest_rtt)
		{
			if (vDebugLevel > 2)
				printf("***highest rtt is %.3fms\n", highest_rtt/(double)1000);
		}

		sleep(3); //check again in 3 secs
		goto rttstart;

return ((char *) 0);
}

void * fDoRunHelperDtn(void * vargp)
{
	time_t clk;
	char ctime_buf[27];
	struct stat sb;

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"%s %s: ***Starting HelperDtn thread ...***\n", ctime_buf, phase2str(current_phase));
	fflush(tunLogPtr);
	//check if already running
	system("ps -ef | grep -v grep | grep help_dtn.sh  > /tmp/help_dtn_alive.out 2>/dev/null");
	stat("/tmp/help_dtn_alive.out", &sb);
	if (sb.st_size == 0); //good - no runaway process
	else //kill it
	{
		printf("Killing runaway help_dtn.sh process\n");
		system("pkill -9 help_dtn.sh");
	}

	system("rm -f /tmp/help_dtn_alive.out");
	sleep(1); //relax

restart_vfork:
	printf("About to fork new help_dtn.sh process\n");
	pid_t pid = vfork();
	if (pid == 0)
	{
		if (execlp("./help_dtn.sh", "help_dtn.sh", netDevice, (char*) NULL) == -1)
		{
			perror("Could not execlp");
			exit(-1);;
		}
	}
#if 0
	else
		{
			printf("I'm the parent process; the child got pid %d.\n", pid);
			//  return 0;
		}
#endif

	while (1)
	{
		sleep(5); //check every 5 seconds to see if process alive
		system("ps -ef | grep -v grep | grep -v defunct | grep help_dtn.sh  > /tmp/help_dtn_alive.out 2>/dev/null");
		stat("/tmp/help_dtn_alive.out", &sb);
		if (sb.st_size == 0) //process died, restart it
		{
			int status;
			system("rm -f /tmp/help_dtn_alive.out");
			wait(&status);
			goto restart_vfork;
		}

		system("rm -f /tmp/help_dtn_alive.out");
	}

return ((char *) 0);
}

void sig_chld_handler(int signum)
{
        pid_t pid;
        int stat;

        while ( (pid = waitpid(-1, &stat, WNOHANG)) > 0)
                printf("Child %d terminated\n", pid);

        return;
}

void catch_sigchld()
{
        static struct sigaction act;

        memset(&act, 0, sizeof(act));

        act.sa_handler = sig_chld_handler;
        sigemptyset(&act.sa_mask); //no additional signals will be blocked
        act.sa_flags = 0;

        sigaction(SIGCHLD, &act, NULL);
}

void ignore_sigchld()
{
	int sigret;
	static struct sigaction act;
        memset(&act, 0, sizeof(act));

        act.sa_handler = SIG_IGN;;
        sigemptyset(&act.sa_mask); //no additional signals will be blocked
        act.sa_flags = 0;

        sigret = sigaction(SIGCHLD, &act, NULL);
	if (sigret == 0)
		printf("SIGCHLD ignored***\n");
	else
		printf("SIGCHLD not ignored***\n");
	
	return;
}


ssize_t                                         /* Read "n" bytes from a descriptor. */
readn(int fd, void *vptr, size_t n)
{
        size_t  nleft;
        ssize_t nread;
        char    *ptr;

        ptr = vptr;
        nleft = n;
        while (nleft > 0) {
                if ( (nread = read(fd, ptr, nleft)) < 0) {
                        if (errno == EINTR)
                                nread = 0;              /* and call read() again */
                        else
                                return(-1);
                } else if (nread == 0)
                        break;                          /* EOF */

                nleft -= nread;
                ptr   += nread;
        }
        return(n - nleft);              /* return >= 0 */
}
/* end readn */

ssize_t
Readn(int fd, void *ptr, size_t nbytes)
{
        ssize_t         n;

        if ( (n = readn(fd, ptr, nbytes)) < 0)
                err_sys("readn error");
        return(n);
}

void
process_request(int sockfd)
{
	ssize_t                 n;
	struct args             from_cli;
	time_t clk;
	char ctime_buf[27];

	for ( ; ; ) 
	{
		if ( (n = Readn(sockfd, &from_cli, sizeof(from_cli))) == 0)
			return;         /* connection closed by other end */

		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received message %d from destination DTN...***\n", ctime_buf, phase2str(current_phase), ntohl(from_cli.len));
		fflush(tunLogPtr);
		printf("arg len = %d, arg buf = %s", ntohl(from_cli.len), from_cli.msg);
	}
}

void * fDoRunGetMessageFromPeer(void * vargp)
{
	time_t clk;
	char ctime_buf[27];
	int listenfd, connfd;
	pid_t childpid;
	socklen_t clilen;
	struct sockaddr_in cliaddr, servaddr;
	
	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"%s %s: ***Starting Listener for receiving messages destination DTN...***\n", ctime_buf, phase2str(current_phase));
	fflush(tunLogPtr);
	
	listenfd = Socket(AF_INET, SOCK_STREAM, 0);

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family      = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port        = htons(gSource_Dtn_Port);

	Bind(listenfd, (SA *) &servaddr, sizeof(servaddr));
	Listen(listenfd, LISTENQ);
	
	for ( ; ; ) 
	{
		clilen = sizeof(cliaddr);
		if ( (connfd = accept(listenfd, (SA *) &cliaddr, &clilen)) < 0) 
		{
			if (errno == EINTR)
				continue;  /* back to for() */
			else
				err_sys("accept error");
		}
        	
		if ( (childpid = Fork()) == 0) 
		{        /* child process */
			Close(listenfd); /* close listening socket */
			process_request(connfd);/* process the request */
			exit(0);
		}
		
		Close(connfd); /* parent closes connected socket */
	}

	return ((char *)0);
}

void read_sock(int sockfd)
{
	ssize_t                 n;
	struct args             from_cli;

	for ( ; ; ) 
	{
		if ( (n = Readn(sockfd, &from_cli, sizeof(from_cli))) == 0)
			return;         /* connection closed by other end */

		printf("arg len = %d, arg buf = %s", from_cli.len, from_cli.msg);
	}
}

void str_cli(int sockfd, struct args *this_test) //str_cli09
{
	Writen(sockfd, this_test, sizeof(struct args));
	return;
}

void * fDoRunSendMessageToPeer(void * vargp)
{
	time_t clk;
	char ctime_buf[27];
	int sockfd;
	struct sockaddr_in servaddr;
	struct args test2;
	int check = 0;

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"%s %s: ***Starting Client for sending messages to source DTN...***\n", ctime_buf, phase2str(current_phase));
	fflush(tunLogPtr);

cli_again:
	Pthread_mutex_lock(&dtn_mutex);
	
	while(cdone == 0)
		Pthread_cond_wait(&dtn_cond, &dtn_mutex);
	memcpy(&test2,&test,sizeof(test2));
	cdone = 0;
	Pthread_mutex_unlock(&dtn_mutex);

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"%s %s: ***Sending message %d to source DTN...***\n", ctime_buf, phase2str(current_phase), sleep_count);
	fflush(tunLogPtr);

	sockfd = Socket(AF_INET, SOCK_STREAM, 0);

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(gSource_Dtn_Port);
	if (src_ip_addr.y)
	{
		sprintf(aSrc_Ip,"%u.%u.%u.%u", src_ip_addr.a[0], src_ip_addr.a[1], src_ip_addr.a[2], src_ip_addr.a[3]);
		Inet_pton(AF_INET, aSrc_Ip, &servaddr.sin_addr);
	}
	else
	{
		fprintf(stdout, "Source (Peer) IP address is zero. Can't connect to it****\n");
		goto cli_again;
	}

	if (Connect(sockfd, (SA *) &servaddr, sizeof(servaddr)))
	{
		goto cli_again;
	}

	str_cli(sockfd, &test2);         /* do it all */
	check = shutdown(sockfd, SHUT_WR);
//	close(sockfd); - use shutdown instead of close
	if (!check)
		read_sock(sockfd); //final read to wait on close from other end
	else
		printf("shutdown failed, check = %d\n",check);

	sleep_count++;
	goto cli_again;

return ((char *)0);
}

int main(int argc, char **argv) 
{
	int vRetFromRunBpfThread, vRetFromRunBpfJoin;
	int vRetFromRunHttpServerThread, vRetFromRunHttpServerJoin;
	int vRetFromRunGetThresholdsThread, vRetFromRunGetThresholdsJoin;
	int vRetFromRunHelperDtnThread, vRetFromRunHelperDtnJoin;
	int vRetFromRunFindHighestRttThread, vRetFromRunFindHighestRttJoin;
	int vRetFromRunGetMessageFromPeerThread, vRetFromRunGetMessageFromPeerJoin;
	int vRetFromRunSendMessageToPeerThread, vRetFromRunSendMessageToPeerJoin;
	pthread_t doRunBpfCollectionThread_id, doRunHttpServerThread_id, doRunGetThresholds_id, doRunHelperDtn_id;
	pthread_t doRunFindHighestRttThread_id, doRunGetMessageFromPeerThread_id, doRunSendMessageToPeerThread_id;;
	sArgv_t sArgv;
	time_t clk;
	char ctime_buf[27];
	 
	ignore_sigchld(); //won't leave zombie processes

	sArgv.argc = argc;
	sArgv.argv = argv;
	
	catch_sigint();

	system("sh ./user_menu.sh"); //make backup of tuningLog first if already exist
	tunLogPtr = fopen("/tmp/tuningLog","w");
	if (!tunLogPtr)
	{
		printf("Could not open tuning Logfile, exiting...\n");
		exit(-1);
	}

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr, "%s %s: tuning Log opened***\n", ctime_buf, phase2str(current_phase));

	if (argc == 3)
		strcpy(netDevice,argv[2]);
	else
		{
			gettime(&clk, ctime_buf);
			fprintf(tunLogPtr, "%s %s: Device name not supplied, exiting***\n", ctime_buf, phase2str(current_phase));
			exit(-3);
		}
		
	user_assess(argc, argv);
	fCheck_log_limit();
	
	gettime(&clk, ctime_buf);
	current_phase = LEARNING;

	memset(sFlowCounters,0,sizeof(sFlowCounters));
	memset(aSrc_Ip,0,sizeof(aSrc_Ip));
	src_ip_addr.y = 0;

	fflush(tunLogPtr);

	//Start Collector Thread - collect from int-sink
	vRetFromRunBpfThread = pthread_create(&doRunBpfCollectionThread_id, NULL, fDoRunBpfCollectionPerfEventArray2, &sArgv);
	//Start Http server Thread	
	vRetFromRunHttpServerThread = pthread_create(&doRunHttpServerThread_id, NULL, fDoRunHttpServer, &sArgv);
	//Start Threshhold monitoring	
	vRetFromRunGetThresholdsThread = pthread_create(&doRunGetThresholds_id, NULL, fDoRunGetThresholds, &sArgv); 
	//Start Helper functioning	
	vRetFromRunHelperDtnThread = pthread_create(&doRunHelperDtn_id, NULL, fDoRunHelperDtn, &sArgv); 
	//Start Rtt monitoring
	vRetFromRunFindHighestRttThread = pthread_create(&doRunFindHighestRttThread_id, NULL, fDoRunFindHighestRtt, &sArgv); 
	//Listen for messages from destination DTN
	vRetFromRunGetMessageFromPeerThread = pthread_create(&doRunGetMessageFromPeerThread_id, NULL, fDoRunGetMessageFromPeer, &sArgv); 
	//Send messages to source DTN
	vRetFromRunSendMessageToPeerThread = pthread_create(&doRunSendMessageToPeerThread_id, NULL, fDoRunSendMessageToPeer, &sArgv); 

	if (vRetFromRunBpfThread == 0)
    		vRetFromRunBpfJoin = pthread_join(doRunBpfCollectionThread_id, NULL);
	
	if (vRetFromRunHttpServerThread == 0)
    		vRetFromRunHttpServerJoin = pthread_join(doRunHttpServerThread_id, NULL);
	
	if (vRetFromRunGetThresholdsThread == 0)
    		vRetFromRunGetThresholdsJoin = pthread_join(doRunGetThresholds_id, NULL);

	if (vRetFromRunHelperDtnThread == 0)
    		vRetFromRunHelperDtnJoin = pthread_join(doRunHelperDtn_id, NULL);

	if (vRetFromRunFindHighestRttThread == 0)
    		vRetFromRunFindHighestRttJoin = pthread_join(doRunFindHighestRttThread_id, NULL);
	
	if (vRetFromRunGetMessageFromPeerThread == 0)
    		vRetFromRunGetMessageFromPeerJoin = pthread_join(doRunGetMessageFromPeerThread_id, NULL);

	if (vRetFromRunSendMessageToPeerThread == 0)
    		vRetFromRunSendMessageToPeerJoin = pthread_join(doRunSendMessageToPeerThread_id, NULL);

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr, "%s %s: Closing tuning Log***\n", ctime_buf, phase2str(current_phase));
	fclose(tunLogPtr);

return 0;
}

