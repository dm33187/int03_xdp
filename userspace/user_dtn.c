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

FILE * tunLogPtr = 0;
FILE * csvLogPtr = 0;

void gettime(time_t *clk, char *ctime_buf)
{
	*clk = time(NULL);
	ctime_r(clk,ctime_buf);
	ctime_buf[24] = ':';
}

void open_csv_file(void);
void open_csv_file(void)
{
	time_t clk;
	char ctime_buf[27];

	csvLogPtr = fopen("/tmp/csvTuningLog","w");
	if (!csvLogPtr)
	{
		printf("Could not open CSV Logfile, exiting...\n");
		exit(-1);
	}

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr, "%s %s: CSV Log file /tmp/csvTuningLog also opened***\n", ctime_buf, phase2str(current_phase));

	fprintf(csvLogPtr,"delta,name,value\n");
	fflush(csvLogPtr);

	return;
}

static time_t now_time = 0;
static time_t last_time = 0;
time_t calculate_delta_for_csv(void);
time_t calculate_delta_for_csv(void)
{
	time_t vTime;

	if (now_time == 0) //first time thru
	{
		now_time = time(&vTime);
		return 0;
	}
	else
	{
		last_time = now_time;
		now_time = time(&vTime);
		return (now_time - last_time);
	}
}

pthread_mutex_t dtn_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t dtn_cond = PTHREAD_COND_INITIALIZER;
static int cdone = 0;
static unsigned int sleep_count = 5;
static double vGoodBitrateValue = 0.0;
struct args test;
char aSrc_Ip[32];
union uIP {
	 __u32 y;
       	 unsigned char  a[4];
};

static union uIP src_ip_addr;

void qOCC_Hop_TimerID_Handler(int signum, siginfo_t *info, void *ptr);
static void timerHandler( int sig, siginfo_t *si, void *uc );

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

/* my_usleep(): Sleep for the requested number of microseconds. */
int my_usleep(long usec)
{
        struct timespec ts;
        int res;
        long sec = usec / 1000000;
	long nsec = (usec % 1000000) * 1000;

        if (usec < 0)
        {
                errno = EINVAL;
                return -1;
        }

        ts.tv_sec = sec;
        ts.tv_nsec = nsec;

        do {
                res = nanosleep(&ts, &ts);
        } while (res && errno == EINTR);

        return res;
}

char netDevice[128];
static unsigned long rx_kbits_per_sec = 0, tx_kbits_per_sec = 0;
//vDebugLevel (Default = 0)
//= 0 - only applied tuning, error and important messages get written to log file unconditionally
//= 1 - include suggested tuning
//= 2 - include additional learning messages which provide window into decision making
//= 3 - include still more learning messages which provide window into decision making
//= 4 - include data from INT sink
//= 5 - include additional sink data logging
//= 6 - include additional information about the link
//>=7 - include everything else
static int vDebugLevel = 0;

#define SIGINT_MSG "SIGINT received.\n"
void sig_int_handler(int signum, siginfo_t *info, void *ptr)
{
	write(STDERR_FILENO, SIGINT_MSG, sizeof(SIGINT_MSG));
	fprintf(tunLogPtr,"Caught SIGINT, exiting...\n");
	fclose(tunLogPtr);

	if (csvLogPtr)
		fclose(csvLogPtr);
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
#define MAX_SIZE_TUNING_STRING		1500
#define NUM_OF_FLOWS_TO_KEEP_TRACK_OF	4
typedef struct {
        int num_tuning_activities;
	int gFlowCountUsed;
	char what_was_done[MAX_TUNING_ACTIVITIES_PER_FLOW][MAX_SIZE_TUNING_STRING];
} sFlowCounters_t;

static __u32 flow_sink_time_threshold = 0;
static __u32 Qinfo = 0;
static __u32 ingress_time = 0;
static __u32 egress_time = 0;
static __u32 hop_hop_latency_threshold = 0;
static __u32 curr_hop_key_hop_index = 0;
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
void record_activity(char * pActivity); 

#define SIGALRM_MSG "SIGALRM received.\n"
int vTimerIsSet = 0;

void qOCC_Hop_TimerID_Handler(int signum, siginfo_t *info, void *ptr)
{
	time_t clk;
	char ctime_buf[27];
	char activity[MAX_SIZE_TUNING_STRING];
	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr, "%s %s: ***Timer Alarm went off*** still having problems with Queue Occupancy and HopDelays. Time to do something***\n",ctime_buf, phase2str(current_phase)); 
	//***Do something here ***//
	vTimerIsSet = 0;
	sprintf(activity,"%s %s: ***hop_key.hop_index %X, Doing Something",ctime_buf, phase2str(current_phase), curr_hop_key_hop_index);
	record_activity(activity); //make sure activity big enough to concatenate additional data -- see record_activity()
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
		fprintf(tunLogPtr, "%s %s: *qOCC_Hop_TimerID* timer created.\n", ctime_buf, phase2str(current_phase));

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
			if (vDebugLevel > 2)
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

void record_activity(char *pActivity)
{
	char add_to_activity[512];
	time_t clk;
	char ctime_buf[27];

	static __u32 myCount = 0;
	gettime(&clk, ctime_buf);
	sprintf(add_to_activity,"***vFlowcount = %d, num_tuning_activty = %d, myCount = %u",vFlowCount, sFlowCounters[vFlowCount].num_tuning_activities + 1, myCount++);
	strcat(pActivity,add_to_activity);
	//sprintf(activity,"%s %s: ***hop_key.hop_index %X, Doing Something***vFlowcount = %d, num_tuning_activty = %d, myCount = %u", ctime_buf, phase2str(current_phase), curr_hop_key_hop_index, vFlowCount, sFlowCounters[vFlowCount].num_tuning_activities + 1, myCount++);

	if (vDebugLevel > 4)
		fprintf(tunLogPtr,"%s\n",pActivity); //special case for testing - making sure activity is recorded to use with tuncli

	strcpy(sFlowCounters[vFlowCount].what_was_done[sFlowCounters[vFlowCount].num_tuning_activities], pActivity);
	(sFlowCounters[vFlowCount].num_tuning_activities)++;
	if (sFlowCounters[vFlowCount].num_tuning_activities == MAX_TUNING_ACTIVITIES_PER_FLOW)
	{
		sFlowCounters[vFlowCount].num_tuning_activities = 0;
	}

	sFlowCounters[vFlowCount].gFlowCountUsed = 1;	

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

	if (vDebugLevel > 3)
	{
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr, "\n%s %s: ******************************************\n", ctime_buf, phase2str(current_phase));
	}

	while (data + data_offset + sizeof(struct int_hop_metadata) <= data_end)
	{
		struct int_hop_metadata *hop_metadata_ptr = data + data_offset;
		data_offset += sizeof(struct int_hop_metadata);

		Qinfo = ntohl(hop_metadata_ptr->queue_info) & 0xffffff;
		ingress_time = ntohl(hop_metadata_ptr->ingress_time);
		egress_time = ntohl(hop_metadata_ptr->egress_time);
		hop_hop_latency_threshold = egress_time - ingress_time;
		if (vDebugLevel > 3)
		{

//			fprintf(stdout, "switch_id = %u\n",ntohl(hop_metadata_ptr->switch_id));
//			fprintf(stdout, "ingress_port_id = %d\n",ntohs(hop_metadata_ptr->ingress_port_id));
//			fprintf(stdout, "egress_port_id = %d\n",ntohs(hop_metadata_ptr->egress_port_id));
//			fprintf(stdout, "hop_latency = %u\n",ntohl(hop_metadata_ptr->hop_latency));
			fprintf(tunLogPtr, "%s %s: Qinfo = %u\n",ctime_buf, phase2str(current_phase), Qinfo);
			fprintf(tunLogPtr, "%s %s: ingress_time = %u\n",ctime_buf, phase2str(current_phase), ingress_time);
			fprintf(tunLogPtr, "%s %s: egress_time = %u\n",ctime_buf, phase2str(current_phase), egress_time);
			fprintf(tunLogPtr, "%s %s: hop_hop_latency_threshold = %u\n",ctime_buf, phase2str(current_phase), hop_hop_latency_threshold);
//			fprintf(stdout, "sizeof struct int_hop-metadata = %lu\n",sizeof(struct int_hop_metadata));
//			fprintf(stdout, "sizeof struct hop_key = %lu\n",sizeof(struct hop_key));
		}
#if 1
		if ((hop_hop_latency_threshold > vHOP_LATENCY_DELTA) && (Qinfo > vQUEUE_OCCUPANCY_DELTA))
		{
			EvaluateQOcc_and_HopDelay(hop_key.hop_index);
			if (vDebugLevel > 2)
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
					if (vDebugLevel > 3)
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

			if (vDebugLevel > 6)
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

	if (vDebugLevel > 3)
	{
		if (flow_hop_latency_threshold > vFLOW_LATENCY_DELTA)
		{
			gettime(&clk, ctime_buf);
			fprintf(tunLogPtr, "%s %s: ***flow_hop_latency_threshold = %lld\n", ctime_buf, phase2str(current_phase), flow_hop_latency_threshold);
		}

		fflush(tunLogPtr);
	}
#if 0
	if (gFlowCountUsed)
	{	
	//	if (++vFlowCount == NUM_OF_FLOWS_TO_KEEP_TRACK_OF) vFlowCount = 0;
		sFlowCounters[vFlowCount].num_tuning_activities = 0;
		gFlowCountUsed = 0;
	}
#endif			
}

void lost_func(struct threshold_maps *ctx, int cpu, __u64 cnt)
{
	time_t clk;
	char ctime_buf[27];

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr, "%s %s: Missed %llu sets of packet metadata.\n", ctime_buf, phase2str(current_phase), cnt);
	fflush(tunLogPtr);
}
	
void print_flow_key(struct flow_key *key, char ctime_buf[])
{
	//fprintf(stdout, "Flow Key:\n");
	fprintf(tunLogPtr,"%s %s: Flow Key:\n", ctime_buf, phase2str(current_phase));
#if 1
	fprintf(tunLogPtr,"%s %s: \tegress_switch:%X\n", ctime_buf, phase2str(current_phase), key->switch_id);
	fprintf(tunLogPtr,"%s %s: \tegress_port:%hu\n", ctime_buf, phase2str(current_phase), key->egress_port);
	fprintf(tunLogPtr,"%s %s: \tvlan_id:%hu\n", ctime_buf, phase2str(current_phase), key->vlan_id);
	//fprintf(stdout, "\tegress_switch:%X\n", key->switch_id);
	//fprintf(stdout, "\tegress_port:%hu\n", key->egress_port);
	//fprintf(stdout, "\tvlan_id:%hu\n", key->vlan_id);

	if (src_ip_addr.y)
		fprintf(tunLogPtr,"%s %s: \tsrc_ip:%u.%u.%u.%u", ctime_buf, phase2str(current_phase), src_ip_addr.a[0],src_ip_addr.a[1],src_ip_addr.a[2],src_ip_addr.a[3]);
	//	fprintf(stdout,"%u.%u.%u.%u", src_ip_addr.a[0], src_ip_addr.a[1], src_ip_addr.a[2], src_ip_addr.a[3]);
#endif
}

void print_hop_key(struct hop_key *key)
{
	time_t clk;
	char ctime_buf[27];
	if (vDebugLevel > 4 )
	{
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: Hop Key:\n", ctime_buf, phase2str(current_phase));
		//fprintf(stdout, "Hop Key:\n");
		print_flow_key(&(key->flow_key), ctime_buf);
		fprintf(tunLogPtr,"  ***hop_index: %X\n", key->hop_index);
		//fprintf(stdout, "\thop_index: %X\n", key->hop_index);
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

	if (strstr(pReqData,"GET /-pc"))
	{
		//Get counters
		int i, g, start = 0;
		for (g = 0; g <= vFlowCount; g++)
		{
			if (g == MAX_TUNING_ACTIVITIES_PER_FLOW) break; //use this untile we can figure out when a new flow starts

			if (sFlowCounters[g].num_tuning_activities == 0 && sFlowCounters[g].gFlowCountUsed)
				strcpy(aResp,sFlowCounters[g].what_was_done[MAX_TUNING_ACTIVITIES_PER_FLOW - 1]);
			else
				if (sFlowCounters[g].num_tuning_activities == 0 && !g) //vFlowCount == 0
				{
					strcpy(aResp,"***No tuning activity has happened so far***\n");
					break;
				}
				else
					if (sFlowCounters[g].num_tuning_activities == 0)  //vFlowCount > 0
						break;
					else
						{
							int num_activities = sFlowCounters[g].num_tuning_activities; //for now as a simple aid with critical sections
							fprintf(stdout,"FlowCount = %d, num_activities = %d\n",g, num_activities);
							for (i = 0; i < num_activities; i++)
							{
								memcpy(aResp+start, sFlowCounters[g].what_was_done[i], strlen(sFlowCounters[g].what_was_done[i]));
								start = start + strlen(sFlowCounters[g].what_was_done[i]);
								aResp[start] = '\n';
								start++;
								fprintf(stdout,"start = %d\n",start);
							}
							aResp[start-1] = 0;
						}
		}

		fprintf(stdout,"%s",aResp);	
		fprintf(stdout,"\n***\n");
		fflush(stdout);

		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to provide counters of tuning activities throughout data transfer***\n", ctime_buf, phase2str(current_phase));
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
		if (vDebugLevel > 2 && src_ip_addr.y)
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
	
	if (strstr(pReqData,"GET /-l#on"))
	{
		/* Put Tuning Module in learning mode */
		char aMode[8];

		if (gTuningMode)
			strcpy(aMode,"off");
		else
			strcpy(aMode,"on");

		sprintf(aResp,"Tuning Module is in learning mode!!!\n");
		
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to change Tuning Module learning mode from %s to on***\n", ctime_buf, phase2str(current_phase), aMode);
		
		gTuningMode = 0;
		fprintf(tunLogPtr,"%s %s: ***Tuning Module is now in learning mode***\n", ctime_buf, phase2str(current_phase));
		goto after_check;
	}

	if (strstr(pReqData,"GET /-l#off"))
	{
		/* Put Tuning Module in tuning mode */
		char aMode[8];

		if (gTuningMode)
			strcpy(aMode,"off");
		else
			strcpy(aMode,"on");

		sprintf(aResp,"Tuning Module has turned off learning mode!!!\n");
		
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to change Tuning Module learning mode from %s to off***\n", ctime_buf, phase2str(current_phase), aMode);
		
		gTuningMode = 1;
		fprintf(tunLogPtr,"%s %s: ***Tuning Module is now *not* in learning mode***\n", ctime_buf, phase2str(current_phase));
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

#define MAX_SIZE_OF_THE_RESPONSE  ((MAX_TUNING_ACTIVITIES_PER_FLOW * MAX_SIZE_TUNING_STRING * NUM_OF_FLOWS_TO_KEEP_TRACK_OF) + (2 * sizeof(int) * NUM_OF_FLOWS_TO_KEEP_TRACK_OF))
/* TODO: edit this function to handle HTTP data and answer Websocket requests.*/
static void on_http_request(http_s *h) 
{
	char aTheResp[MAX_SIZE_OF_THE_RESPONSE];	
	//char aTheResp[4096];	
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

#define BITRATE_INTERVAL 5
#define KTUNING_DELTA	200000
extern int my_tune_max;
void check_if_bitrate_too_low(double average_tx_Gbits_per_sec, int * applied, int * suggested, int * nothing_done, int * tune, char aApplyDefTun[MAX_SIZE_SYSTEM_SETTING_STRING]);
void check_if_bitrate_too_low(double average_tx_Gbits_per_sec, int * applied, int * suggested, int * nothing_done, int * tune, char aApplyDefTun[MAX_SIZE_SYSTEM_SETTING_STRING])
{
	time_t clk;
	char ctime_buf[27];
	char buffer[256];
	FILE *pipe;
	char kernel_parameter[128];
	char equal_sign;
	unsigned int  kminimum;
	int kdefault;
	unsigned int kmaximum;
	static time_t delta = 0;

	gettime(&clk, ctime_buf);
	if (average_tx_Gbits_per_sec < vGoodBitrateValue)
	{

		if (current_phase == TUNING)
		{
			fprintf(tunLogPtr, "%s %s: Trying to tune net.ipv4.tcp_wmem, but already TUNING something else.  Will retry later if still need TUNING***\n",ctime_buf, phase2str(current_phase));

		}
		else
			{
				pipe = popen("sysctl net.ipv4.tcp_wmem","r");
				if (!pipe)
				{
					printf("popen failed!\n");
					return ;
				}
				
				while (!feof(pipe))
				{
 					if (fgets(buffer, 256, pipe) != NULL)
					{
						sscanf(buffer,"%s %c %u %d %u", kernel_parameter, &equal_sign, &kminimum, &kdefault, &kmaximum);
						break;
					}
					else
						{
							printf("***ERROR: problem getting buffer from popen, returning!!!***\n");
							pclose(pipe);
							return ;
						}
				}
				pclose(pipe);

				if (!my_tune_max)
				{
					printf("***ERROR: Strange error. Could not find net.ipv4.tcp_wmem in local database!!!***\n");
					return ;
				}

				if (gTuningMode && current_phase == LEARNING)
				{
					gettime(&clk, ctime_buf);
					current_phase = TUNING;
					//fprintf(tunLogPtr, "%s %s: Changed current phase***\n",ctime_buf, phase2str(current_phase));
					//do something
					if (my_tune_max <= kmaximum) //already high
					{
						if (vDebugLevel > 0)
						{
							//don't apply - just log suggestions - decided to use a debug level here because this file could fill up if user never accepts recommendation
							fprintf(tunLogPtr, "%s %s: ***CURRENT TUNING***: %s*",ctime_buf, phase2str(current_phase), buffer);
							fprintf(tunLogPtr, "%s %s: *** Current Tuning of net.ipv4.tcp_wmem appears sufficient***\n", ctime_buf, phase2str(current_phase));
						}
						
						*nothing_done = 1;
					}
					else
						{
							//char aApplyDefTun[MAX_SIZE_SYSTEM_SETTING_STRING];
							char aApplyDefTunNoStdOut[MAX_SIZE_SYSTEM_SETTING_STRING+32];
							char activity[MAX_SIZE_TUNING_STRING];
							char aName[100];
							char aValue[128];

							sprintf(aName,"net.ipv4.tcp_wmem");
							if (*tune == 1) //apply up
							{
								sprintf(aApplyDefTun,"sysctl -w net.ipv4.tcp_wmem=\"%u %d %u\"", kminimum, kdefault, kmaximum+KTUNING_DELTA);
								sprintf(aValue, "%u %d %u", kminimum, kdefault, kmaximum+KTUNING_DELTA);
							}
							else
								if (*tune == 2)
								{
									if (kmaximum > 600000)
									{
										sprintf(aApplyDefTun,"sysctl -w net.ipv4.tcp_wmem=\"%u %d %u\"", kminimum, kdefault, kmaximum - KTUNING_DELTA);
										sprintf(aValue, "%u %d %u", kminimum, kdefault, kmaximum-KTUNING_DELTA);
									}
									else
										{
								
											fprintf(tunLogPtr, "%s %s: ***Could not apply tuning since the maximum value of wmem would be less than %d...***\n",ctime_buf, phase2str(current_phase), 600000 - KTUNING_DELTA);
											current_phase = LEARNING; //change back phase to LEARNING
											*nothing_done = 1;
											return;	
										}
								}
								else
									if (*tune == 3)
									{
										fprintf(tunLogPtr,"%s %s: ***No better change found. Using ***%s***\n\n", ctime_buf, phase2str(current_phase), aApplyDefTun);
									}
									else
										{
											fprintf(tunLogPtr, "%s %s: ***Could not apply tuning*** invalid value for tune %d***\n",ctime_buf, phase2str(current_phase), *tune);
											current_phase = LEARNING; //change back phase to LEARNING
											*nothing_done = 1;
											return;	
										}

							fprintf(tunLogPtr, "%s %s: ***CURRENT TUNING***: %s",ctime_buf, phase2str(current_phase), buffer);
							strcpy(aApplyDefTunNoStdOut,aApplyDefTun);
							strcat(aApplyDefTunNoStdOut," >/dev/null"); //so it won't print to stderr on console
							system(aApplyDefTunNoStdOut);

							delta = delta + calculate_delta_for_csv();
							fprintf(csvLogPtr,"%lu,%s,%s\n",delta,aName,aValue);
							fflush(csvLogPtr);

							fprintf(tunLogPtr, "%s %s: ***APPLIED TUNING***: %s\n\n",ctime_buf, phase2str(current_phase), aApplyDefTun);

							sprintf(activity,"%s %s: ***ACTIVITY=APPLIED=TUNING***: %s\n",ctime_buf, phase2str(current_phase), aApplyDefTun);
							record_activity(activity); //make sure activity big enough to concatenate additional data -- see record_activity()

							*applied = 1;
					
							current_phase = LEARNING;
							//fprintf(tunLogPtr, "%s %s: Changed current phase***\n",ctime_buf, phase2str(current_phase));
						}

					current_phase = LEARNING; //change back phase to LEARNING
				}
				else
					if (current_phase == LEARNING)
					{
						if (my_tune_max <= kmaximum) //already high
						{
							*nothing_done = 1;
							if (vDebugLevel > 0)
							{
								//don't apply - just log suggestions - decided to use a debug level here because this file could fill up if user never accepts recommendation
								fprintf(tunLogPtr, "%s %s: ***CURRENT TUNING***: %s*",ctime_buf, phase2str(current_phase), buffer);
								fprintf(tunLogPtr, "%s %s: *** Current Tuning of net.ipv4.tcp_wmem appears sufficient***\n", ctime_buf, phase2str(current_phase));
							}
						}
						else
							{
								*suggested = 1;
								if (vDebugLevel > 0)
								{
									//don't apply - just log suggestions - decided to use a debug level here because this file could fill up if user never accepts recommendation
									fprintf(tunLogPtr, "%s %s: ***CURRENT TUNING***: *%s",ctime_buf, phase2str(current_phase), buffer);
									fprintf(tunLogPtr, "%s %s: ***SUGGESTED TUNING***: *sudo sysctl -w net.ipv4.tcp_wmem=\"%u %d %u\"\n\n",ctime_buf, phase2str(current_phase), kminimum, kdefault, kmaximum+KTUNING_DELTA);
								}
							}
					}
			}
	}
        
	fflush(tunLogPtr);
	return;
}

#define MAX_TUNING_APPLY	10
static double previous_average_tx_Gbits_per_sec = 0.0;
void * fDoRunGetThresholds(void * vargp)
{
	time_t clk;
	char ctime_buf[27];
	
	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"%s %s: ***Starting Check Threshold thread ...***\n", ctime_buf, phase2str(current_phase));
	fflush(tunLogPtr);
	char buffer[128];
	char aApplyDefTunBest[MAX_SIZE_SYSTEM_SETTING_STRING];
	char best_wmem_val[MAX_SIZE_SYSTEM_SETTING_STRING];
	FILE *pipe;
	unsigned long last_tx_bytes = 0, last_rx_bytes = 0;	
	int check_bitrate_interval = 0, keep_bitrate_interval = 0;
	unsigned long rx_before, rx_now, rx_bytes_tot;
	unsigned long tx_before, tx_now, tx_bytes_tot;
	double average_tx_kbits_per_sec = 0.0;
	double average_tx_Gbits_per_sec = 0.0;
	double highest_average_tx_Gbits_per_sec = 0.0;
	char try[1024];
	int stage = 0;
	int applied = 0, suggested = 0, nothing_done = 0, max_apply = 0, something_wrong_check = 0;
	int tune = 1; //1 = up, 2 = down - tune up initially

	sprintf(try,"bpftrace -e \'BEGIN { @name;} kprobe:dev_get_stats { $nd = (struct net_device *) arg0; @name = $nd->name; } kretprobe:dev_get_stats /@name == \"%s\"/ { $rtnl = (struct rtnl_link_stats64 *) retval; $rx_bytes = $rtnl->rx_bytes; $tx_bytes = $rtnl->tx_bytes; printf(\"%s %s\\n\", $tx_bytes, $rx_bytes); } interval:s:1 { exit(); } END { clear(@name); }\'",netDevice,"%lu","%lu");
	/* fix for kfunc below too */
	/*sprintf(try,"bpftrace -e \'BEGIN { @name;} kfunc:dev_get_stats { $nd = (struct net_device *) args->dev; @name = $nd->name; } kretfunc:dev_get_stats /@name == \"%s\"/ { $nd = (struct net_device *) args->dev; $rtnl = (struct rtnl_link_stats64 *) args->storage; $rx_bytes = $rtnl->rx_bytes; $tx_bytes = $rtnl->tx_bytes; printf(\"%s %s\\n\", $tx_bytes, $rx_bytes); time(\"%s\"); exit(); } END { clear(@name); }\'",netDevice,"%lu","%lu","%S");*/

start:
#if 1
	rx_before =  rx_now = rx_bytes_tot = rx_kbits_per_sec = 0;
	tx_before =  tx_now = tx_bytes_tot = tx_kbits_per_sec = 0;
	last_tx_bytes = last_rx_bytes = 0;	
#endif

	tx_bytes_tot = 0;
	rx_bytes_tot = 0;	
	tx_kbits_per_sec = 0;
	rx_kbits_per_sec = 0;

	pipe = popen(try,"r");
	if (!pipe)
	{
		printf("popen failed!\n");
		return ((char *) 0);
	}

	// read for 2 lines of process:
	if (!feof(pipe))
	{
		// use buffer to read and add to result
		if (fgets(buffer, 128, pipe) != NULL);
			//printf("buffer0 is %s",buffer);		
		else
			{
				printf("Not working****\n");
				return ((char *) 0);
			}
	}

	if (!feof(pipe))
	{	
 		if (fgets(buffer, 128, pipe) != NULL)
		{
			//printf("buffer1 is %s",buffer);		
			sscanf(buffer,"%lu %lu", &tx_before, &rx_before);
			//printf("tx_bytes = %lu, rx_bytes = %lu\n",tx_before,rx_before);
			check_bitrate_interval++;
			stage = 1;
		}
		else
			{
				printf("Not working****\n");
				return ((char *) 0);
			}
	}

	while (!feof(pipe) && stage)
	{
		if (fgets(buffer, 128, pipe) != NULL)
		{
			//printf("buffer2 is %s",buffer);		
			sscanf(buffer,"%lu %lu", &tx_now, &rx_now);
			if(tx_now != 0)
			{
				last_tx_bytes = tx_now;
				last_rx_bytes = rx_now;
			}
			tx_now = 0;
			rx_now = 0;
		}
	}
	pclose(pipe);

	tx_bytes_tot =  last_tx_bytes - tx_before;
	rx_bytes_tot =  last_rx_bytes - rx_before;

	//tx_kbits_per_sec = ((8 * tx_bytes_tot) / 1024) / secs_passed;
	//rx_kbits_per_sec = ((8 * rx_bytes_tot) / 1024) / secs_passed;;
	tx_kbits_per_sec = ((8 * tx_bytes_tot) / 1000);
	rx_kbits_per_sec = ((8 * rx_bytes_tot) / 1000);
		
	average_tx_kbits_per_sec += tx_kbits_per_sec;	
	keep_bitrate_interval = check_bitrate_interval;
	if (check_bitrate_interval >= BITRATE_INTERVAL) 
	{
		//average_tx_bits_per_sec = average_tx_bits_per_sec/check_bitrate_interval;
		average_tx_kbits_per_sec = average_tx_kbits_per_sec/(double)check_bitrate_interval;
		average_tx_Gbits_per_sec = average_tx_kbits_per_sec/(double)(1000000);
		check_bitrate_interval = 0;
	}

	gettime(&clk, ctime_buf);
			
	if (vDebugLevel > 5 && tx_kbits_per_sec)
	{
		fprintf(tunLogPtr,"%s %s: DEV %s: TX : %.2f Gb/s RX : %.2f Gb/s\n", ctime_buf, phase2str(current_phase), netDevice, tx_kbits_per_sec/(double)(1000000), rx_kbits_per_sec/(double)(1000000));
		//fprintf(tunLogPtr,"%s %s: DEV %s: TX : %.2f Gb/s RX : %.2f Gb/s\n", ctime_buf, phase2str(current_phase), netDevice, tx_kbits_per_sec/(double)(1048576), rx_kbits_per_sec/(double)(1048576));
	}

	if (vDebugLevel > 1 && average_tx_Gbits_per_sec)
	{
		if (!check_bitrate_interval)
		{
			fprintf(tunLogPtr,"%s %s: average_tx_Gbits_per_sec = %.2f Gb/s, bitrate_interval = %d \n",ctime_buf, phase2str(current_phase), average_tx_Gbits_per_sec, keep_bitrate_interval);
		}
	}

	if (!check_bitrate_interval)
	{
		if (tune == 3 && average_tx_Gbits_per_sec)
		{
			tune = 0;
			applied = 0;
			nothing_done = 1;
		}
		else
			{
#if 0 
				if ((vDebugLevel > 2) &&  (highest_average_tx_Gbits_per_sec >= 1))
				{
					fprintf(tunLogPtr,"%s %s: ***applied = %d, highest avg tx bitrate= %.2f***\n", 
						ctime_buf, phase2str(current_phase), applied, highest_average_tx_Gbits_per_sec);
				}
#endif
				if (highest_average_tx_Gbits_per_sec <= average_tx_Gbits_per_sec)
				{
					highest_average_tx_Gbits_per_sec = average_tx_Gbits_per_sec;
#if 1
					if (applied)
					{
						strcpy(best_wmem_val,aApplyDefTunBest);
	
						if (vDebugLevel > 1)
						{
							fprintf(tunLogPtr,"%s %s: ***Best wmem val***%s***\n\n", ctime_buf, 
										phase2str(current_phase), best_wmem_val);
						}

						max_apply = 0;
					}
#endif
				}
				
				if (previous_average_tx_Gbits_per_sec < highest_average_tx_Gbits_per_sec)
				{
					tune = 1; //up
				}
				else
					tune = 2; //down

				gettime(&clk, ctime_buf);
				if (previous_average_tx_Gbits_per_sec)
				{
					if ((vDebugLevel > 2) &&  (highest_average_tx_Gbits_per_sec >= 1))
					{
						fprintf(tunLogPtr,"%s %s: ***applied = %d, previous avg bitrate %.2f, highest avg bitrate= %.2f***\n", 
								ctime_buf, phase2str(current_phase), applied, 
									previous_average_tx_Gbits_per_sec, highest_average_tx_Gbits_per_sec);
					}

					if (previous_average_tx_Gbits_per_sec*2 < highest_average_tx_Gbits_per_sec)
						something_wrong_check++;
					else
						something_wrong_check = 0;

					if (something_wrong_check > 2)
					{
						if ((vDebugLevel > 1) &&  (highest_average_tx_Gbits_per_sec >= 1))
						{
							fprintf(tunLogPtr,"%s %s: previous value %.2f, is way too smaller than highest = %.2f***\n",
								ctime_buf, phase2str(current_phase), previous_average_tx_Gbits_per_sec, 
									highest_average_tx_Gbits_per_sec);

							fprintf(tunLogPtr,"%s %s: Will need to adjust***\n", ctime_buf, phase2str(current_phase));
						}

						highest_average_tx_Gbits_per_sec = previous_average_tx_Gbits_per_sec/2;
						something_wrong_check = 0;
						tune = 0;
						nothing_done = 0;
						max_apply = 0;
						average_tx_Gbits_per_sec = 0.0;
						average_tx_kbits_per_sec = 0.0;
						goto ck_stage;
					}
				}
				
				if (applied)
					max_apply++;
				else
					max_apply = 0;

				if (max_apply >= MAX_TUNING_APPLY)
				{
					tune = 3;
					strcpy(aApplyDefTunBest,best_wmem_val);
#if 1	
					if (vDebugLevel > 1)
					{
						fprintf(tunLogPtr,"%s %s: ***Going to apply Best wmem val***%s***\n\n", ctime_buf, 
									phase2str(current_phase), best_wmem_val);
					}
#endif
					max_apply = 0;
				}

				fflush(tunLogPtr);

				previous_average_tx_Gbits_per_sec = average_tx_Gbits_per_sec;
			}

			if (suggested)
			{
				if (suggested++ > 3)
					suggested = 0;
				else
					{
						if ((suggested == 2) && (vDebugLevel > 0))
						{
							gettime(&clk, ctime_buf);
							fprintf(tunLogPtr, "%s %s: ***Tuning was suggested but not applied, will skip suggesting for now ...***\n", ctime_buf, phase2str(current_phase));
							fflush(tunLogPtr);
						}
						average_tx_Gbits_per_sec = 0.0;
						average_tx_kbits_per_sec = 0.0;
						goto ck_stage;
					}
			}
			else
				if (applied) //tuning applied
				{
					applied = 0;
				}
				else
					if (nothing_done) //no change to tuning
					{
						if (nothing_done++ > 6)
							nothing_done = 0;
						else
						{
							if ((nothing_done == 2) && (vDebugLevel > 0))
							{
								gettime(&clk, ctime_buf);

								fprintf(tunLogPtr, "%s %s: ***Tuning appears sufficient, will skip suggesting or applying for now ...***\n", ctime_buf, phase2str(current_phase));
								fflush(tunLogPtr);
							}
							average_tx_Gbits_per_sec = 0.0;
							average_tx_kbits_per_sec = 0.0;
							goto ck_stage;
						}
					}

			applied = 0;

			if (average_tx_Gbits_per_sec >= 1) //must be at least a Gig to check
				check_if_bitrate_too_low(average_tx_Gbits_per_sec, &applied, &suggested, &nothing_done, &tune, aApplyDefTunBest);

			if (vDebugLevel > 5 && (tx_kbits_per_sec || rx_kbits_per_sec))
			{
				fprintf(tunLogPtr, "%s %s: ***Sleeping for %d microseconds before resuming Bitrate checking...\n", ctime_buf, phase2str(current_phase), gInterval);
				fflush(tunLogPtr);
			}
				
			average_tx_Gbits_per_sec = 0.0;
			average_tx_kbits_per_sec = 0.0;
			my_usleep(gInterval); //sleeps in microseconds
	}

	msleep(1000); //give it another second to quiesce

ck_stage:
	if (stage)
	{
		stage = 0;
		goto start;
	}

	fprintf(tunLogPtr, "%s %s: ***Problems*** stage not set...\n", ctime_buf, phase2str(current_phase));
	fflush(tunLogPtr);

return ((char *) 0);
}


//Measured in milliseconds
#define RTT_THRESHOLD	50 
void fDoManageRtt(double average_tx_Gbits_per_sec, int * applied, int * suggested, int * nothing_done, int * tune, char aApplyDefTun[MAX_SIZE_SYSTEM_SETTING_STRING]);
void fDoManageRtt(double average_tx_Gbits_per_sec, int * applied, int * suggested, int * nothing_done, int * tune, char aApplyDefTun[MAX_SIZE_SYSTEM_SETTING_STRING])
{
	time_t clk;
	char ctime_buf[27];
	char buffer[256];
	FILE *pipe;
	char kernel_parameter[128];
	char equal_sign;
	unsigned int  kminimum;
	int kdefault;
	unsigned int kmaximum;

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr, "%s %s: *** In fDoManageRtt(). Must have hit some RTT threshold. Returning for now...***\n", ctime_buf, phase2str(current_phase));

	return;

	if (average_tx_Gbits_per_sec < vGoodBitrateValue)
	{
		if (current_phase == TUNING)
		{
			fprintf(tunLogPtr, "%s %s: Trying to tune net.ipv4.tcp_wmem, but already TUNING something else.  Will retry later if still need TUNING***\n",ctime_buf, phase2str(current_phase));
		}
		else
			{
				pipe = popen("sysctl net.ipv4.tcp_wmem","r");
				if (!pipe)
				{
					printf("popen failed!\n");
					return ;
				}

				while (!feof(pipe))
				{
					if (fgets(buffer, 256, pipe) != NULL)
					{
						sscanf(buffer,"%s %c %u %d %u", kernel_parameter, &equal_sign, &kminimum, &kdefault, &kmaximum);
						break;
					}
					else
						{
							printf("***ERROR: problem getting buffer from popen, returning!!!***\n");
							pclose(pipe);
							return ;
						}
				}
				pclose(pipe);

				if (!my_tune_max)
				{
					printf("***ERROR: Strange error. Could not find net.ipv4.tcp_wmem in local database!!!***\n");
					return ;
				}

				if (gTuningMode && current_phase == LEARNING)
				{
					gettime(&clk, ctime_buf);
					current_phase = TUNING;
					//fprintf(tunLogPtr, "%s %s: Changed current phase***\n",ctime_buf, phase2str(current_phase));
					//do something
					if (my_tune_max <= kmaximum) //already high
					{
						if (vDebugLevel > 0)
						{
							//don't apply - just log suggestions - decided to use a debug level here because this file could fill up if user never accepts recommendation
							fprintf(tunLogPtr, "%s %s: ***CURRENT TUNING***: %s*",ctime_buf, phase2str(current_phase), buffer);
							fprintf(tunLogPtr, "%s %s: *** Current Tuning of net.ipv4.tcp_wmem appears sufficient***\n", ctime_buf, phase2str(current_phase));
						}
						
						*nothing_done = 1;
					}
					else
						{
							//char aApplyDefTun[MAX_SIZE_SYSTEM_SETTING_STRING];
							char aApplyDefTunNoStdOut[MAX_SIZE_SYSTEM_SETTING_STRING+32];

							if (*tune == 1) //apply up
								sprintf(aApplyDefTun,"sysctl -w net.ipv4.tcp_wmem=\"%u %d %u\"", kminimum, kdefault, kmaximum+KTUNING_DELTA);
							else
								if (*tune == 2)
								{
									if (kmaximum > 600000)
										sprintf(aApplyDefTun,"sysctl -w net.ipv4.tcp_wmem=\"%u %d %u\"", kminimum, kdefault, kmaximum - KTUNING_DELTA);
									else
										{

											fprintf(tunLogPtr, "%s %s: ***Could not apply tuning since the maximum value of wmem would be less than %d...***\n",ctime_buf, phase2str(current_phase), 600000 - KTUNING_DELTA);
											current_phase = LEARNING; //change back phase to LEARNING
											*nothing_done = 1;
											return;
										}
								}
								else
									if (*tune == 3)
									{
										fprintf(tunLogPtr,"%s %s: ***No better change found. Using ***%s***\n\n", ctime_buf, phase2str(current_phase), aApplyDefTun);
									}
									else
										{
											fprintf(tunLogPtr, "%s %s: ***Could not apply tuning*** invalid value for tune %d***\n",ctime_buf, phase2str(current_phase), *tune);
											current_phase = LEARNING; //change back phase to LEARNING
											*nothing_done = 1;
											return;
										}

										fprintf(tunLogPtr, "%s %s: ***CURRENT TUNING***: %s",ctime_buf, phase2str(current_phase), buffer);
										strcpy(aApplyDefTunNoStdOut,aApplyDefTun);
										strcat(aApplyDefTunNoStdOut," >/dev/null"); //so it won't print to stderr on console
										system(aApplyDefTunNoStdOut);
										fprintf(tunLogPtr, "%s %s: ***APPLIED TUNING***: %s\n\n",ctime_buf, phase2str(current_phase), aApplyDefTun);
										*applied = 1;

										current_phase = LEARNING;
										//fprintf(tunLogPtr, "%s %s: Changed current phase***\n",ctime_buf, phase2str(current_phase));
						}

						current_phase = LEARNING; //change back phase to LEARNING
				}
				else
					if (current_phase == LEARNING)
					{
						if (my_tune_max <= kmaximum) //already high
						{
							*nothing_done = 1;
							if (vDebugLevel > 0)
							{
								//don't apply - just log suggestions - decided to use a debug level here because this file could fill up if user never accepts recommendation
							}
						}
						else
							{
								*suggested = 1;
								if (vDebugLevel > 0)
								{
									//don't apply - just log suggestions - decided to use a debug level here because this file could fill up if user never accepts recommendation
									fprintf(tunLogPtr, "%s %s: ***CURRENT TUNING***: *%s",ctime_buf, phase2str(current_phase), buffer);
									fprintf(tunLogPtr, "%s %s: ***SUGGESTED TUNING***: *sudo sysctl -w net.ipv4.tcp_wmem=\"%u %d %u\"\n\n",ctime_buf, phase2str(current_phase), kminimum, kdefault, kmaximum+KTUNING_DELTA);
								}
							}
					}
			}
	}

	fflush(tunLogPtr);
return;
}

void * fDoRunFindHighestRtt(void * vargp)
{
	//int * fd = (int *) vargp;
	time_t clk;
	char ctime_buf[27];
	char buffer[128];
	FILE *pipe;
	char try[1024];
	char aApplyDefTunBest[MAX_SIZE_SYSTEM_SETTING_STRING];
	long rtt = 0, highest_rtt = 0;
	int applied = 0, suggested = 0, nothing_done = 0;
	int tune = 1; //1 = up, 2 = down - tune up initially

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"%s %s: ***Starting Finding Highest RTT thread ...***\n", ctime_buf, phase2str(current_phase));
	fflush(tunLogPtr);
        
	sprintf(try,"sudo bpftrace -e \'BEGIN { @ca_rtt_us;} kprobe:tcp_ack_update_rtt { @ca_rtt_us = arg4; } kretprobe:tcp_ack_update_rtt /pid != 0/ { printf(\"%s\\n\", @ca_rtt_us); } interval:ms:125 {  exit(); } END { clear(@ca_rtt_us); }\'", "%ld");

rttstart:
	rtt = 0;
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

#if 1
		if (vDebugLevel > 6 && previous_average_tx_Gbits_per_sec) 
			fprintf(tunLogPtr,"%s %s: **rtt = %luus, highest rtt = %luus\n", ctime_buf, phase2str(current_phase), rtt, highest_rtt);
#endif
	}

finish_up:
	pclose(pipe);

	if (highest_rtt)
	{
		if (vDebugLevel > 1 && previous_average_tx_Gbits_per_sec)
		{
			gettime(&clk, ctime_buf);
			fprintf(tunLogPtr,"%s %s: ***Highest RTT is %.3fms\n", ctime_buf, phase2str(current_phase), highest_rtt/(double)1000);
			fflush(tunLogPtr);
		}

		if (highest_rtt/1000 >= RTT_THRESHOLD)
			fDoManageRtt(highest_rtt/1000, &applied, &suggested, &nothing_done, &tune, aApplyDefTunBest);
	}

	if (vDebugLevel > 5 && previous_average_tx_Gbits_per_sec)
	{
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr, "%s %s: ***Sleeping for %d microseconds before resuming RTT checking...\n", ctime_buf, phase2str(current_phase), gInterval);
		fflush(tunLogPtr);
	}

	my_usleep(gInterval); //sleeps in microseconds	
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
	fprintf(tunLogPtr,"%s %s: ***Starting Listener for receiving messages from destination DTN...***\n", ctime_buf, phase2str(current_phase));
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

	open_csv_file();	

	user_assess(argc, argv);
	fCheck_log_limit();
	
	gettime(&clk, ctime_buf);
	current_phase = LEARNING;

	memset(sFlowCounters,0,sizeof(sFlowCounters));
	memset(aSrc_Ip,0,sizeof(aSrc_Ip));
	src_ip_addr.y = 0;

	vGoodBitrateValue = ((95/(double)100) * netDeviceSpeed); //99% of NIC speed must be a good bitrate
	fprintf(tunLogPtr, "%s %s: ***vGoodBitrateValue = %.1f***\n", ctime_buf, phase2str(current_phase), vGoodBitrateValue);
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

