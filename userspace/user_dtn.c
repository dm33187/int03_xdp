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
#include <sys/prctl.h>
#include <signal.h>
#include <sys/wait.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <arpa/inet.h>

#include <sys/ipc.h>
#include <sys/shm.h>

#include "unp.h"
#include "user_dtn.h"


#ifdef HPNSSH_QFACTOR_BINN
#include "binncli.h"
void fMake_Binn_Server_Object(struct PeerMsg *pMsg, binn * obj)
{
	binn_object_set_uint32(obj, "msg_type", pMsg->msg_no);
	binn_object_set_uint32(obj, "op", pMsg->value);
	binn_object_set_uint32(obj, "hop_latency", pMsg->hop_latency);
	binn_object_set_uint32(obj, "queue_occupancy", pMsg->queue_occupancy);
	binn_object_set_uint32(obj, "switch_id", pMsg->switch_id);
	binn_object_set_str(obj, "timestamp", pMsg->timestamp);
        
	return;
}

void fRead_Binn_Client_Object(struct ClientBinnMsg *pMsg, binn * obj)
{
	pMsg->msg_type = binn_object_uint32(obj, "msg_type");
	pMsg->op = binn_object_uint32(obj, "op");
	
	return;
}
#endif

FILE * tunLogPtr = 0;
FILE * csvLogPtr = 0;

char *pLearningSpaces 			= "                                        ";
char *pLearningSpacesMinusLearning 	= "                              ";

void gettime(time_t *clk, char *ctime_buf)
{
	*clk = time(NULL);
	ctime_r(clk,ctime_buf);
	ctime_buf[24] = ':';
}

void gettimeWithMilli(time_t *clk, char *ctime_buf, char *ms_ctime_buf)
{
	struct timespec ts;
	timespec_get(&ts, TIME_UTC);
	*clk = ts.tv_sec;
	struct tm *t = localtime(clk);
	ctime_r(clk,ctime_buf);
	ctime_buf[19] = '.';
	ctime_buf[20] = '\0';
	sprintf(ms_ctime_buf,"%s%03ld %04d:", ctime_buf, ts.tv_nsec/1000000, t->tm_year+1900);
return;
}


typedef struct
{
	int id;
	size_t size;
} shm_t;

shm_t *shm_new(size_t size)
{
	time_t clk;
	char ctime_buf[CTIME_BUF_LEN];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	shm_t *shm = calloc(1, sizeof *shm);
	shm->size = size;

	if ((shm->id = shmget(IPC_PRIVATE, size, IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR)) < 0)
	{
		int saverrno = errno;
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(tunLogPtr, "%s %s: shmget() failed, errno = %d***\n", ms_ctime_buf, phase2str(current_phase), saverrno);
		free(shm);
		return NULL;
	}

	return shm;
}

void shm_write(shm_t *shm, void *data)
{
	time_t clk;
	char ctime_buf[CTIME_BUF_LEN];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	void *shm_data;

	if ((shm_data = shmat(shm->id, NULL, 0)) == (void *) -1)
	{
		int saverrno = errno;
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(tunLogPtr, "%s %s: shmat in shm_write() failed, errno = %d***\n", ms_ctime_buf, phase2str(current_phase), saverrno);
		return;
	}

	memcpy(shm_data, data, shm->size);
	shmdt(shm_data);
}

int shm_read(void *data, shm_t *shm)
{
	time_t clk;
	char ctime_buf[CTIME_BUF_LEN];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	void *shm_data;

	if ((shm_data = shmat(shm->id, NULL, 0)) == (void *) -1)
	{
		int saverrno = errno;
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(tunLogPtr, "%s %s: shmat in shm_read() failed, errno = %d***\n", ms_ctime_buf, phase2str(current_phase), saverrno);
		return 0;
	}
	memcpy(data, shm_data, shm->size);
	shmdt(shm_data);
	return 1;
}

void shm_del(shm_t *shm)
{
	shmctl(shm->id, IPC_RMID, 0);
	free(shm);
}

static shm_t *shm = 0;

void open_csv_file(void);
void open_csv_file(void)
{
	time_t clk;
	char ctime_buf[CTIME_BUF_LEN];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];

	csvLogPtr = fopen("/tmp/csvTuningLog","w");
	if (!csvLogPtr)
	{
		printf("Could not open CSV Logfile, exiting...\n");
		exit(-1);
	}

	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
	fprintf(tunLogPtr, "%s %s: CSV Log file /tmp/csvTuningLog also opened***\n", ms_ctime_buf, phase2str(current_phase));

	fprintf(csvLogPtr,"delta,name,value\n");
	fflush(csvLogPtr);

	return;
}

static int vDidSetChannel = 0;
static int perf_buffer_poll_start = 0;
//static time_t total_time_passed = 0;
static double vRetransmissionRate = 0.0;
static double vGlobal_average_tx_Gbits_per_sec = 0.0;
int vResetPacingBack = 0;
static int new_traffic = 0;
static int rx_traffic = 0;
static time_t now_time = 0;
static time_t last_time = 0;
static  int vIamASrcDtn = 0;
static  int vIamADestDtn = 0;
static double rtt_threshold = 2.0;
static int rtt_factor = 4;
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
#ifdef HPNSSH_QFACTOR
pthread_mutex_t hpn_ret_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t hpn_ret_cond = PTHREAD_COND_INITIALIZER;
static int hpnretcdone = 0;
struct PeerMsg sHpnRetMsg;
struct PeerMsg sHpnRetMsg2;
unsigned int hpnRetMsgSeqNo = 0;
struct PeerMsg sTimeoutMsg;
#endif
static unsigned int sleep_count = 1;
static double vGoodBitrateValue = 0.0;
static double vGoodBitrateValueThatDoesntNeedMessage = 0.0;
struct PeerMsg sMsg;
unsigned int sMsgSeqNo = 0;
char aSrc_Ip[32];
char aDest_Ip2[32];
char aDest_Ip2_Binary[32];
char aLocal_Ip[32];

union uIP {
	 __u32 y;
       	 unsigned char  a[4];
};

static union uIP src_ip_addr;

void qOCC_Hop_TimerID_Handler(int signum, siginfo_t *info, void *ptr);
void qOCC_TimerID_Handler(int signum, siginfo_t *info, void *ptr);
static void timerHandler( int sig, siginfo_t *si, void *uc );

timer_t qOCC_Hop_TimerID; //when both Qinfo and Hop latency over threshhold
timer_t qOCC_TimerID; // when Qinfo over some user defined value that will cause us to send message to peer to start TCP Pacing if appropiate
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
		if ( *tidp == qOCC_TimerID )
			qOCC_TimerID_Handler(sig, si, uc);
	
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
//vDebugLevel (Default = 1)
//= 0 - only applied tuning, error and important messages get written to log file unconditionally
//= 1 - include suggested tuning
//= 2 - include additional learning messages which provide window into decision making
//= 3 - include still more learning messages which provide window into decision making
//= 4 - include data from INT sink
//= 5 - include additional sink data logging
//= 6 - include additional information about the link
//= 7 - include everything else
static int vDebugLevel = 1;

#define SIGINT_MSG "SIGINT received.\n"
void sig_int_handler(int signum, siginfo_t *info, void *ptr)
{
	//write(STDERR_FILENO, SIGINT_MSG, sizeof(SIGINT_MSG));
	fprintf(tunLogPtr,"Caught SIGINT, exiting...\n");
	shm_del(shm);
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

#define NUMMETAVALUES   10000
typedef struct {
        char timestamp[MS_CTIME_BUF_LEN];
        unsigned int hop_latency;
        unsigned int queue_occupancy;
	unsigned int switch_id;
} sMetaData_t[NUMMETAVALUES];


sMetaData_t metaData;
unsigned int vMetaDataCount = 0;
unsigned int vMetaDataClientCount = 0;

typedef struct {
	int argc;
	char ** argv;
} sArgv_t;

#include "../../int-sink/src/shared/int_defs.h"
#include "../../int-sink/src/shared/filter_defs.h"

#ifdef INCLUDE_SRC_PORT
static __u16 src_port;
#endif

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

#define QINFO_START_MIN_VALUE 0xFFFFFF //16777215
//no need for a START_MAX since it will be zero

static __u32 flow_sink_time_threshold = 0;
static __u32 Qinfo = 0;

static __u32 qinfo_min_value = QINFO_START_MIN_VALUE;
static __u32 qinfo_hop_latency_min = 0;
static __u32 qinfo_hop_switch_id_min = 0;
static time_t qinfo_clk_min = 0;
static char qinfo_ms_ctime_buf_min[MS_CTIME_BUF_LEN];

static __u32 qinfo_max_value = 0;
static __u32 qinfo_hop_latency_max = 0;
static __u32 qinfo_hop_switch_id_max = 0;
static time_t qinfo_clk_max = 0;
static char qinfo_ms_ctime_buf_max[MS_CTIME_BUF_LEN];

static __u32 vQinfoUserValue = 0; //Eventually Initialize this value with vQUEUE_OCCUPANCY_DELTA
static double vRetransmissionRateThreshold = 2; //Percentage 
static __u32 ingress_time = 0;
static __u32 egress_time = 0;
static __u32 hop_hop_latency_threshold = 0;
static __u32 curr_hop_key_hop_index = 0;
static int vFlowCount = 0;
static int vFlowCountWrapped = 0;
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
static __u32 vQUEUE_OCCUPANCY_DELTA = 415; //was 6400 then 30000
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
int vq_h_TimerIsSet = 0;
int vq_TimerIsSet = 0;
int vq_WarningCount = 0;

void qOCC_Hop_TimerID_Handler(int signum, siginfo_t *info, void *ptr)
{
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	char activity[MAX_SIZE_TUNING_STRING];
	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
	fprintf(tunLogPtr, "%s %s: ***Timer Alarm went off*** still having problems with Queue Occupancy and HopDelays. Time to do something***\n",ms_ctime_buf, phase2str(current_phase)); 
	//***Do something here ***//
	vq_h_TimerIsSet = 0;
	sprintf(activity,"%s %s: ***hop_key.hop_index %X, Doing Something",ctime_buf, phase2str(current_phase), curr_hop_key_hop_index);
	record_activity(activity); //make sure activity big enough to concatenate additional data -- see record_activity()
	fflush(tunLogPtr);
	
	return;
}

void qOCC_TimerID_Handler(int signum, siginfo_t *info, void *ptr)
{
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	char activity[MAX_SIZE_TUNING_STRING];
	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
	fprintf(tunLogPtr, "%s %s: ***Timer Alarm went off*** still having problems with Queue Occupancy User Info. Time to do something***\n",ms_ctime_buf, phase2str(current_phase)); 
	//***Do something here ***//
	vq_TimerIsSet = 0;
	sprintf(activity,"%s %s: ***hop_key.hop_index %X, Doing Something",ctime_buf, phase2str(current_phase), curr_hop_key_hop_index);
	record_activity(activity); //make sure activity big enough to concatenate additional data -- see record_activity()
	fflush(tunLogPtr);

#if 1
	Pthread_mutex_lock(&dtn_mutex);
	strcpy(sMsg.msg, "Hello there!!! This is a Qinfo msg...\n");
	sMsg.msg_no = htonl(QINFO_MSG);
	sMsg.value = htonl(vQinfoUserValue);
	sMsgSeqNo++;
	sMsg.seq_no = htonl(sMsgSeqNo);
	cdone = 1;
	Pthread_cond_signal(&dtn_cond);
	Pthread_mutex_unlock(&dtn_mutex);
#endif	
	vq_WarningCount = 0;
	return;
}

void * fDoRunBpfCollectionPerfEventArray2(void * vargp)
{
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	int timerRc = 0;
	int perf_output_map;
	int int_dscp_map;
	struct perf_buffer *pb;
	struct threshold_maps maps = {};

	memset (&sStartTimer,0,sizeof(struct itimerspec));
	memset (&sDisableTimer,0,sizeof(struct itimerspec));

	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);

	timerRc = makeTimer("qOCC_Hop_TimerID", &qOCC_Hop_TimerID, gInterval);
	if (timerRc)
	{
		fprintf(tunLogPtr, "%s %s: Problem creating timer *qOCC_Hop_TimerID*.\n", ms_ctime_buf, phase2str(current_phase));
		return ((char *)1);
	}
	else
		fprintf(tunLogPtr, "%s %s: *qOCC_Hop_TimerID* timer created.\n", ms_ctime_buf, phase2str(current_phase));

	timerRc = makeTimer("qOCC_TimerID", &qOCC_TimerID, gInterval);
	if (timerRc)
	{
		fprintf(tunLogPtr, "%s %s: Problem creating timer *qOCC_TimerID*.\n", ms_ctime_buf, phase2str(current_phase));
		return ((char *)1);
	}
	else
		fprintf(tunLogPtr, "%s %s: *qOCC_TimerID* timer created.\n", ms_ctime_buf, phase2str(current_phase));
	
	fprintf(tunLogPtr,"%s %s: ***Queue occupancy threshold is set to %u\n", ms_ctime_buf, phase2str(current_phase), vQUEUE_OCCUPANCY_DELTA);

open_maps: {
	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
	fprintf(tunLogPtr,"%s %s: Opening maps.\n", ms_ctime_buf, phase2str(current_phase));
	//maps.counters = bpf_obj_get(MAP_DIR "/counters_map");
	fprintf(tunLogPtr,"%s %s: Opening flow_counters_map.\n", ms_ctime_buf, phase2str(current_phase));
	maps.flow_counters = bpf_obj_get(MAP_DIR "/flow_counters_map");
	if (maps.flow_counters < 0) { goto close_maps; }
	fprintf(tunLogPtr,"%s %s: Opening flow_thresholds_map.\n", ms_ctime_buf, phase2str(current_phase));
	maps.flow_thresholds = bpf_obj_get(MAP_DIR "/flow_thresholds_map");
	if (maps.flow_thresholds < 0) { goto close_maps; }
	fprintf(tunLogPtr,"%s %s: Opening hop_thresholds_map.\n", ms_ctime_buf, phase2str(current_phase));
	maps.hop_thresholds = bpf_obj_get(MAP_DIR "/hop_thresholds_map");
	if (maps.hop_thresholds < 0) { goto close_maps; }
	fprintf(tunLogPtr,"%s %s: Opening perf_output_map.\n", ms_ctime_buf, phase2str(current_phase));
	perf_output_map = bpf_obj_get(MAP_DIR "/perf_output_map");
	if (perf_output_map < 0) { goto close_maps; }
	fprintf(tunLogPtr,"%s %s: Opening int_dscp_map.\n", ms_ctime_buf, phase2str(current_phase));
	int_dscp_map = bpf_obj_get(MAP_DIR "/int_dscp_map");
	if (int_dscp_map < 0) { goto close_maps; }
	}
set_int_dscp: {
	fprintf(tunLogPtr,"%s %s: Setting INT DSCP.\n", ms_ctime_buf, phase2str(current_phase));
	__u32 int_dscp = INT_DSCP;
	__u32 zero_value = 0;
	bpf_map_update_elem(int_dscp_map, &int_dscp, &zero_value, BPF_NOEXIST);
    }
open_perf_event: {
	fprintf(tunLogPtr,"%s %s: Opening perf event buffer.\n", ms_ctime_buf, phase2str(current_phase));
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
	fprintf(tunLogPtr,"%s %s: Running perf event loop.\n", ms_ctime_buf, phase2str(current_phase));
	fflush(tunLogPtr);
 	int err = 0;
	do {
		perf_buffer_poll_start = 1;
		qinfo_min_value = QINFO_START_MIN_VALUE; 
		qinfo_max_value = 0;

		//err = perf_buffer__poll(pb, 500);
		err = perf_buffer__poll(pb, 250);
	
		if (err >= 0)
		{
			if (!perf_buffer_poll_start)
			{
#if 0
				Pthread_mutex_lock(&hpn_ret_mutex);
				//sHpnRetMsg.value = value;
				hpnRetMsgSeqNo++;
				sHpnRetMsg.seq_no = htonl(hpnRetMsgSeqNo);
				hpnretcdone = 1;
				Pthread_cond_signal(&hpn_ret_cond);
				Pthread_mutex_unlock(&hpn_ret_mutex);
#endif
					if ((qinfo_min_value != QINFO_START_MIN_VALUE) && (qinfo_max_value != 0))
					{
						if (qinfo_clk_min <= qinfo_clk_max)
						{ 	
							Pthread_mutex_lock(&hpn_ret_mutex);
							
//							sHpnRetMsg.pts = qinfo_ms_ctime_buf_min;
							memcpy(sHpnRetMsg.timestamp,qinfo_ms_ctime_buf_min,MS_CTIME_BUF_LEN);
							sHpnRetMsg.hop_latency = qinfo_hop_latency_min;
							sHpnRetMsg.queue_occupancy = qinfo_min_value;
							sHpnRetMsg.switch_id = qinfo_hop_switch_id_min;
							//hpnretcdone = 1;
							//Pthread_cond_signal(&hpn_ret_cond);
							//Pthread_mutex_unlock(&hpn_ret_mutex);
///****************************************************************************************************	We'll see if a better way after
							//Pthread_mutex_lock(&hpn_ret_mutex);
							sHpnRetMsg2.pts = qinfo_ms_ctime_buf_max;
							sHpnRetMsg2.hop_latency = qinfo_hop_latency_max;
							sHpnRetMsg2.queue_occupancy = qinfo_max_value;
							sHpnRetMsg2.switch_id = qinfo_hop_switch_id_max;
							hpnretcdone = 1;

							Pthread_cond_signal(&hpn_ret_cond);
							Pthread_mutex_unlock(&hpn_ret_mutex);
#if 0
							memcpy(metaData[vMetaDataCount].timestamp,qinfo_ms_ctime_buf_min,MS_CTIME_BUF_LEN);
							metaData[vMetaDataCount].hop_latency = qinfo_hop_latency_min;
							metaData[vMetaDataCount].queue_occupancy = qinfo_min_value;
							metaData[vMetaDataCount].switch_id = qinfo_hop_switch_id_min;
						
							vMetaDataCount++;
							if (vMetaDataCount == NUMMETAVALUES)
								vMetaDataCount = 0;


							memcpy(metaData[vMetaDataCount].timestamp,qinfo_ms_ctime_buf_max,MS_CTIME_BUF_LEN);
							metaData[vMetaDataCount].hop_latency = qinfo_hop_latency_max;
							metaData[vMetaDataCount].queue_occupancy = qinfo_max_value;
							metaData[vMetaDataCount].switch_id = qinfo_hop_switch_id_max;
							
							vMetaDataCount++;
							if (vMetaDataCount == NUMMETAVALUES)
								vMetaDataCount = 0;
#endif
							if (vDebugLevel == 4)
							{ 	//print in this order
								fprintf(tunLogPtr, "\n%s %s: ***********************FLOW************************", qinfo_ms_ctime_buf_min, phase2str(current_phase));
								fprintf(tunLogPtr, "\n%s %s: FLOW    : hop_switch_id = %u\n",qinfo_ms_ctime_buf_min, phase2str(current_phase), qinfo_hop_switch_id_min);
								fprintf(tunLogPtr, "%s %s: FLOW    : queue_occupancy = %u\n",qinfo_ms_ctime_buf_min, phase2str(current_phase), qinfo_min_value);
								fprintf(tunLogPtr, "%s %s: FLOW    : hop_latency = %u\n",qinfo_ms_ctime_buf_min, phase2str(current_phase), qinfo_hop_latency_min);
		
								fprintf(tunLogPtr, "\n%s %s: ***********************FLOW************************", qinfo_ms_ctime_buf_max, phase2str(current_phase));
								fprintf(tunLogPtr, "\n%s %s: FLOW    : hop_switch_id = %u\n",qinfo_ms_ctime_buf_max, phase2str(current_phase), qinfo_hop_switch_id_max);
								fprintf(tunLogPtr, "%s %s: FLOW    : queue_occupancy = %u\n",qinfo_ms_ctime_buf_max, phase2str(current_phase), qinfo_max_value);
								fprintf(tunLogPtr, "%s %s: FLOW    : hop_latency = %u\n",qinfo_ms_ctime_buf_max, phase2str(current_phase), qinfo_hop_latency_max);
							}
						}
						else
							{
								Pthread_mutex_lock(&hpn_ret_mutex);
								//sHpnRetMsg.pts = qinfo_ms_ctime_buf_max;
								memcpy(sHpnRetMsg.timestamp,qinfo_ms_ctime_buf_max,MS_CTIME_BUF_LEN);
								sHpnRetMsg.hop_latency = qinfo_hop_latency_max;
								sHpnRetMsg.queue_occupancy = qinfo_max_value;
								sHpnRetMsg.switch_id = qinfo_hop_switch_id_max;
							//	hpnretcdone = 1;
							//	Pthread_cond_signal(&hpn_ret_cond);
							//	Pthread_mutex_unlock(&hpn_ret_mutex);
///****************************************************************************************************	We'll see if a better way after
							//	Pthread_mutex_lock(&hpn_ret_mutex);
								sHpnRetMsg2.pts = qinfo_ms_ctime_buf_min;
								sHpnRetMsg2.hop_latency = qinfo_hop_latency_min;
								sHpnRetMsg2.queue_occupancy = qinfo_min_value;
								sHpnRetMsg2.switch_id = qinfo_hop_switch_id_min;
								hpnretcdone = 1;
								Pthread_cond_signal(&hpn_ret_cond);
								Pthread_mutex_unlock(&hpn_ret_mutex);
#if 0
								memcpy(metaData[vMetaDataCount].timestamp,qinfo_ms_ctime_buf_max,MS_CTIME_BUF_LEN);
								metaData[vMetaDataCount].hop_latency = qinfo_hop_latency_max;
								metaData[vMetaDataCount].queue_occupancy = qinfo_max_value;
								metaData[vMetaDataCount].switch_id = qinfo_hop_switch_id_max;
							
								vMetaDataCount++;
								if (vMetaDataCount == NUMMETAVALUES)
									vMetaDataCount = 0;

								memcpy(metaData[vMetaDataCount].timestamp,qinfo_ms_ctime_buf_min,MS_CTIME_BUF_LEN);
								metaData[vMetaDataCount].hop_latency = qinfo_hop_latency_min;
								metaData[vMetaDataCount].queue_occupancy = qinfo_min_value;
								metaData[vMetaDataCount].switch_id = qinfo_hop_switch_id_min;
						
								vMetaDataCount++;
								if (vMetaDataCount == NUMMETAVALUES)
									vMetaDataCount = 0;
#endif							
								if (vDebugLevel == 4)
								{ 	//print in this order
									fprintf(tunLogPtr, "\n%s %s: ***********************FLOW************************", qinfo_ms_ctime_buf_max, phase2str(current_phase));
									fprintf(tunLogPtr, "\n%s %s: FLOW    : hop_switch_id = %u\n",qinfo_ms_ctime_buf_max, phase2str(current_phase), qinfo_hop_switch_id_max);
									fprintf(tunLogPtr, "%s %s: FLOW    : queue_occupancy = %u\n",qinfo_ms_ctime_buf_max, phase2str(current_phase), qinfo_max_value);
									fprintf(tunLogPtr, "%s %s: FLOW    : hop_latency = %u\n",qinfo_ms_ctime_buf_max, phase2str(current_phase), qinfo_hop_latency_max);

									fprintf(tunLogPtr, "\n%s %s: ***********************FLOW************************", qinfo_ms_ctime_buf_min, phase2str(current_phase));
									fprintf(tunLogPtr, "\n%s %s: FLOW    : hop_switch_id = %u\n",qinfo_ms_ctime_buf_min, phase2str(current_phase), qinfo_hop_switch_id_min);
									fprintf(tunLogPtr, "%s %s: FLOW    : queue_occupancy = %u\n",qinfo_ms_ctime_buf_min, phase2str(current_phase), qinfo_min_value);
									fprintf(tunLogPtr, "%s %s: FLOW    : hop_latency = %u\n",qinfo_ms_ctime_buf_min, phase2str(current_phase), qinfo_hop_latency_min);
								}
							}
					}
					else
						{
							if (qinfo_min_value != QINFO_START_MIN_VALUE)
							{
								Pthread_mutex_lock(&hpn_ret_mutex);
								//sHpnRetMsg.pts = qinfo_ms_ctime_buf_min;
								memcpy(sHpnRetMsg.timestamp,qinfo_ms_ctime_buf_min,MS_CTIME_BUF_LEN);
								sHpnRetMsg.hop_latency = qinfo_hop_latency_min;
								sHpnRetMsg.queue_occupancy = qinfo_min_value;
								sHpnRetMsg.switch_id = qinfo_hop_switch_id_min;
								hpnretcdone = 1;
								Pthread_cond_signal(&hpn_ret_cond);
								Pthread_mutex_unlock(&hpn_ret_mutex);
#if 0
								memcpy(metaData[vMetaDataCount].timestamp,qinfo_ms_ctime_buf_min,MS_CTIME_BUF_LEN);
								metaData[vMetaDataCount].hop_latency = qinfo_hop_latency_min;
								metaData[vMetaDataCount].queue_occupancy = qinfo_min_value;
								metaData[vMetaDataCount].switch_id = qinfo_hop_switch_id_min;
						
								vMetaDataCount++;
								if (vMetaDataCount == NUMMETAVALUES)
									vMetaDataCount = 0;
#endif
								if (vDebugLevel == 4)
								{
									fprintf(tunLogPtr, "\n%s %s: ***********************FLOW************************", qinfo_ms_ctime_buf_min, phase2str(current_phase));
									fprintf(tunLogPtr, "\n%s %s: FLOW    : hop_switch_id = %u\n",qinfo_ms_ctime_buf_min, phase2str(current_phase), qinfo_hop_switch_id_min);
									fprintf(tunLogPtr, "%s %s: FLOW    : queue_occupancy = %u\n",qinfo_ms_ctime_buf_min, phase2str(current_phase), qinfo_min_value);
									fprintf(tunLogPtr, "%s %s: FLOW    : hop_latency = %u\n",qinfo_ms_ctime_buf_min, phase2str(current_phase), qinfo_hop_latency_min);
								}
							}
							else
								{ //must be this
									Pthread_mutex_lock(&hpn_ret_mutex);
									//sHpnRetMsg.pts = qinfo_ms_ctime_buf_max;
									memcpy(sHpnRetMsg.timestamp,qinfo_ms_ctime_buf_max,MS_CTIME_BUF_LEN);
									sHpnRetMsg.hop_latency = qinfo_hop_latency_max;
									sHpnRetMsg.queue_occupancy = qinfo_max_value;
									sHpnRetMsg.switch_id = qinfo_hop_switch_id_max;
									hpnretcdone = 1;
									Pthread_cond_signal(&hpn_ret_cond);
									Pthread_mutex_unlock(&hpn_ret_mutex);
#if 0
									memcpy(metaData[vMetaDataCount].timestamp,qinfo_ms_ctime_buf_max,MS_CTIME_BUF_LEN);
									metaData[vMetaDataCount].hop_latency = qinfo_hop_latency_max;
									metaData[vMetaDataCount].queue_occupancy = qinfo_max_value;
									metaData[vMetaDataCount].switch_id = qinfo_hop_switch_id_max;
							
									vMetaDataCount++;
									if (vMetaDataCount == NUMMETAVALUES)
										vMetaDataCount = 0;
#endif
									if (vDebugLevel == 4)
									{
										fprintf(tunLogPtr, "\n%s %s: ***********************FLOW************************", qinfo_ms_ctime_buf_max, phase2str(current_phase));
										fprintf(tunLogPtr, "\n%s %s: FLOW    : hop_switch_id = %u\n",qinfo_ms_ctime_buf_max, phase2str(current_phase), qinfo_hop_switch_id_max);
										fprintf(tunLogPtr, "%s %s: FLOW    : queue_occupancy = %u\n",qinfo_ms_ctime_buf_max, phase2str(current_phase), qinfo_max_value);
										fprintf(tunLogPtr, "%s %s: FLOW    : hop_latency = %u\n",qinfo_ms_ctime_buf_max, phase2str(current_phase), qinfo_hop_latency_max);
									}
								}
						}
			}
		}
	}
	while(err >= 0);
	fprintf(tunLogPtr,"%s %s: Exited perf event loop with err %d..\n", ms_ctime_buf, phase2str(current_phase), -err);
	}
close_maps: {
	fprintf(tunLogPtr,"%s %s: Closing maps.\n", ms_ctime_buf, phase2str(current_phase));
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
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	int vRetTimer;

	if (!vq_h_TimerIsSet)
	{
		vRetTimer = timer_settime(qOCC_Hop_TimerID, 0, &sStartTimer, (struct itimerspec *)NULL);
		if (!vRetTimer)
		{
			vq_h_TimerIsSet = 1;
			curr_hop_key_hop_index = hop_key_hop_index;
			if (vDebugLevel > 2)
			{
				gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
				fprintf(tunLogPtr,"%s %s: ***WARNING !!! WARNING !!! Timer set to %d microseconds for Queue Occupancy and HopDelay over threshholds***\n",ms_ctime_buf, phase2str(current_phase), gInterval); 
			}
		}
		else
			fprintf(tunLogPtr,"%s %s: ***WARNING !!! WARNING !!! Could not set Timer, vRetTimer = %d,  errno = to %d***\n",ms_ctime_buf, phase2str(current_phase), vRetTimer, errno); 
	}

	return;
}

void EvaluateQOccUserInfo(__u32 hop_key_hop_index)
{
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	int vRetTimer;

	if (!vq_TimerIsSet)
	{
		vRetTimer = timer_settime(qOCC_TimerID, 0, &sStartTimer, (struct itimerspec *)NULL);
		if (!vRetTimer)
		{
			vq_TimerIsSet = 1;
			curr_hop_key_hop_index = hop_key_hop_index;
			if (vDebugLevel > 2)
			{
				gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
				fprintf(tunLogPtr,"%s %s: ***WARNING !!! WARNING !!! Timer set to %d microseconds for Queue Occupancy User Info***\n",ms_ctime_buf, phase2str(current_phase), gInterval); 
			}
		}
		else
			fprintf(tunLogPtr,"%s %s: ***WARNING !!! WARNING !!! Could not set Qinfo User InfoTimer, vRetTimer = %d,  errno = to %d***\n",ms_ctime_buf, phase2str(current_phase), vRetTimer, errno); 
	}

	return;
}

void record_activity(char *pActivity)
{
	char add_to_activity[512];
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];

	static __u32 myCount = 0;
	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
	sprintf(add_to_activity,":::***vFlowcount = %d, num_tuning_activty = %d, myCount = %u",vFlowCount, sFlowCounters[vFlowCount].num_tuning_activities + 1, myCount++);
	strcat(pActivity,add_to_activity);

	if (vDebugLevel > 6)
		fprintf(tunLogPtr,"%s\n",pActivity); //special case for testing - making sure activity is recorded to use with tuncli

	strcpy(sFlowCounters[vFlowCount].what_was_done[sFlowCounters[vFlowCount].num_tuning_activities], pActivity);
	sFlowCounters[vFlowCount].gFlowCountUsed = 1;	

	(sFlowCounters[vFlowCount].num_tuning_activities)++;
	if (sFlowCounters[vFlowCount].num_tuning_activities == MAX_TUNING_ACTIVITIES_PER_FLOW)
	{
		sFlowCounters[vFlowCount].num_tuning_activities = 0;
	}

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
	char ms_ctime_buf[MS_CTIME_BUF_LEN];

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

	if (vDebugLevel > 4)
	{
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(tunLogPtr, "\n%s %s: ***********************FLOW************************", ms_ctime_buf, phase2str(current_phase));
	}

	while (data + data_offset + sizeof(struct int_hop_metadata) <= data_end)
	{
		struct int_hop_metadata *hop_metadata_ptr = data + data_offset;
		data_offset += sizeof(struct int_hop_metadata);
		Qinfo = ntohl(hop_metadata_ptr->queue_info) & 0xffffff;
		ingress_time = ntohl(hop_metadata_ptr->ingress_time);
		egress_time = ntohl(hop_metadata_ptr->egress_time);
		hop_hop_latency_threshold = egress_time - ingress_time;
		
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);

		if (Qinfo < qinfo_min_value)
		{
			qinfo_clk_min = clk;
			qinfo_min_value = Qinfo;
			qinfo_hop_latency_min = hop_hop_latency_threshold;
			qinfo_hop_switch_id_min = ntohl(hop_metadata_ptr->switch_id);
			memcpy(qinfo_ms_ctime_buf_min, ms_ctime_buf, MS_CTIME_BUF_LEN);
		}
		
		if (Qinfo > qinfo_max_value && !perf_buffer_poll_start) //!perf_buffer_poll_start means there was at least 2 metadata info that we got at this point
		{
			qinfo_clk_max = clk;
			qinfo_max_value = Qinfo;
			qinfo_hop_latency_max = hop_hop_latency_threshold;
			qinfo_hop_switch_id_max = ntohl(hop_metadata_ptr->switch_id);
			memcpy(qinfo_ms_ctime_buf_max, ms_ctime_buf, MS_CTIME_BUF_LEN);
		}

		perf_buffer_poll_start = 0;

		if (vDebugLevel > 4)
		{
#if 1
			fprintf(tunLogPtr, "\n%s %s: FLOW    : hop_switch_id = %u\n",ms_ctime_buf, phase2str(current_phase), ntohl(hop_metadata_ptr->switch_id));
			fprintf(tunLogPtr, "%s %s: FLOW    : hop_ingress_port = %d\n",ms_ctime_buf, phase2str(current_phase), ntohs(hop_metadata_ptr->ingress_port_id));
			fprintf(tunLogPtr, "%s %s: FLOW    : hop_egress_port = %d\n",ms_ctime_buf, phase2str(current_phase), ntohs(hop_metadata_ptr->egress_port_id));
			fprintf(tunLogPtr, "%s %s: FLOW    : queue_occupancy = %u\n",ms_ctime_buf, phase2str(current_phase), Qinfo);
			fprintf(tunLogPtr, "%s %s: FLOW    : ingress_time = %u\n",ms_ctime_buf, phase2str(current_phase), ingress_time);
			fprintf(tunLogPtr, "%s %s: FLOW    : egress_time = %u\n",ms_ctime_buf, phase2str(current_phase), egress_time);
			fprintf(tunLogPtr, "%s %s: FLOW    : hop_latency = %u\n",ms_ctime_buf, phase2str(current_phase), hop_hop_latency_threshold);
#endif
		}
#if 1
		if ((hop_hop_latency_threshold > vHOP_LATENCY_DELTA) && (Qinfo > vQUEUE_OCCUPANCY_DELTA))
		{
			if (vDebugLevel > 0)
			{
				gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
				fprintf(tunLogPtr, "%s %s: ***WARNING !!! WARNING !!! Both hop_latency and queue_occupancy is high!!! WARNING !!! WARNING***u\n", ms_ctime_buf, phase2str(current_phase));
				fprintf(tunLogPtr, "%s %s: ***WARNING hop_latency  = %u\n", ms_ctime_buf, phase2str(current_phase), hop_hop_latency_threshold);
				fprintf(tunLogPtr, "%s %s: ***WARNING queue_occupancy = %u\n", ms_ctime_buf, phase2str(current_phase), Qinfo);
			}

			EvaluateQOcc_and_HopDelay(hop_key.hop_index);
		}
		else
			{
				if (vq_h_TimerIsSet)
				{
					timer_settime(qOCC_Hop_TimerID, 0, &sDisableTimer, (struct itimerspec *)NULL);
					vq_h_TimerIsSet = 0;
				}

				if (hop_hop_latency_threshold > vHOP_LATENCY_DELTA)
				{
					if (vDebugLevel > 0)
					{
						fprintf(tunLogPtr, "%s %s: ***WARNING !!! WARNING !!! hop_latency = %u which is high!!! WARNING !!! WARNING***u\n", ms_ctime_buf, phase2str(current_phase), hop_hop_latency_threshold);
					}
				}
			}

#if 1
		//kinda hokey, but will leave this way for now
		if (Qinfo > vQUEUE_OCCUPANCY_DELTA)  
		{
			vQinfoUserValue = Qinfo;
			if (vDebugLevel > 0 && vq_WarningCount < 1)  //print up to 3 times for this timer event, otherwise could flood the log
			{
				gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
				fprintf(tunLogPtr, "%s %s: ***WARNING !!! WARNING !!! queue_occupancy = %u which is high!!! WARNING !!! WARNING***u\n", ms_ctime_buf, phase2str(current_phase), Qinfo);
			}

			vq_WarningCount = 1;
			EvaluateQOccUserInfo(hop_key.hop_index);
		}
		else
			{
				if (vq_TimerIsSet)
				{
					if (vDebugLevel > 0)
						fprintf(tunLogPtr, "%s %s: ***INFO:  queue_occupancy is %u which is lower than threshold. Turning off Timer***u\n", ms_ctime_buf, phase2str(current_phase), Qinfo);

					timer_settime(qOCC_TimerID, 0, &sDisableTimer, (struct itimerspec *)NULL);
					vq_TimerIsSet = 0;
				}
				vq_WarningCount = 0;
			}
#endif
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
					gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
					fprintf(tunLogPtr, "%s %s: ***flow_sink_time = %u\n", ms_ctime_buf, phase2str(current_phase), ingress_time - flow_sink_time_threshold);
				}
			}

			flow_sink_time_threshold = ingress_time;	
		}
		
		flow_threshold_update.hop_latency_threshold += ntohl(hop_metadata_ptr->egress_time) - ntohl(hop_metadata_ptr->ingress_time);
		flow_hop_latency_threshold += ntohl(hop_metadata_ptr->egress_time) - ntohl(hop_metadata_ptr->ingress_time);
		print_hop_key(&hop_key);
#if 1
                if ((src_ip_addr.y != ntohl(hop_key.flow_key.src_ip)) || new_traffic)
                //if ((src_ip_addr.y != ntohl(hop_key.flow_key.src_ip)) || new_traffic)
                {
			new_traffic = 0;
			src_ip_addr.y = ntohl(hop_key.flow_key.src_ip);
		//	src_ip_addr.y = hop_key.flow_key.src_ip;
			if (vDebugLevel > 4)
			{
				gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
				fprintf(tunLogPtr, "%s %s: ***new traffic???***\n", ms_ctime_buf, phase2str(current_phase));
			}
#if 1
			vIamADestDtn  = 1;
                        Pthread_mutex_lock(&dtn_mutex);
                        strcpy(sMsg.msg, "Hello there!!! This is a Start of Traffic  msg...\n");
                        sMsg.msg_no = htonl(TEST_MSG);
			sMsg.value = htonl(0);
			sMsgSeqNo++;
			sMsg.seq_no = htonl(sMsgSeqNo);
                        cdone = 1;
                        Pthread_cond_signal(&dtn_cond);
                        Pthread_mutex_unlock(&dtn_mutex);
#endif
		}
#endif
#ifdef INCLUDE_SRC_PORT
		//src_port = ntohs(hop_key.flow_key.src_port);
		src_port = hop_key.flow_key.src_port;
#endif
		hop_key.hop_index++;

	}

	flow_threshold_update.total_hops = hop_key.hop_index;
	bpf_map_update_elem(ctx->flow_thresholds, &hop_key.flow_key, &flow_threshold_update, BPF_ANY);
	struct counter_set empty_counter = {};
	bpf_map_update_elem(ctx->flow_counters, &(hop_key.flow_key), &empty_counter, BPF_NOEXIST);

	if (vDebugLevel > 6)
	{
		if (flow_hop_latency_threshold > vFLOW_LATENCY_DELTA)
		{
			gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
			fprintf(tunLogPtr, "%s %s: ***flow_total_time_in_all_hops = %lld\n", ms_ctime_buf, phase2str(current_phase), flow_hop_latency_threshold);
		}
	}
		
	fflush(tunLogPtr);
}

void lost_func(struct threshold_maps *ctx, int cpu, __u64 cnt)
{
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];

	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
	fprintf(tunLogPtr, "%s %s: Missed %llu sets of packet metadata.\n", ms_ctime_buf, phase2str(current_phase), cnt);
	fflush(tunLogPtr);
}
	
void print_flow_key(struct flow_key *key, char ms_ctime_buf[])
{
	fprintf(tunLogPtr,"%sFLOW    : Flow Key:\n", pLearningSpaces);
	fprintf(tunLogPtr,"%sFLOW    : \tflow_switch_id:%u\n", pLearningSpaces, key->switch_id);
	fprintf(tunLogPtr,"%sFLOW    : \tflow_egress_port:%hu\n", pLearningSpaces, key->egress_port);
	fprintf(tunLogPtr,"%sFLOW    : \tvlan_id:%hu\n", pLearningSpaces, key->vlan_id);
#ifdef INCLUDE_SRC_PORT
	if (src_ip_addr.y)
		fprintf(tunLogPtr,"%sFLOW    : \tsrc_ip:%u.%u.%u.%u, src_port:%d", pLearningSpaces, src_ip_addr.a[0],src_ip_addr.a[1],src_ip_addr.a[2],src_ip_addr.a[3], src_port);
#else
	if (src_ip_addr.y)
		fprintf(tunLogPtr,"%sFLOW    : \tsrc_ip:%u.%u.%u.%u", pLearningSpaces, src_ip_addr.a[0],src_ip_addr.a[1],src_ip_addr.a[2],src_ip_addr.a[3]);
#endif
}

void print_hop_key(struct hop_key *key)
{
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	if (vDebugLevel > 5 )
	{
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		//fprintf(tunLogPtr,"%s %s: Hop Key:\n", ctime_buf, phase2str(current_phase));
		print_flow_key(&(key->flow_key), ms_ctime_buf);
		fprintf(tunLogPtr,"  ***hop_index: %X\n", key->hop_index);
	}
}
/* End of bpf stuff ****/

/***** HTTP *************/
void check_req(http_s *h, char aResp[])
{
	FIOBJ r = http_req2str(h);
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	char aHttpRequest[256];
	char * pReqData = fiobj_obj2cstr(r).data;
	int count = 0;
	char aSettingFromHttp[512];
	char aNumber[16];
	
	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
	fprintf(tunLogPtr,"%s %s: ***Received Data from Http Client***\nData is:\n", ms_ctime_buf, phase2str(current_phase));
	fprintf(tunLogPtr,"%s", pReqData);

	memset(aNumber,0,sizeof(aNumber));

	if (strstr(pReqData,"GET /-t"))
	{
		//Apply tuning
		strcpy(aResp,"Recommended Tuning applied!!!\n");
	
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to apply recommended Tuning***\n", ms_ctime_buf, phase2str(current_phase));
		fprintf(tunLogPtr,"%s %s: ***Applying recommended Tuning now***\n", ms_ctime_buf, phase2str(current_phase));
		sprintf(aHttpRequest,"sh ./user_menu.sh apply_all_recommended_settings");
		system(aHttpRequest);
		goto after_check;
	}

	if (strstr(pReqData,"GET /-pc"))
	{
		//Get counters
		int i, g, start = 0, vNoactivitySoFar = 0, vLoopMax = 0;
		
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to provide counters of tuning activities throughout data transfer***\n", ms_ctime_buf, phase2str(current_phase));

		if (vFlowCountWrapped) //array wrapped already
			vLoopMax = NUM_OF_FLOWS_TO_KEEP_TRACK_OF;
		else
			vLoopMax = vFlowCount + 1;

		for (g = 0; g < vLoopMax; g++)
		{
			if (sFlowCounters[g].num_tuning_activities == 0 && !sFlowCounters[g].gFlowCountUsed && !vFlowCountWrapped && !g) 
			{
				strcpy(aResp,"***No tuning activity has happened so far***\n");
				start = strlen(aResp);
				vNoactivitySoFar = 1;
			}
			else
				{
					int num_activities;
						
					if (sFlowCounters[g].num_tuning_activities == 0 && sFlowCounters[g].gFlowCountUsed)
						num_activities = MAX_TUNING_ACTIVITIES_PER_FLOW; //This means num_tuning_activities got recycled to zero, but it was really maxed out
					else
						num_activities = sFlowCounters[g].num_tuning_activities; 

					for (i = 0; i < num_activities; i++)
					{
						vNoactivitySoFar = 0;
						memcpy(aResp+start, sFlowCounters[g].what_was_done[i], strlen(sFlowCounters[g].what_was_done[i]));
						start = start + strlen(sFlowCounters[g].what_was_done[i]);
						aResp[start] = '\n';
						start++;
					}
				}
		}

		aResp[start-1] = 0;

		if (vNoactivitySoFar)
			fprintf(tunLogPtr,"%s***Tuning Activities*** \n%s%s\n", pLearningSpaces, pLearningSpaces, aResp);
		else
			fprintf(tunLogPtr,"%s***Tuning Activities*** \n%s\n", pLearningSpaces, aResp);

		fprintf(tunLogPtr,"%s***End of Tuning Activities***\n\n", pLearningSpaces);

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
		
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to change debug level of Tuning Module from %d to %d***\n", ms_ctime_buf, phase2str(current_phase), vDebugLevel, vNewDebugLevel);
		vDebugLevel = vNewDebugLevel;
		fprintf(tunLogPtr,"%s %s: ***New debug level is %d***\n", ms_ctime_buf, phase2str(current_phase), vDebugLevel);
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
		
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to change Tuning Module learning mode from %s to on***\n", ms_ctime_buf, phase2str(current_phase), aMode);
		
		gTuningMode = 0;
		fprintf(tunLogPtr,"%s %s: ***Tuning Module is now in learning mode***\n", ms_ctime_buf, phase2str(current_phase));
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
		
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to change Tuning Module learning mode from %s to off***\n", ms_ctime_buf, phase2str(current_phase), aMode);
		
		gTuningMode = 1;
		fprintf(tunLogPtr,"%s %s: ***Tuning Module is now *not* in learning mode***\n", ms_ctime_buf, phase2str(current_phase));
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
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to change flow sink time delta from %u to %u***\n", ms_ctime_buf, phase2str(current_phase), vFLOW_SINK_TIME_DELTA, vNewFlowSinkTimeDelta);
		vFLOW_SINK_TIME_DELTA = vNewFlowSinkTimeDelta;
		fprintf(tunLogPtr,"%s %s: ***New flow sink time delta value is *%u***\n", ms_ctime_buf, phase2str(current_phase), vFLOW_SINK_TIME_DELTA);
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
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to change queue occupancy delta from %u to %u***\n", ms_ctime_buf, phase2str(current_phase), vQUEUE_OCCUPANCY_DELTA, vNewQueueOccupancyDelta);
		vQUEUE_OCCUPANCY_DELTA = vNewQueueOccupancyDelta;
		fprintf(tunLogPtr,"%s %s: ***New queue occupancy delta value is *%u***\n", ms_ctime_buf, phase2str(current_phase), vQUEUE_OCCUPANCY_DELTA);
		goto after_check;
	}

	if (strstr(pReqData,"GET /-ct#retrans_rate#"))
	{
		/* Change the value of the retransmits allwoed per sec */
		double vNewRetransRate = 0.0;
		int countdots = 0;

		char *p = (pReqData + sizeof("GET /-ct#retrans_rate#")) - 1;

		while ((isdigit(*p) || (*p == '.')) && countdots <= 1)
		{
			if (*p == '.') countdots++;
			aNumber[count++] = *p;
			p++;
		}
        
		if (countdots > 1)
        	{
			fprintf(tunLogPtr,"%s %s: ***Received **INVALID** request from Http Client to change maximum retransmission rate. Number is invalid: *%s***\n", ms_ctime_buf, phase2str(current_phase), aNumber);
			sprintf(aResp,"***ERROR: Number is invalid for retransmission rate: *%s***\n", aNumber);
			goto after_check;
		}

        	sscanf(aNumber,"%lf", &vNewRetransRate);
		sprintf(aResp,"Changed  maximum retransmission rate allowed from %.5f to %.5f!\n", vRetransmissionRateThreshold, vNewRetransRate);
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to change maximum retransmission rate allowed from %.5f to %.5f***\n", ms_ctime_buf, phase2str(current_phase), vRetransmissionRateThreshold, vNewRetransRate);
		vRetransmissionRateThreshold = vNewRetransRate;
		fprintf(tunLogPtr,"%s %s: ***New retransmission rate allowed is *%.5f***\n", ms_ctime_buf, phase2str(current_phase), vRetransmissionRateThreshold);
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
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to change hop latency delta from %u to %u***\n", ms_ctime_buf, phase2str(current_phase), vHOP_LATENCY_DELTA, vNewHopLatencyDelta);
		vHOP_LATENCY_DELTA = vNewHopLatencyDelta;
		fprintf(tunLogPtr,"%s %s: ***New hop latency delta value is *%u***\n", ms_ctime_buf, phase2str(current_phase), vHOP_LATENCY_DELTA);
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
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to change flow latency delta from %u to %u***\n", ms_ctime_buf, phase2str(current_phase), vFLOW_LATENCY_DELTA, vNewFlowLatencyDelta);
		vFLOW_LATENCY_DELTA = vNewFlowLatencyDelta;
		fprintf(tunLogPtr,"%s %s: ***New flow latency delta value is *%u***\n", ms_ctime_buf, phase2str(current_phase), vFLOW_LATENCY_DELTA);
		goto after_check;
	}
			
	if (strstr(pReqData,"GET /-rtt#thresh#"))
	{
		/* Change the value of the flow latency delta */
		int vNewRttThreshold = 0;
		char *p = (pReqData + sizeof("GET /-rtt#thresh#")) - 1;
		while (isdigit(*p))
		{
			aNumber[count++] = *p;
			p++;
		}

		vNewRttThreshold = strtoul(aNumber, (char **)0, 10);
		sprintf(aResp,"Changed rtt threshold from %.2fms to %.2fms!\n", rtt_threshold, vNewRttThreshold*1.0);
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to change rtt threshold from %.2fms to %.2fms***\n", ms_ctime_buf, phase2str(current_phase), rtt_threshold, vNewRttThreshold*1.0);
		rtt_threshold = vNewRttThreshold;
		fprintf(tunLogPtr,"%s %s: ***New RTT THRESHOLD value is *%.2fms***\n", ms_ctime_buf, phase2str(current_phase), rtt_threshold);
		goto after_check;
	}

	if (strstr(pReqData,"GET /-rtt#factor#"))
	{
		/* Change the value of the flow latency delta */
		int vNewRttFactor = 0;
		char *p = (pReqData + sizeof("GET /-rtt#factor#")) - 1;
		while (isdigit(*p))
		{
			aNumber[count++] = *p;
			p++;
		}

		vNewRttFactor = strtoul(aNumber, (char **)0, 10);
		sprintf(aResp,"Changed rtt factor from %d to %d!\n", rtt_factor, vNewRttFactor);
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to change rtt factor from %d to %d***\n", ms_ctime_buf, phase2str(current_phase), rtt_factor, vNewRttFactor);
		rtt_factor = vNewRttFactor;
		fprintf(tunLogPtr,"%s %s: ***New RTT FACTOR value is *%d***\n", ms_ctime_buf, phase2str(current_phase), rtt_factor);
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
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to change RX ring buffer size of %s to %s***\n", ms_ctime_buf, phase2str(current_phase), netDevice, aNumber);
		fprintf(tunLogPtr,"%s %s: ***Changing RX buffer size now***\n", ms_ctime_buf, phase2str(current_phase));
		sprintf(aSettingFromHttp,"ethtool -G %s rx %s", netDevice, aNumber);
		
		fprintf(tunLogPtr,"%s %s: ***Doing *%s***\n", ms_ctime_buf, phase2str(current_phase), aSettingFromHttp);
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
		
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to change TX ring buffer size of %s to %s***\n", ms_ctime_buf, phase2str(current_phase), netDevice, aNumber);
		fprintf(tunLogPtr,"%s %s: ***Changing TX buffer size now***\n", ms_ctime_buf, phase2str(current_phase));
		sprintf(aSettingFromHttp,"ethtool -G %s tx %s", netDevice, aNumber);
		
		fprintf(tunLogPtr,"%s %s: ***Doing *%s***\n", ms_ctime_buf, phase2str(current_phase), aSettingFromHttp);
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
		
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to change the maximum OS receive buffer size for all types of connections to %s***\n", ms_ctime_buf, phase2str(current_phase), aNumber);
		fprintf(tunLogPtr,"%s %s: ***Changing receive buffer size now***\n", ms_ctime_buf, phase2str(current_phase));
		sprintf(aSettingFromHttp,"sysctl -w net.core.rmem_max=%s", aNumber);
		
		fprintf(tunLogPtr,"%s %s: ***Doing *%s***\n", ms_ctime_buf, phase2str(current_phase), aSettingFromHttp);
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
		
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received request from Http Client to change the maximum OS send buffer size for all types of connections to %s***\n", ms_ctime_buf, phase2str(current_phase), aNumber);
		fprintf(tunLogPtr,"%s %s: ***Changing send buffer size now***\n", ms_ctime_buf, phase2str(current_phase));
		sprintf(aSettingFromHttp,"sysctl -w net.core.wmem_max=%s", aNumber);
		
		fprintf(tunLogPtr,"%s %s: ***Doing *%s***\n", ms_ctime_buf, phase2str(current_phase), aSettingFromHttp);
		system(aSettingFromHttp);
		goto after_check;
	}

	{
		strcpy(aResp,"Received something else!!!\n");
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Received some kind of request from Http Client***\n", ms_ctime_buf, phase2str(current_phase));
		fprintf(tunLogPtr,"%s %s: ***Applying some kind of request***\n", ms_ctime_buf, phase2str(current_phase));
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
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
  	char aListenPort[32];	

	/* listen for inncoming connections */
	sprintf(aListenPort,"%d",gAPI_listen_port);
	if (http_listen(aListenPort, NULL, .on_request = on_http_request) == -1) 
	{
    		/* listen failed ?*/
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***ERROR: facil couldn't initialize HTTP service (already running?)...***\n", ms_ctime_buf, phase2str(current_phase));
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
	char ms_ctime_buf[MS_CTIME_BUF_LEN];

	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
	fprintf(tunLogPtr,"%s %s: ***Starting Http Server ...***\n", ms_ctime_buf, phase2str(current_phase));
	fflush(tunLogPtr);
	initialize_http_service();
	/* start facil */
	fio_start(.threads = 1, .workers = 0);
	return ((char *)0);
}

void fGetMtuInfoOfDevices(void)
{

	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	char log_inter[128];
        char buffer[128];
        char buffer2[128];
	FILE *pipe1, *pipe2, *pipe3;
	char try[1024];
	char * foundstr = 0;
	int found = 0;

	memset(log_inter,0,128);
	sprintf(try,"ip route | grep %s", aLocal_Ip);

	pipe1 = popen(try,"r");
	if (!pipe1)
	{
		printf("popen failed!\n");
		return;
	}

	while (!feof(pipe1))
	{
		// use buffer to read and add to result
		if (fgets(buffer, 128, pipe1) != NULL);
		else
			{
				goto finish_up;
			}

		foundstr = strstr(buffer,"dev");
		//should look like example: "10.35.1.0/24 dev vlan3501 proto kernel scope link src 10.35.1.1 advmss 9164"
		if (foundstr)
		{
			foundstr = strchr(foundstr,' ');
			if (foundstr)
			{
				char * q = 0;
				foundstr++; //move up one to get to actual device name
				q = strchr(foundstr,' ');
				if (q)
				{
					strncpy(log_inter,foundstr,q-foundstr);
					found = 1;
					break;
				}
			}
		}
		else
			continue;
	}

finish_up:
	pclose(pipe1);
	if (found)
	{
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(tunLogPtr, "%sBITRATE : !!!*****PLEASE CHECK IF MTU of Physical Interface \"%s\" is correct or MTU of Interface \"%s\" is correct********!!!\n",
			pLearningSpacesMinusLearning, netDevice, log_inter);
		
		sprintf(try,"cat /sys/class/net/%s/mtu", log_inter);

		pipe2 = popen(try,"r");
		if (!pipe2)
		{
			printf("popen failed!\n");
			return;
		}
		if (fgets(buffer, 128, pipe2) != NULL);
		else
			{
				pclose(pipe2);
				return;
			}

		pclose(pipe2);		


		fprintf(tunLogPtr, "%sBITRATE : !!!***** MTU of %s is %s", pLearningSpacesMinusLearning, log_inter, buffer);
		
		sprintf(try,"cat /sys/class/net/%s/mtu", netDevice);

		pipe3 = popen(try,"r");
		if (!pipe3)
		{
			printf("popen failed!\n");
			return;
		}
		if (fgets(buffer2, 128, pipe3) != NULL);
		else
			{
				pclose(pipe3);
				return;
			}

		pclose(pipe3);		
		
		fprintf(tunLogPtr, "%sBITRATE : !!!***** MTU of %s is %s", pLearningSpacesMinusLearning, netDevice, buffer2);

		if(strcmp(buffer, buffer2) != 0)
			fprintf(tunLogPtr, "%sBITRATE : !!!***** WARNING ***** ABOVE MTUs are NOT the same*****!!!\n", pLearningSpacesMinusLearning);

		fflush(tunLogPtr);
        }

return;
}

#define BITRATE_INTERVAL 1
#define KTUNING_DELTA	200000
extern int my_tune_max;
void check_if_bitrate_too_low(double average_tx_Gbits_per_sec, int * applied, int * suggested, int * nothing_done, int * tune, char aApplyDefTun[MAX_SIZE_SYSTEM_SETTING_STRING]);
void check_if_bitrate_too_low(double average_tx_Gbits_per_sec, int * applied, int * suggested, int * nothing_done, int * tune, char aApplyDefTun[MAX_SIZE_SYSTEM_SETTING_STRING])
{
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	char buffer[256];
	FILE *pipe;
	char kernel_parameter[128];
	char equal_sign;
	unsigned int  kminimum;
	int kdefault;
	unsigned int kmaximum;
	static time_t delta = 0;

	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
	if (average_tx_Gbits_per_sec < vGoodBitrateValue)
	{
#if 0
		fprintf(tunLogPtr,"%s %s: average_tx_Gbits_per_sec = %.2f Gb/s, vGoodBitrateValue Gb/s = %.2f \n",ctime_buf, phase2str(current_phase), average_tx_Gbits_per_sec, vGoodBitrateValue);
		fflush(tunLogPtr);
#endif
		if (current_phase == TUNING)
		{
			fprintf(tunLogPtr, "%s %s: Trying to tune net.ipv4.tcp_wmem, but already TUNING something else.  Will retry later if still need TUNING***\n",ms_ctime_buf, phase2str(current_phase));

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
					gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
					current_phase = TUNING;
					//fprintf(tunLogPtr, "%s %s: Changed current phase***\n",ctime_buf, phase2str(current_phase));
					//do something
					if (my_tune_max <= kmaximum) //already high
					{
						if (vDebugLevel > 4)
						{
							fprintf(tunLogPtr, "%s %s: ***CURRENT TUNING***: %s",ms_ctime_buf, phase2str(current_phase), buffer);
							fprintf(tunLogPtr, "%s %s: *** Current Tuning of net.ipv4.tcp_wmem appears sufficient***\n", ms_ctime_buf, phase2str(current_phase));
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
								
											fprintf(tunLogPtr, "%s %s: ***Could not apply tuning since the maximum value of wmem would be less than %d...***\n",ms_ctime_buf, phase2str(current_phase), 600000 - KTUNING_DELTA);
											current_phase = LEARNING; //change back phase to LEARNING
											*nothing_done = 1;
											return;	
										}
								}
								else
									if (*tune == 3)
									{
										fprintf(tunLogPtr,"%s %s: ***No better change found. Using ***%s***\n\n", ms_ctime_buf, phase2str(current_phase), aApplyDefTun);
									}
									else
										{
											fprintf(tunLogPtr, "%s %s: ***Could not apply tuning*** invalid value for tune %d***\n",ms_ctime_buf, phase2str(current_phase), *tune);
											current_phase = LEARNING; //change back phase to LEARNING
											*nothing_done = 1;
											return;	
										}

							fprintf(tunLogPtr, "%s %s: ***CURRENT TUNING***: %s",ms_ctime_buf, phase2str(current_phase), buffer);
							strcpy(aApplyDefTunNoStdOut,aApplyDefTun);
							strcat(aApplyDefTunNoStdOut," >/dev/null"); //so it won't print to stderr on console
							system(aApplyDefTunNoStdOut);

							delta = delta + calculate_delta_for_csv();
							fprintf(csvLogPtr,"%lu,%s,%s\n",delta,aName,aValue);
							fflush(csvLogPtr);

							fprintf(tunLogPtr, "%s %s: ***APPLIED TUNING***: %s\n\n",ms_ctime_buf, phase2str(current_phase), aApplyDefTun);

							sprintf(activity,"%s %s: ***ACTIVITY=APPLIED TUNING***: %s",ms_ctime_buf, phase2str(current_phase), aApplyDefTun);
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
							if (vDebugLevel > 4)
							{
								fprintf(tunLogPtr, "%s %s: ***CURRENT TUNING***: %s",ms_ctime_buf, phase2str(current_phase), buffer);
								fprintf(tunLogPtr, "%s %s: *** Current Tuning of net.ipv4.tcp_wmem appears sufficient***\n", ms_ctime_buf, phase2str(current_phase));
							}
						}
						else
							{
								*suggested = 1;
								if (vDebugLevel > 0)
								{
									//don't apply - just log suggestions - decided to use a debug level here because this file could fill up if user never accepts recommendation
									fprintf(tunLogPtr, "%s %s: ***CURRENT TUNING***: *%s",ms_ctime_buf, phase2str(current_phase), buffer);
									fprintf(tunLogPtr, "%s %s: ***SUGGESTED TUNING***: *sudo sysctl -w net.ipv4.tcp_wmem=\"%u %d %u\"\n\n",ms_ctime_buf, phase2str(current_phase), kminimum, kdefault, kmaximum+KTUNING_DELTA);
								}
							}
					}
			}
		
		if ((vDebugLevel > 1) && (average_tx_Gbits_per_sec < vGoodBitrateValueThatDoesntNeedMessage ))
		{
			fprintf(tunLogPtr, "%s %s: !!!*****BITRATE IS LOW********!!!\n", ms_ctime_buf, phase2str(current_phase));
			if (aLocal_Ip[0])
				fGetMtuInfoOfDevices();
			else
				fprintf(tunLogPtr, "%s!!!*****PLEASE CHECK IF MTU of device \"%s\" is correct or MTU of VLANS on %s are correct********!!!\n", pLearningSpaces, netDevice, netDevice);
		}
	}
        
	fflush(tunLogPtr);
	return;
}

#define MAX_TUNING_APPLY	10
static double previous_average_tx_Gbits_per_sec = 0.0;

double fCheckAppBandwidth(char app[])
{
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	char buffer[128];
	FILE *pipe;
	char try[1024];
	unsigned long vBandWidthInBits = 0;
	double vBandWidthInGBits = 0;

	sprintf(try,"bpftrace -e \'BEGIN { zero(@size); zero(@sum); } kprobe:tcp_sendmsg /comm == \"%s\"/ { @size = arg2; } kretprobe:tcp_sendmsg /comm == \"%s\"/ { @sum = @sum + @size; } interval:ms:1002 { exit(); } END { printf(\"%s\", @sum); clear(@size); clear(@sum); }\'",app,app,"%lu");

	pipe = popen(try,"r");
	if (!pipe)
	{
		printf("popen failed!\n");
		printf("here37***\n");
		return 0;
	}

	while (!feof(pipe))
	{
		// use buffer to read and add to result
		if (fgets(buffer, 128, pipe) != NULL); //don't need first line
		else
			break;
		if (fgets(buffer, 128, pipe) != NULL)
		{
			sscanf(buffer,"%lu", &vBandWidthInBits); //next line
			vBandWidthInBits = ((8 * vBandWidthInBits) / 1000);	//really became kilobits here
			vBandWidthInGBits = vBandWidthInBits/(double)(1000000);
			
			gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);

			fprintf(tunLogPtr,"%s %s: ***The app \"%s\" is using a Bandwidth of %.2f Gb/s\n", ms_ctime_buf, phase2str(current_phase), app, vBandWidthInGBits); //only need this one buffer
			while (fgets(buffer, 128, pipe) != NULL); //dump the buffers after
			break;
		}
		else
			break;
	}

	pclose(pipe);

	fflush(tunLogPtr);
return 0;
}


double fGetAppBandWidth()
{

	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	char buffer[256];
	FILE *pipe;
	char try[1024];
	int found = 0;
	static int nolsof = 0;
	char * q = 0;
	char value[256];
	char previous_value[256];

	if (nolsof)
		return 0;

	if (aDest_Ip2[0] == 0)
	{
		return 0; //didn't get  a message from the peer yet
	}

	strcpy(previous_value," ");
	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);

	sprintf(try,"lsof | grep %s:",aDest_Ip2);

	pipe = popen(try,"r");
	if (!pipe)
	{
		printf("popen failed!\n");
		printf("here17***\n");
		return 0;
	}

	found = 1;

	while (!feof(pipe))
	{
		// use buffer to read and add to result
		if (fgets(buffer, 256, pipe) != NULL)
		{
			memset(value,0,256);
			q = strchr(buffer,' ');
			if (q)
				strncpy(value,buffer,q-buffer);

			if (q)
			{
				if (strcmp(previous_value,value) != 0)
					fCheckAppBandwidth(value);
				else
					strcpy(previous_value,value);
			}
		}
		else
			break;
	}

	pclose(pipe);

	if (!found)
	{
		nolsof = 1;
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(tunLogPtr,"\n%s %s: ***!!!ERROR!!!**** Could not find \"lsof\" to get App Bandwidth***\n", ms_ctime_buf, phase2str(current_phase));
	}

	fflush(tunLogPtr);

return found;
}

#ifdef HPNSSH_QFACTOR
void fDoHpnRead(unsigned int val, int sockfd);
void fDoHpnReadAll(unsigned int val, int sockfd);
void fDoHpnShutdown(unsigned int val, int sockfd);
void fDoHpnStart(unsigned int val, int sockfd);
void fDoHpnAssessment(unsigned int val, int sockfd);

void fDoHpnRead(unsigned int val, int sockfd)
{
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	struct PeerMsg sRetMsg;
	struct PeerMsg sRetMsg2;
	int y,n;
	struct timeval tv;
	struct timespec ts;
	int saveerrno = 0;
	char mychar;
	int two = 0;
	
	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
	if (vDebugLevel > 6)
		fprintf(tunLogPtr,"%s %s: ***INFO***: In fDoHpnRead(), value is %u***\n", ms_ctime_buf, phase2str(current_phase), val);
	
#ifdef HPNSSH_QFACTOR_BINN 
	//BINN objects are cross platform - no need for big endian, littl endian worries - so sayeth the binn repo
	sRetMsg.msg_no = HPNSSH_MSG;
	sRetMsg.value = HPNSSH_READ_FS;
	sRetMsg2.msg_no = HPNSSH_MSG;
	sRetMsg2.value = HPNSSH_READ_FS;
#else
	sRetMsg.msg_no = htonl(HPNSSH_MSG);
	sRetMsg.value = htonl(HPNSSH_READ_FS);
	sRetMsg2.msg_no = htonl(HPNSSH_MSG);
	sRetMsg2.value = htonl(HPNSSH_READ_FS);
#endif

read_again:
	Pthread_mutex_lock(&hpn_ret_mutex);
	if (gettimeofday(&tv, NULL) < 0)
		err_sys("gettimeofday error");
	ts.tv_sec = tv.tv_sec + 5; //seconds in future
	ts.tv_nsec = tv.tv_usec * 1000; //microsec to nanosec

	while(hpnretcdone == 0)
		if ( (n = pthread_cond_timedwait(&hpn_ret_cond, &hpn_ret_mutex, &ts)) != 0)
		{
			saveerrno = errno;
			gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
			if (vDebugLevel > 8)
				fprintf(tunLogPtr,"%s %s: ***INFO***: In fDoHpnRead(),  errno = %d, n= %d**\n", ms_ctime_buf, phase2str(current_phase), saveerrno,n);

			if (n == ETIME || n == ETIMEDOUT) //apparently n could also be ETIME although man notes only mention ETIMEDOUT
			{
				if (vDebugLevel > 7)
				{
					fprintf(tunLogPtr,"%s %s: ***WARNING***: In fDoHpnRead(), wait condition timed out errno = %d, n= %d**\n", ms_ctime_buf, phase2str(current_phase), saveerrno,n);
					fflush(tunLogPtr);
				}

				Pthread_mutex_unlock(&hpn_ret_mutex); //release the Kraken
				//goto read_again;
				y = recv(sockfd, &mychar, 1, MSG_DONTWAIT|MSG_PEEK);
				saveerrno = errno;
				if (vDebugLevel > 6)
				{
					fprintf(tunLogPtr,"%s %s: ***INFO***: In fDoHpnRead(), after recv(), errno = %d, y= %d**\n", ms_ctime_buf, phase2str(current_phase), saveerrno,y);
					fflush(tunLogPtr);
				}

				if (saveerrno && !y) //cpnnection dropped on client side
				{
					if (vDebugLevel > 1)
					{
						fprintf(tunLogPtr,"%s %s: ***INFO***: client closed connection, returning from read fDoHpnRead()****\n", ms_ctime_buf, phase2str(current_phase));
						fflush(tunLogPtr);
					}

					return;
				}
				else
					goto read_again;

				//y = str_cli(sockfd, &sTimeoutMsg);
				//return;
			}
                }	
		//Pthread_cond_wait(&hpn_ret_cond, &hpn_ret_mutex);
	
	//memcpy(sRetMsg.timestamp, sHpnRetMsg.pts, MS_CTIME_BUF_LEN);
	memcpy(sRetMsg.timestamp, sHpnRetMsg.timestamp, MS_CTIME_BUF_LEN);
#ifdef HPNSSH_QFACTOR_BINN 
	sRetMsg.hop_latency = sHpnRetMsg.hop_latency;
	sRetMsg.queue_occupancy = sHpnRetMsg.queue_occupancy;
	sRetMsg.switch_id = sHpnRetMsg.switch_id;
#else
	sRetMsg.hop_latency = htonl(sHpnRetMsg.hop_latency);
	sRetMsg.queue_occupancy = htonl(sHpnRetMsg.queue_occupancy);
	sRetMsg.switch_id = htonl(sHpnRetMsg.switch_id);
#endif
	sHpnRetMsg.pts = 0;

	if(sHpnRetMsg2.pts)
	{
		memcpy(sRetMsg2.timestamp, sHpnRetMsg2.pts, MS_CTIME_BUF_LEN);
#ifdef HPNSSH_QFACTOR_BINN 
       		sRetMsg2.hop_latency = sHpnRetMsg2.hop_latency;
        	sRetMsg2.queue_occupancy = sHpnRetMsg2.queue_occupancy;
        	sRetMsg2.switch_id = sHpnRetMsg2.switch_id;
#else
       		sRetMsg2.hop_latency = htonl(sHpnRetMsg2.hop_latency);
        	sRetMsg2.queue_occupancy = htonl(sHpnRetMsg2.queue_occupancy);
        	sRetMsg2.switch_id = htonl(sHpnRetMsg2.switch_id);
#endif
		sHpnRetMsg2.pts = 0;
		two = 1;
	}
	
	hpnretcdone = 0;
	Pthread_mutex_unlock(&hpn_ret_mutex);
#if 0	
	if (!str_cli(sockfd, &sRetMsg))
		goto read_again;
	
	fprintf(tunLogPtr,"%s %s: ***WARNING***: client closed connection, EPIPE error???****\n", ms_ctime_buf, phase2str(current_phase));
	fflush(tunLogPtr);
#endif
	if (two)
	{
		two = 0;
		//y = str_cli(sockfd, &sRetMsg);
		y = str_cli(sockfd, &sRetMsg2);
	}
	else
		y = str_cli(sockfd, &sRetMsg);

return;
}

void fDoHpnReadAll(unsigned int val, int sockfd)
{
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	struct PeerMsg sRetMsg;
	struct PeerMsg sRetMsg2;
	int y,n;
	struct timeval tv;
	struct timespec ts;
	int saveerrno = 0;
	char mychar;
	int two = 0;
	
	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
	if (vDebugLevel > 0)
		fprintf(tunLogPtr,"%s %s: ***INFO***: In fDoHpnReadAll(), value is %u***\n", ms_ctime_buf, phase2str(current_phase), val);
	
	strcpy(sRetMsg.msg, "Hello there!!! Got your ReadAll message..., Here's some data\n");
	strcpy(sRetMsg2.msg, "Hello there!!! Got your ReadAll message..., Here's some data\n");
#ifdef HPNSSH_QFACTOR_BINN 
	//BINN objects are cross platform - no need for big endian, littl endian worries - so sayeth the binn repo
	sRetMsg.msg_no = HPNSSH_MSG;
	sRetMsg.value = HPNSSH_READALL_FS;
	sRetMsg2.msg_no = HPNSSH_MSG;
	sRetMsg2.value = HPNSSH_READALL_FS;
#else
	sRetMsg.msg_no = htonl(HPNSSH_MSG);
	sRetMsg.value = htonl(HPNSSH_READALL_FS);
	sRetMsg2.msg_no = htonl(HPNSSH_MSG);
	sRetMsg2.value = htonl(HPNSSH_READALL_FS);
#endif
read_again:
	Pthread_mutex_lock(&hpn_ret_mutex);
	if (gettimeofday(&tv, NULL) < 0)
		err_sys("gettimeofday error");
	ts.tv_sec = tv.tv_sec + 5; //seconds in future
	ts.tv_nsec = tv.tv_usec * 1000; //microsec to nanosec

	while(hpnretcdone == 0)
		if ( (n = pthread_cond_timedwait(&hpn_ret_cond, &hpn_ret_mutex, &ts)) != 0)
		{
			saveerrno = errno;
			gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
			if (vDebugLevel > 8)
				fprintf(tunLogPtr,"%s %s: ***INFO***: In fDoHpnReadAll(),  errno = %d, n= %d**\n", 
									ms_ctime_buf, phase2str(current_phase), saveerrno,n);

			if (n == ETIME || n == ETIMEDOUT) //apparently n could also be ETIME although man notes only mention ETIMEDOUT
			{
				if (vDebugLevel > 7)
				{
					fprintf(tunLogPtr,"%s %s: ***WARNING***: In fDoHpnReadAll(), wait condition timed out errno = %d, n= %d**\n", 
													ms_ctime_buf, phase2str(current_phase), saveerrno,n);
					fflush(tunLogPtr);
				}

				Pthread_mutex_unlock(&hpn_ret_mutex); //release the Kraken
				//goto read_again;
				y = recv(sockfd, &mychar, 1, MSG_DONTWAIT|MSG_PEEK);
				saveerrno = errno;
				if (vDebugLevel > 6)
				{
					fprintf(tunLogPtr,"%s %s: ***WARNING***: In fDoHpnReadAll(), after recv(), errno = %d, y= %d**\n", 
												ms_ctime_buf, phase2str(current_phase), saveerrno,y);
					fflush(tunLogPtr);
				}

				if (saveerrno && !y) //cpnnection dropped on client side
				{
					if (vDebugLevel > 1)
					{
						fprintf(tunLogPtr,"%s %s: ***INFO***: client closed connection, returning from read fDoHpnReadAll()****\n", 
															ms_ctime_buf, phase2str(current_phase));
						fflush(tunLogPtr);
					}
				
					return;
				}
				else
					goto read_again;

				//y = str_cli(sockfd, &sTimeoutMsg);
				//return;
			}
                }	

//check here	
	//memcpy(sRetMsg.timestamp, sHpnRetMsg.pts, MS_CTIME_BUF_LEN);
	memcpy(sRetMsg.timestamp, sHpnRetMsg.timestamp, MS_CTIME_BUF_LEN);
#ifdef HPNSSH_QFACTOR_BINN 
	sRetMsg.hop_latency = sHpnRetMsg.hop_latency;
	sRetMsg.queue_occupancy = sHpnRetMsg.queue_occupancy;
	sRetMsg.switch_id = sHpnRetMsg.switch_id;
	sRetMsg.seq_no = ++sMsgSeqNo;
#else
	sRetMsg.hop_latency = htonl(sHpnRetMsg.hop_latency);
	sRetMsg.queue_occupancy = htonl(sHpnRetMsg.queue_occupancy);
	sRetMsg.switch_id = htonl(sHpnRetMsg.switch_id);
	sRetMsg.seq_no = htonl(++sMsgSeqNo);
#endif
	sHpnRetMsg.pts = 0;	

	if(sHpnRetMsg2.pts)
	{
		memcpy(sRetMsg2.timestamp, sHpnRetMsg2.pts, MS_CTIME_BUF_LEN);
#ifdef HPNSSH_QFACTOR_BINN 
       		sRetMsg2.hop_latency = sHpnRetMsg2.hop_latency;
        	sRetMsg2.queue_occupancy = sHpnRetMsg2.queue_occupancy;
        	sRetMsg2.switch_id = sHpnRetMsg2.switch_id;
		sRetMsg2.seq_no = ++sMsgSeqNo;	
#else
       		sRetMsg2.hop_latency = htonl(sHpnRetMsg2.hop_latency);
        	sRetMsg2.queue_occupancy = htonl(sHpnRetMsg2.queue_occupancy);
        	sRetMsg2.switch_id = htonl(sHpnRetMsg2.switch_id);
		sRetMsg2.seq_no = htonl(++sMsgSeqNo);	
#endif
		sHpnRetMsg2.pts = 0;
		two = 1;
	}

	hpnretcdone = 0;
	Pthread_mutex_unlock(&hpn_ret_mutex);
#if 1	
	if (two)
	{
		two = 0;
		if ((!str_cli(sockfd, &sRetMsg)) && (!str_cli(sockfd, &sRetMsg2)))
			goto read_again;
	}
	else
		{	
			if (!str_cli(sockfd, &sRetMsg))
				goto read_again;
		}
	
	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
	if (vDebugLevel > 0)
	{
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***WARNING***: client closed connection, EPIPE error???****\n", ms_ctime_buf, phase2str(current_phase));
		fflush(tunLogPtr);
	}
#endif
//	y = str_cli(sockfd, &sRetMsg);
return;
}

void fDoHpnShutdown(unsigned int val, int sockfd)
{
        time_t clk;
        char ctime_buf[27];
        char ms_ctime_buf[MS_CTIME_BUF_LEN];
	int check = 0;
        
	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
        fprintf(tunLogPtr,"%s %s: ***INFO***: In fDoHpnShutdown(), value is %u, Shutting down HPNSSH-QFACTOR  Server socket ***\n", ms_ctime_buf, phase2str(current_phase), val);
#if 1
	check = shutdown(sockfd, SHUT_WR);
        //close(sockfd); //- use shutdown instead of close
        if (!check)
        	read_sock(sockfd); //final read to wait on close from other end
        else
        	fprintf(tunLogPtr,"%s %s: ***shutdoooown failed to HPNSSN_QFACTOR server..., check = %d***\n", ms_ctime_buf, phase2str(current_phase), check);
#endif
return;
}

void fDoHpnStart(unsigned int val, int sockfd)
{
        time_t clk;
        char ctime_buf[27];
        char ms_ctime_buf[MS_CTIME_BUF_LEN];
	struct PeerMsg sRetMsg;
       
	memset(&sRetMsg,0,sizeof(sRetMsg));
	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
	if (vDebugLevel > 1)
        	fprintf(tunLogPtr,"%s %s: ***INFO***: In fDoHpnStart(), value is %u***\n", ms_ctime_buf, phase2str(current_phase), val);

	strcpy(sRetMsg.msg, "Hello there!!! Got your start message...\n");
        sRetMsg.msg_no = htonl(HPNSSH_MSG);
        sRetMsg.value = htonl(199);;
	str_cli(sockfd, &sRetMsg);
return;
}

void fDoHpnAssessment(unsigned int val, int sockfd)
{
        time_t clk;
        char ctime_buf[27];
        char ms_ctime_buf[MS_CTIME_BUF_LEN];
        
	switch (val) {
		case  HPNSSH_READ:
			fDoHpnRead(val, sockfd);
			break;
		case HPNSSH_READALL:
			fDoHpnReadAll(val, sockfd);
			break;
		case HPNSSH_SHUTDOWN:
			fDoHpnShutdown(val, sockfd);
			break;
		case HPNSSH_START:
			fDoHpnStart(val, sockfd);
			break;
		default:
			gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
        		fprintf(tunLogPtr,"%s %s: ***WARNING***: Invalid Hpnmessage value from client. Value is %u***\n", ms_ctime_buf, phase2str(current_phase), val);
			break;
	}

return;
}
#endif

#if 1
void fDoQinfoAssessment(unsigned int val);
void fDoQinfoAssessment(unsigned int val)
{

        time_t clk;
        char ctime_buf[27];
        char ms_ctime_buf[MS_CTIME_BUF_LEN];
        char aQdiscVal[512];
        char aNicSetting[1024];
        //FILE *nicCfgFPtr = 0;

        //For now
        //memset(aQdiscVal,0,sizeof(aQdiscVal));
        //strcpy(aQdiscVal,"aTest");
        //sprintf(aNicSetting,"tc qdisc show dev %s root > /tmp/NIC.cfgfile 2>/dev/null",netDevice);
        //system(aNicSetting);
        //stat("/tmp/NIC.cfgfile", &sb);

        strcpy(aQdiscVal,"fq");
        gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
        fprintf(tunLogPtr,"%s %s: ***WARNING***: Qinfo message value from destination DTN is %u***\n", ms_ctime_buf, phase2str(current_phase), val);

        if (vRetransmissionRate > vRetransmissionRateThreshold)
        {
                fprintf(tunLogPtr,"%s %s: ***WARNING***: the retransmission rate of %.5f is higher that the retansmission threshold of %.5f.\n", ms_ctime_buf, phase2str(current_phase), vRetransmissionRate, vRetransmissionRateThreshold);
                sprintf(aNicSetting,"tc qdisc del dev %s root %s 2>/dev/null; tc qdisc add dev %s root fq maxrate %.2fgbit", netDevice, aQdiscVal, netDevice, (vGlobal_average_tx_Gbits_per_sec/4.0)*3.0);

                if (gTuningMode && (current_phase == LEARNING))
                {
                        current_phase = TUNING;
                        fprintf(tunLogPtr,"%s %s: ***WARNING***: It appears that congestion is on the link. Current average transmitted bytes on the link is %.2f. Will adjust the pacing with the following:\n",
                                                                                                                                                        ms_ctime_buf, phase2str(current_phase), vGlobal_average_tx_Gbits_per_sec);
                        fprintf(tunLogPtr,"%s %s: ***WARNING***: *%s*\n", ms_ctime_buf, phase2str(current_phase), aNicSetting);
                        system(aNicSetting);
                        fprintf(tunLogPtr,"%s %s: ***WARNING***: !!!!Pacing has been adjusted!!!!\n", ms_ctime_buf, phase2str(current_phase));
                        current_phase = LEARNING;
                        vResetPacingBack = 1;
			shm_write(shm, &vResetPacingBack);

                        fprintf(tunLogPtr,"%s %s: ***WARNING***: !!!!Pacing has been adjusted!!!! %d\n", ms_ctime_buf, phase2str(current_phase), vResetPacingBack);
                        current_phase = LEARNING;
                }
                else
                        if (current_phase == TUNING)
                        {
                                fprintf(tunLogPtr,"%s %s: ***WARNING***: It appears that congestion is on the link. Current average transmitted bytes on the link is %.2f. Will adjust the pacing with the following:\n",
                                                                                                                                                                ms_ctime_buf, phase2str(current_phase), vGlobal_average_tx_Gbits_per_sec);
                                fprintf(tunLogPtr,"%s %s: ***WARNING***: *%s*\n", ms_ctime_buf, phase2str(current_phase), aNicSetting);
                                system(aNicSetting);
                                fprintf(tunLogPtr,"%s %s: ***WARNING***: !!!!Pacing has been adjusted!!!!\n", ms_ctime_buf, phase2str(current_phase));
                                vResetPacingBack = 1;
				shm_write(shm, &vResetPacingBack);
                        }
                        else
                                {
                                        fprintf(tunLogPtr,"%s %s: ***WARNING***: It appears that congestion is on the link. Current average transmitted bytes on the link is %.2f. Try running the following:\n",
                                                                                                                                                        ms_ctime_buf, phase2str(current_phase), vGlobal_average_tx_Gbits_per_sec);
                                        fprintf(tunLogPtr,"%s %s: ***WARNING***: \"%s\"\n", ms_ctime_buf, phase2str(current_phase), aNicSetting);
                                }
        }
        else
        {
                fprintf(tunLogPtr,"%s %s: ***WARNING***: It appears that congestion is on the link.:***\n", ms_ctime_buf, phase2str(current_phase));
                fprintf(tunLogPtr,"%s %s: ***WARNING***: However, the retransmission rate of %.5f is lower that the retansmission threshold of %.5f**\n",
                                                                                        ms_ctime_buf, phase2str(current_phase), vRetransmissionRate, vRetransmissionRateThreshold);
        }
return;
}
#endif

void * fDoRunGetThresholds(void * vargp)
{
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	
	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
	fprintf(tunLogPtr,"%s %s: ***Starting Check Threshold thread ...***\n", ms_ctime_buf, phase2str(current_phase));
	fflush(tunLogPtr);
	char buffer[128];
	char aApplyDefTunBest[MAX_SIZE_SYSTEM_SETTING_STRING];
	char best_wmem_val[MAX_SIZE_SYSTEM_SETTING_STRING];
	FILE *pipe;
	unsigned long last_tx_bytes = 0, last_rx_bytes = 0;	
	int check_bitrate_interval = 0;
	unsigned long rx_before, rx_now, rx_bytes_tot;
	unsigned long tx_before, tx_now, tx_bytes_tot;
	double average_tx_kbits_per_sec = 0.0;
	double average_tx_Gbits_per_sec = 0.0;
	double average_rx_kbits_per_sec = 0.0;
	double average_rx_Gbits_per_sec = 0.0;
	double tx_jitter = 0.30;
	double rx_jitter = 0.30;
	double highest_average_tx_Gbits_per_sec = 0.0;
	char try[1024];
	char aNicSetting[1024];
	int vPacingCount = 9999;
	int stage = 0;
	int applied = 0, suggested = 0, nothing_done = 0, max_apply = 0, something_wrong_check = 0;
	int tune = 1; //1 = up, 2 = down - tune up initially
	static unsigned long count = 0;
	static int vFirstTimeThru = 1;

	sprintf(aNicSetting,"tc qdisc del dev %s root fq 2>/dev/null", netDevice);

	sprintf(try,"bpftrace -e \'BEGIN { @name;} kprobe:dev_get_stats { $nd = (struct net_device *) arg0; @name = $nd->name; } kretprobe:dev_get_stats /@name == \"%s\"/ { $rtnl = (struct rtnl_link_stats64 *) retval; $rx_bytes = $rtnl->rx_bytes; $tx_bytes = $rtnl->tx_bytes; printf(\"%s %s\\n\", $tx_bytes, $rx_bytes); } interval:s:1 { exit(); } END { clear(@name); }\'",netDevice,"%lu","%lu");
	/* fix for kfunc below too */
	/*sprintf(try,"bpftrace -e \'BEGIN { @name;} kfunc:dev_get_stats { $nd = (struct net_device *) args->dev; @name = $nd->name; } kretfunc:dev_get_stats /@name == \"%s\"/ { $nd = (struct net_device *) args->dev; $rtnl = (struct rtnl_link_stats64 *) args->storage; $rx_bytes = $rtnl->rx_bytes; $tx_bytes = $rtnl->tx_bytes; printf(\"%s %s\\n\", $tx_bytes, $rx_bytes); time(\"%s\"); exit(); } END { clear(@name); }\'",netDevice,"%lu","%lu","%S");*/

start:
	if (vDebugLevel > 2 && previous_average_tx_Gbits_per_sec && vIamASrcDtn)
	{
		fGetAppBandWidth();
	//	sleep(1);
	}
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

#if 0	
	if (!tx_kbits_per_sec) //nothing happening - reset back the pacing
		fprintf(tunLogPtr,"%s %s: ***INFO***: Activity on link has stopped for now Mode %d Pacing %d*\n",ms_ctime_buf, phase2str(current_phase), gTuningMode, vResetPacingBack);
	else
		fprintf(tunLogPtr,"%s %s: ***INFO***: Activity on the link ****  Mode %d Pacing %d\n",ms_ctime_buf, phase2str(current_phase), gTuningMode, vResetPacingBack);
#endif
	if (!tx_kbits_per_sec)
	{
		vIamASrcDtn = 0; //reset
		vIamADestDtn = 0;
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);

		if (vDebugLevel > 8)
			fprintf(tunLogPtr,"%s %s: ***INFO***: Activity on link has stopped for now\n",ms_ctime_buf, phase2str(current_phase));

		if (vq_TimerIsSet) //Turn off this timer since transmission has stopped
		{
			fprintf(tunLogPtr,"%s %s: ***INFO***: Activity on link has stopped for now *** Turning off Queue Occupancy timer:\n",ms_ctime_buf, phase2str(current_phase));
			timer_settime(qOCC_TimerID, 0, &sDisableTimer, (struct itimerspec *)NULL);
			vq_TimerIsSet = 0;
			vq_WarningCount = 0;
		}

		if (vq_h_TimerIsSet) //Turn off this timer since transmission has stopped
		{		
			fprintf(tunLogPtr,"%s %s: ***INFO***: Activity on link has stopped for now *** Turning off Queue occupancy and Hop Delay timer:",ms_ctime_buf, phase2str(current_phase));
			timer_settime(qOCC_Hop_TimerID, 0, &sDisableTimer, (struct itimerspec *)NULL);
			vq_h_TimerIsSet = 0;
		}

		if (shm_read(&vResetPacingBack, shm) && vResetPacingBack) //nothing happening - reset back the pacing
		{
			if (gTuningMode && (current_phase == LEARNING))
			{
				vResetPacingBack = 0;
				shm_write(shm, &vResetPacingBack);	    

				current_phase = TUNING;
				fprintf(tunLogPtr,"%s %s: ***INFO***: Activity on link has stopped for now *** resetting back the Pacing with the following:",ms_ctime_buf, phase2str(current_phase));
				fprintf(tunLogPtr,"%s %s: ***INFO***: *%s*\n", ms_ctime_buf, phase2str(current_phase), aNicSetting);
				system(aNicSetting);
				fprintf(tunLogPtr,"%s %s: ***INFO***: !!!!Pacing has been reset!!!!\n", ms_ctime_buf, phase2str(current_phase));
				current_phase = LEARNING;
			}
			else
				if (current_phase == TUNING)
				{
					vResetPacingBack = 0;
					shm_write(shm, &vResetPacingBack);	    

					fprintf(tunLogPtr,"%s %s: ***INFO***: Activity on link has stopped for now *** resetting back the Pacing with the following:",ms_ctime_buf, phase2str(current_phase));
					fprintf(tunLogPtr,"%s %s: ***INFO***: *%s*\n", ms_ctime_buf, phase2str(current_phase), aNicSetting);
					system(aNicSetting);
					fprintf(tunLogPtr,"%s %s: ***INFO***: !!!!Pacing has been resetted!!!!\n", ms_ctime_buf, phase2str(current_phase));
				}
				else
					{
						if (((vPacingCount++) > 5) && (vDebugLevel > 0))
						{
							vPacingCount = 0;
							fprintf(tunLogPtr,"%s %s: ***WARNING***: Activity on link has stopped for now, but the pacing was changed and should be changed back.***", ms_ctime_buf, phase2str(current_phase));
							fprintf(tunLogPtr,"%s %s: ***WARNING***: The simplest way to change back is to turn off Learning Mode and the Tuning Module will do it for you***\n", ms_ctime_buf, phase2str(current_phase));
							fprintf(tunLogPtr,"%s %s: ***WARNING***: Do the following from the Tuning Module directory to turn off Learning mode: \"./tuncli -l off\"\n", ms_ctime_buf, phase2str(current_phase));
							fprintf(tunLogPtr,"%s %s: ***WARNING***: You probably want to turn back on Learning mode after waiting a couple seconds with the following: \"./tuncli -l on\"\n", 
																									ms_ctime_buf, phase2str(current_phase));
						}
					}
		}
	}
	else
	{
		if (vDebugLevel > 8)
			fprintf(tunLogPtr,"%s %s: ***INFO***: Activity is on the link***\n",ms_ctime_buf, phase2str(current_phase));
	}
		
	
	average_tx_kbits_per_sec += tx_kbits_per_sec;	
	average_rx_kbits_per_sec += rx_kbits_per_sec;
	if (check_bitrate_interval >= BITRATE_INTERVAL) 
	{
		//average_tx_bits_per_sec = average_tx_bits_per_sec/check_bitrate_interval;
		average_tx_kbits_per_sec = average_tx_kbits_per_sec/(double)check_bitrate_interval;
		average_tx_Gbits_per_sec = average_tx_kbits_per_sec/(double)(1000000);
		average_rx_kbits_per_sec = average_rx_kbits_per_sec/(double)check_bitrate_interval;;
		average_rx_Gbits_per_sec = average_rx_kbits_per_sec/(double)(1000000);;
		check_bitrate_interval = 0;
		
		if (average_tx_Gbits_per_sec)
		{
			//Sanity checking here - need to further investigate how this could happen
			if (average_tx_Gbits_per_sec > (netDeviceSpeed/1000))
			{
				//can't be - something off - don't use as a recorded value 
				if (vDebugLevel > 0)
				{
					gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
					fprintf(tunLogPtr,"%s %s: ***ERROR BITRATE*** average_tx_Gbits_per_sec = %.2f Gb/s is above maximum Bandwidth of %.2f... skiping this value\n",ms_ctime_buf, phase2str(current_phase), average_tx_Gbits_per_sec, netDeviceSpeed/1000.0);
				}
				average_tx_Gbits_per_sec = 0.0;
				average_tx_kbits_per_sec = 0.0;
				average_rx_kbits_per_sec = 0.0;
				average_rx_Gbits_per_sec = 0.0;
				goto tx_Gbs_off;
			}
#if 1 
			if (vIamASrcDtn && vIamADestDtn)	
			{ // sometimes slightly off, will keep observing
				average_tx_Gbits_per_sec = average_tx_Gbits_per_sec + tx_jitter;
				average_rx_Gbits_per_sec = average_rx_Gbits_per_sec + rx_jitter;
			}
			else
				if (vIamASrcDtn)	
					average_tx_Gbits_per_sec = average_tx_Gbits_per_sec + tx_jitter;
				else
					average_rx_Gbits_per_sec = average_rx_Gbits_per_sec + rx_jitter;
#endif
		}
	}

	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
			
	if (vDebugLevel > 6 && tx_kbits_per_sec)
	{
		fprintf(tunLogPtr,"%s %s: DEV %s: TX : %.2f Gb/s RX : %.2f Gb/s\n", ms_ctime_buf, phase2str(current_phase), netDevice, tx_kbits_per_sec/(double)(1000000), rx_kbits_per_sec/(double)(1000000));
		//fprintf(tunLogPtr,"%s %s: DEV %s: TX : %.2f Gb/s RX : %.2f Gb/s\n", ctime_buf, phase2str(current_phase), netDevice, tx_kbits_per_sec/(double)(1048576), rx_kbits_per_sec/(double)(1048576));
	}

	if (!tx_kbits_per_sec && vDidSetChannel && (vDebugLevel > 0))
	{
		char buffer[256];
		vDidSetChannel = 0;
		if (!netDevice_only_combined_channel_cfg)
		{
			sprintf(buffer,"ethtool -L %s rx %d tx %d  combined %d",netDevice, netDevice_rx_channel_cfg_curr_val, netDevice_tx_channel_cfg_curr_val, 
																netDevice_combined_channel_cfg_curr_val);
			current_phase = TUNING;
			fprintf(tunLogPtr,"%s %s: ***WARNING: File Transfer has stopped... Running the following command to set back %s channels::: %s\n",
												ms_ctime_buf, phase2str(current_phase), netDevice, buffer);
			system(buffer);
			current_phase = LEARNING;
		}
		else
			{
				sprintf(buffer,"ethtool -L %s combined %d",netDevice,  netDevice_combined_channel_cfg_curr_val);
				current_phase = TUNING;
				fprintf(tunLogPtr,"%s %s: ***WARNING: File Transfer has stopped... Running the following command to set back %s channels::: %s\n",
														ms_ctime_buf, phase2str(current_phase), netDevice, buffer);
				system(buffer);
				current_phase = LEARNING;
			}
	}


	if (vDebugLevel > 1 && average_tx_Gbits_per_sec)
	{
		if (!check_bitrate_interval)
		{
			fprintf(tunLogPtr,"%s %s: average_tx_Gbits_per_sec = %.2f Gb/s, average_rx_Gbits_per_sec = %.2f Gb/s\n",
							ms_ctime_buf, phase2str(current_phase), average_tx_Gbits_per_sec, average_rx_Gbits_per_sec);
		}
	}

	if (!check_bitrate_interval)
	{
		vGlobal_average_tx_Gbits_per_sec = average_tx_Gbits_per_sec;

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
							fprintf(tunLogPtr,"%s %s: ***Best wmem val***%s***\n\n", ms_ctime_buf, 
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

				gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
				if (previous_average_tx_Gbits_per_sec)
				{
					if ((vDebugLevel > 6) &&  (highest_average_tx_Gbits_per_sec >= 1))
					{
						fprintf(tunLogPtr,"%s %s: ***applied = %d, previous avg bitrate %.2f, highest avg bitrate= %.2f***\n", 
								ms_ctime_buf, phase2str(current_phase), applied, 
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
								ms_ctime_buf, phase2str(current_phase), previous_average_tx_Gbits_per_sec, 
									highest_average_tx_Gbits_per_sec);

							fprintf(tunLogPtr,"%s %s: Will need to adjust***\n", ms_ctime_buf, phase2str(current_phase));
						}

						highest_average_tx_Gbits_per_sec = previous_average_tx_Gbits_per_sec/2;
						something_wrong_check = 0;
						tune = 0;
						nothing_done = 0;
						max_apply = 0;
						average_tx_Gbits_per_sec = 0.0;
						average_tx_kbits_per_sec = 0.0;
						average_rx_kbits_per_sec = 0.0;
						average_rx_Gbits_per_sec = 0.0;
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
						fprintf(tunLogPtr,"%s %s: ***Going to apply Best wmem val***%s***\n\n", ms_ctime_buf, 
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
							gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
							fprintf(tunLogPtr, "%s %s: ***Tuning was suggested but not applied, will skip suggesting for now ...***\n", ms_ctime_buf, phase2str(current_phase));
							fflush(tunLogPtr);
						}
						average_tx_Gbits_per_sec = 0.0;
						average_tx_kbits_per_sec = 0.0;
						average_rx_kbits_per_sec = 0.0;
						average_rx_Gbits_per_sec = 0.0;
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
						if (vDebugLevel > 4)
						{
							fprintf(tunLogPtr, "%s %s: ***What is nothing_done??? and nothing_done is %d ...***\n", ms_ctime_buf, phase2str(current_phase), nothing_done);
						}

						if (nothing_done++ > 5)
							nothing_done = 0;
						else
						{
							if ((nothing_done == 2) && (vDebugLevel > 1))
							{
								gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);

								fprintf(tunLogPtr, "%s %s: ***Tuning appears sufficient, will skip suggesting or applying for now ...***\n", ms_ctime_buf, phase2str(current_phase));
								fflush(tunLogPtr);
							}
							average_tx_Gbits_per_sec = 0.0;
							average_tx_kbits_per_sec = 0.0;
							average_rx_kbits_per_sec = 0.0;
							average_rx_Gbits_per_sec = 0.0;
							goto ck_stage;
						}
					}

			applied = 0;

			if (average_tx_Gbits_per_sec >= 1) //must be at least a Gig to check
				check_if_bitrate_too_low(average_tx_Gbits_per_sec, &applied, &suggested, &nothing_done, &tune, aApplyDefTunBest);
#if 0
			if (vDebugLevel > 5 && (tx_kbits_per_sec || rx_kbits_per_sec))
			{
				fprintf(tunLogPtr, "%s %s: ***Sleeping for %d microseconds before resuming Bitrate checking...\n", ctime_buf, phase2str(current_phase), gInterval);
				fflush(tunLogPtr);
			}
#endif				
			average_tx_Gbits_per_sec = 0.0;
			average_tx_kbits_per_sec = 0.0;
			average_rx_kbits_per_sec = 0.0;
			average_rx_Gbits_per_sec = 0.0;
//			my_usleep(gInterval); //sleeps in microseconds
	}

tx_Gbs_off:
	if (!check_bitrate_interval)
		msleep(1000); //give it another second to quiesce

	if (!rx_kbits_per_sec)
	{
		rx_traffic = 0;
		new_traffic = 0;
	}

	if (rx_kbits_per_sec && !rx_traffic)
	{
		rx_traffic = 1;
		new_traffic = 1;

		//Track vFlowCount this way
		if (vFirstTimeThru)
			vFirstTimeThru = 0;
		else
			{
				if (++vFlowCount == NUM_OF_FLOWS_TO_KEEP_TRACK_OF) 
				{
					vFlowCountWrapped = 1;
					vFlowCount = 0;
				}
			
				sFlowCounters[vFlowCount].num_tuning_activities = 0;
				sFlowCounters[vFlowCount].gFlowCountUsed = 0;
			}

		if (vDebugLevel > 1)
		{
			gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
			fprintf(tunLogPtr, "%s %s: ***New traffic %lu***\n", ms_ctime_buf, phase2str(current_phase), count++);
			fflush(tunLogPtr);
		}
	}


ck_stage:
	if (stage)
	{
		stage = 0;
		goto start;
	}

	fprintf(tunLogPtr, "%s %s: ***Problems*** stage not set...\n", ms_ctime_buf, phase2str(current_phase));
	fflush(tunLogPtr);

return ((char *) 0);
}


//Measured in milliseconds
#define RTT_THRESHOLD	2 
void fDoManageRtt(double highest_rtt_ms, int * applied, int * suggested, int * nothing_done, int * tune, char aApplyDefTun[MAX_SIZE_SYSTEM_SETTING_STRING], int from_bpftrace);
void fDoManageRtt(double highest_rtt_ms, int * applied, int * suggested, int * nothing_done, int * tune, char aApplyDefTun[MAX_SIZE_SYSTEM_SETTING_STRING], int from_bpftrace)
{
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	char buffer[256];
	FILE *pipe;
	char kernel_parameter[128];
	char equal_sign;
	unsigned int  kminimum;
	int kdefault;
	unsigned int kmaximum;
	double average_tx_Gbits_per_sec = 2000.00;

	return; //******ATTENTION!!!!!!!!! doesn't do anything for now ******** ATTENTION!!!!!!!!!

	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
	if (from_bpftrace)
		fprintf(tunLogPtr, "%s %s: *** WARNING**** RTT from *BPFTRACE* is ABOVE THRESHOLD***** WARNING****!!!! RTT is  %.3fms, threshold is %f ***\n", ms_ctime_buf, phase2str(current_phase), highest_rtt_ms, rtt_threshold);
	else
		fprintf(tunLogPtr, "%s %s: *** WARNING**** RTT from *PING* is ABOVE THRESHOLD***** WARNING****!!!! RTT is  %.3fms, threshold is %f ***\n", ms_ctime_buf, phase2str(current_phase), highest_rtt_ms, rtt_threshold);


	//remember average_tx_Gbits_per_sec is a bogus value
	if (average_tx_Gbits_per_sec < vGoodBitrateValue)
	{
		if (current_phase == TUNING)
		{
			fprintf(tunLogPtr, "%s %s: Trying to tune net.ipv4.tcp_wmem, but already TUNING something else.  Will retry later if still need TUNING***\n",ms_ctime_buf, phase2str(current_phase));
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
					gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
					current_phase = TUNING;
					//fprintf(tunLogPtr, "%s %s: Changed current phase***\n",ctime_buf, phase2str(current_phase));
					//do something
					if (my_tune_max <= kmaximum) //already high
					{
						if (vDebugLevel > 4)
						{
							fprintf(tunLogPtr, "%s %s: ***CURRENT TUNING***: %s",ms_ctime_buf, phase2str(current_phase), buffer);
							fprintf(tunLogPtr, "%s %s: *** Current Tuning of net.ipv4.tcp_wmem appears sufficient***\n", ms_ctime_buf, phase2str(current_phase));
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

											fprintf(tunLogPtr, "%s %s: ***Could not apply tuning since the maximum value of wmem would be less than %d...***\n",ms_ctime_buf, phase2str(current_phase), 600000 - KTUNING_DELTA);
											current_phase = LEARNING; //change back phase to LEARNING
											*nothing_done = 1;
											return;
										}
								}
								else
									if (*tune == 3)
									{
										fprintf(tunLogPtr,"%s %s: ***No better change found. Using ***%s***\n\n", ms_ctime_buf, phase2str(current_phase), aApplyDefTun);
									}
									else
										{
											fprintf(tunLogPtr, "%s %s: ***Could not apply tuning*** invalid value for tune %d***\n",ms_ctime_buf, phase2str(current_phase), *tune);
											current_phase = LEARNING; //change back phase to LEARNING
											*nothing_done = 1;
											return;
										}

										fprintf(tunLogPtr, "%s %s: ***CURRENT TUNING***: %s",ms_ctime_buf, phase2str(current_phase), buffer);
										strcpy(aApplyDefTunNoStdOut,aApplyDefTun);
										strcat(aApplyDefTunNoStdOut," >/dev/null"); //so it won't print to stderr on console
										system(aApplyDefTunNoStdOut);
										fprintf(tunLogPtr, "%s %s: ***APPLIED TUNING***: %s\n\n",ms_ctime_buf, phase2str(current_phase), aApplyDefTun);
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
						}
						else
							{
								*suggested = 1;
								if (vDebugLevel > 0)
								{
									//don't apply - just log suggestions - decided to use a debug level here because this file could fill up if user never accepts recommendation
									fprintf(tunLogPtr, "%s %s: ***CURRENT TUNING***: *%s",ms_ctime_buf, phase2str(current_phase), buffer);
									fprintf(tunLogPtr, "%s %s: ***SUGGESTED TUNING***: *sudo sysctl -w net.ipv4.tcp_wmem=\"%u %d %u\"\n\n",ms_ctime_buf, phase2str(current_phase), kminimum, kdefault, kmaximum+KTUNING_DELTA);
								}
							}
					}
			}
	}

	fflush(tunLogPtr);
return;
}

double fDoCpuMonitoring()
{
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	char buffer[128];
	char header_buffer[128];
	int count = 0;
	FILE *pipe;
	char try[1024];
	char * foundstr;
	int found = 0;
	int ridtwolines = 0;
	static int nompstat = 0;

	if (nompstat)
		return 0;

	sprintf(try,"%s","mpstat -P ALL 1 1 | grep -v all | grep -v 100.00 | grep -v 9[[:digit:]].");

	pipe = popen(try,"r");
	if (!pipe)
	{
		printf("popen failed!\n");
		printf("here2***\n");
		return 0;
	}

	
	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);

	while (!feof(pipe))
	{
		// use buffer to read and add to result
		if (fgets(buffer, 128, pipe) != NULL)
		{
			if (++ridtwolines < 3)
				continue;

			foundstr = strstr(buffer,"Average");
			if (foundstr)
			{
				found = 1;
				break;
			}
			else
			{
				//kind of a hack, but let's not print anything if  CPUs that we want doesn't exist!!!
				if (count == 0)
				{
					strcpy(header_buffer,buffer);
					count++;
				}
				else
					if (count == 1)
					{
						if (buffer[0] != '\n')
						{
							//we have some CPUs that we want - catch up and print 
							fprintf(tunLogPtr,"\n%s %s: ***Monitoring CPUs that are being utilized at least 10%c***\n", 
													ms_ctime_buf, phase2str(current_phase),'%');
							fprintf(tunLogPtr,"%sCPU     : %s", pLearningSpacesMinusLearning, header_buffer);
							fprintf(tunLogPtr,"%sCPU     : %s", pLearningSpacesMinusLearning, buffer);
						}
						
						count++;
					}
					else
						{
							if (buffer[0] != '\n')
								fprintf(tunLogPtr,"%sCPU     : %s", pLearningSpacesMinusLearning, buffer);					
							else
								fprintf(tunLogPtr,"%s%s", pLearningSpaces, buffer);					
						}
			}

		}
		else
			break;
	}

	pclose(pipe);

	if (!found)
	{
		nompstat = 1;
		fprintf(tunLogPtr,"\n%s %s: ***!!!!ERROR!!!**** Could not find \"mpstat\" to monitor CPUs***\n", ms_ctime_buf, phase2str(current_phase));
	}
		
	fflush(tunLogPtr);

return found;
}

#define COUNT_TO_LOG	100
void *doRunFindRetransmissionRate(void * vargp)
{
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	char buffer[256];
	FILE *pipe;
	char try[1024];
	unsigned long total_retrans = 0;
	unsigned long packets_sent = 0;
	unsigned long pre_total_retrans = 0;
	unsigned long pre_packets_sent = 0;
        char * foundstr = 0;
	int found = 0;
	unsigned int countLog = 0;

	while (aDest_Ip2[0] == 0 && !vIamASrcDtn)
	{
		if (vDebugLevel > 6)
		{
			gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
			fprintf(tunLogPtr,"%s %s: ***Waiting on Peer (Dest) Ip addres***\n", ms_ctime_buf, phase2str(current_phase));
			fflush(tunLogPtr);
		}
		sleep(3);
	}
	
	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
	fprintf(tunLogPtr,"%s %s: ***Starting Find Retransmission Rate thread ...***\n", ms_ctime_buf, phase2str(current_phase));	

	sprintf(try,"%s","cat /sys/fs/bpf/tcp4");

retrans:
	total_retrans = 0;
	packets_sent = 0;
        foundstr = 0;
	found = 0;
	pre_total_retrans = 0;
	pre_packets_sent = 0;

	if (!previous_average_tx_Gbits_per_sec)
		msleep(1000); //nothing going on. Get some rest
#if 0
	else 
		fprintf(tunLogPtr,"%s %s: ***Starting of Retransmission and packets %u***\n", ms_ctime_buf, phase2str(current_phase), countLog);
#endif
	pipe = popen(try,"r");
	if (!pipe)
	{
		printf("popen failed!\n");
		printf("here2222***\n");
		return (char *)0;
	}

	while (!feof(pipe))
	{
		// use buffer to read and add to result
		if (fgets(buffer, 256, pipe) != NULL);
		else
			{
				goto finish_up;
			}

		foundstr = strstr(buffer,aDest_Ip2_Binary);
		//should look like example: "11: 012E030A:8B2E 022E030A:1451 01 04DC97C7:00000000 01:00000014 00000000     0        0 13297797 2 00000000367a51de 41 0 0 3722 500 totrt 79""
                if (foundstr)
                {
			gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
			foundstr = strstr(foundstr,"totrt");
			if (foundstr)
			{
				char aValue[32];
				int count = 0;
				memset(aValue,0,32);
				foundstr = foundstr + 6;
#if 0
				if (*foundstr == '0')
					continue; //no need to count zeros
#endif
				while (isdigit(*foundstr))
                		{
                        		aValue[count++] = *foundstr;
					foundstr++;
				}

				aValue[count] = 0;
				if (count)
				{
				
					if ((vDebugLevel > 8) && ((countLog % COUNT_TO_LOG) == 0))
					{
						fprintf(tunLogPtr,"%s %s: ***actual string with retransmission is \"%s\"", ms_ctime_buf, phase2str(current_phase),buffer);
					}

					pre_total_retrans = strtoul(aValue, (char **)0, 10);
					total_retrans += pre_total_retrans;

					// get packets sent now
					memset(aValue,0,32);
					count = 0;
					foundstr++;
					
					while (isdigit(*foundstr))
                			{
                        			aValue[count++] = *foundstr;
						foundstr++;
					}

					aValue[count] = 0;
					if (count)
					{
						pre_packets_sent = strtoul(aValue, (char **)0, 10 );
						packets_sent += pre_packets_sent;
					}


					if (vDebugLevel > 7) //quick log
					{
						fprintf(tunLogPtr,"%s %s: ***pre_packets_sent = %lu, pre_total_retransmissions so far  is %lu\n", 
								ms_ctime_buf, phase2str(current_phase), pre_packets_sent, pre_total_retrans);
						fprintf(tunLogPtr,"%s %s: ***packets_sent = %lu, total retransmissions so far  is %lu\n", 
								ms_ctime_buf, phase2str(current_phase), packets_sent, total_retrans);
					}
					else
						if ((vDebugLevel > 5) && ((countLog % COUNT_TO_LOG) == 0)) //slow log
						{
							fprintf(tunLogPtr,"%s %s: ***packets_sent = %lu, total retransmissions so far  is %lu\n", 
										ms_ctime_buf, phase2str(current_phase), packets_sent, total_retrans);
						}

					found = 1;
				}
                	}
		}
		else
			continue;
	}

finish_up:
	pclose(pipe);
	if (found)
	{
		vRetransmissionRate = (total_retrans/(double)packets_sent) * 100.0;

		if ((vDebugLevel > 2) && ((countLog % COUNT_TO_LOG) == 0))
		{
			fprintf(tunLogPtr,"%s %s: Retransmission rate is %.5f\n", ms_ctime_buf, phase2str(current_phase), vRetransmissionRate);
		}
		
		countLog++; //otherwise would output too quickly
	}
	
	fflush(tunLogPtr);

	msleep(100); //sleep 100 millisecs
	goto retrans;

return (char *) 0;
}

double fFindRttUsingPing()
{
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	char buffer[128];
	FILE *pipe;
	char try[1024];
	double avg_rtt_ping = 0.0;
        char * foundstr = 0;
	int found = 0;

	if (aDest_Ip2[0] == 0)
	{
		if (vDebugLevel > 1)
		{
			gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
			fprintf(tunLogPtr,"%s %s: ***Waiting on Peer Ip address to Ping***\n", ms_ctime_buf, phase2str(current_phase));
			fflush(tunLogPtr);
		}
		return 0; //didn't get  a message from the peer yet
	}
	
	sprintf(try,"ping -c 3 %s", aDest_Ip2);

	avg_rtt_ping = 0;
	pipe = popen(try,"r");
	if (!pipe)
	{
		printf("popen failed!\n");
		printf("here2***\n");
		return 0;
	}

	while (!feof(pipe))
	{
		// use buffer to read and add to result
		if (fgets(buffer, 128, pipe) != NULL);
		else
			{
				goto finish_up;
			}

		foundstr = strstr(buffer,"avg");
		//should look like example: "rtt min/avg/max/mdev = 0.314/0.341/0.366/0.021 ms"
                if (foundstr)
                {
			if (vDebugLevel > 1)
			{
				gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
				fprintf(tunLogPtr,"%s %s: ***using \"%s\" returns *%s", ms_ctime_buf, phase2str(current_phase),try, buffer);
			}
			foundstr = strchr(foundstr,'=');
			if (foundstr)
			{
				foundstr = strchr(foundstr,'/');
				if (foundstr)
				{
					char * q = 0;
					char value[32];
					memset(value,0,32);
					foundstr++;
					q = strchr(foundstr,'/');
					if (q)
					{
						char * strpart;
						strncpy(value,foundstr,q-foundstr);
						avg_rtt_ping = strtod(value, &strpart);
						found = 1;
						break;	
					}
				}
                	}
		}
		else
			continue;
	}

finish_up:
	pclose(pipe);
	if (found)
	{
		if (vDebugLevel > 1)
		{
			gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
			fprintf(tunLogPtr,"%s %s: ***Average RTT using ping is %.3fms\n", ms_ctime_buf, phase2str(current_phase), avg_rtt_ping);
		}
	}
		
	fflush(tunLogPtr);

return avg_rtt_ping;
}

void fDoSetChannels(void);
void fDoSetChannels(void)
{

	time_t clk;
	char ctime_buf[CTIME_BUF_LEN];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	char buffer[256];
	static unsigned int count = 0;

	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);

	if ((count++ % 5) == 0) //check every 5 times so it doesn't become annoying
	{
	 if (netDevice_combined_channel_cfg_max_val <= nProc)
	 {
		if (netDevice_combined_channel_cfg_max_val)
		{
			int combined_to_use = netDevice_combined_channel_cfg_max_val/8;
			int tx_to_use = netDevice_combined_channel_cfg_max_val - combined_to_use;

			if (!netDevice_only_combined_channel_cfg)
			{
				sprintf(buffer,"ethtool -L %s rx 0 tx %d  combined %d",netDevice, tx_to_use, combined_to_use);
				if (gTuningMode && current_phase == LEARNING) //need to fix so that current_phase always has the right mode
				{
					current_phase = TUNING;
					fprintf(tunLogPtr,"%s %s: ***WARNING: running the following command to fix ksoftirqd resource issue::: %s\n", 
														ms_ctime_buf, phase2str(current_phase),  buffer);
					fprintf(tunLogPtr,"%s %s: ***WARNING: Also, please make sure you are running your application using a core in the Nic's NUMA***\n",
														ms_ctime_buf, phase2str(current_phase));
					system(buffer);
					vDidSetChannel = 1;
					current_phase = LEARNING;
				}
				else
					{
						fprintf(tunLogPtr,"%s %s: ***WARNING: Please make sure you are running your application using a core in the Nic's NUMA***\n",
														ms_ctime_buf, phase2str(current_phase));
						fprintf(tunLogPtr,"%s %s: ***WARNING: If the above is true, please run the following command to fix ksoftirqd resource issue::: %s\n", 
														ms_ctime_buf, phase2str(current_phase),  buffer);
					}
			}
			else
				{
					fprintf(tunLogPtr,"%s %s: ***WARNING: No known fix for ksoftirqd issue on this NIC at this point:::\n", ms_ctime_buf, phase2str(current_phase));
					fprintf(tunLogPtr,"%s %s: ***WARNING: Please use tools like \"ethtool -L and/or ethtool -X\" to see if you can resolve this issue:::\n", ms_ctime_buf, phase2str(current_phase));
					fprintf(tunLogPtr,"%s %s: ***WARNING: Also, please make sure you are running your application using a core in the Nic's NUMA***\n", ms_ctime_buf, phase2str(current_phase));
				}
		}
		else
			{
				fprintf(tunLogPtr,"%s %s: ***WARNING: can't fix ksoftirqd resource issue with ethtool command at this point***\n", 
															ms_ctime_buf, phase2str(current_phase));
				fprintf(tunLogPtr,"%s %s: ***WARNING: However, please make sure you are running your application using a core in the Nic's NUMA***\n",
															ms_ctime_buf, phase2str(current_phase));
			}
	 }
	 else
		if (nProc)
		{
			if (netDevice_combined_channel_cfg_max_val)
			{
				int combined_to_use = nProc/8;
				int tx_to_use = netDevice_combined_channel_cfg_max_val - combined_to_use;

				if (!netDevice_only_combined_channel_cfg)
				{
					sprintf(buffer,"ethtool -L %s rx 0 tx %d  combined %d",netDevice, tx_to_use, combined_to_use);
					if (gTuningMode && current_phase == LEARNING) //need to fix so that current_phase always has the right mode
					{
						current_phase = TUNING;
						fprintf(tunLogPtr,"%s %s: ***WARNING: running the following command to fix ksoftirqd resource issue::: %s\n", 
														ms_ctime_buf, phase2str(current_phase),  buffer);
						fprintf(tunLogPtr,"%s %s: ***WARNING: Also, please make sure you are running your application using a core in the Nic's NUMA***\n",
																ms_ctime_buf, phase2str(current_phase));
						system(buffer);
						vDidSetChannel = 1;
						current_phase = LEARNING;
					}
					else
						{
							fprintf(tunLogPtr,"%s %s: ***WARNING: Please make sure you are running your application using a core in the Nic's NUMA***\n",
														ms_ctime_buf, phase2str(current_phase));
							fprintf(tunLogPtr,"%s %s: ***WARNING: If the above is true, please run the following command to fix ksoftirqd resource issue::: %s\n", 
														ms_ctime_buf, phase2str(current_phase),  buffer);
						}
				}
				else
					{
#if 0
						sprintf(buffer,"ethtool -L %s combined %d",netDevice, combined_to_use);
						if (gTuningMode && (current_phase == LEARNING)) //need to fix so that current_phase always has the right mode
						{
							current_phase = TUNING;
							fprintf(tunLogPtr,"%s %s: ***WARNING: running the following command to fix ksoftirqd resource issue::: %s\n", 
															ms_ctime_buf, phase2str(current_phase), buffer);
							system(buffer);
							vDidSetChannel = 1;
							current_phase = LEARNING;
						}
						else
							{	
								fprintf(tunLogPtr,"%s %s: ***WARNING: please run the following command to fix ksoftirqd resource issue::: %s\n", 
															ms_ctime_buf, phase2str(current_phase), buffer);
							}
#endif
						fprintf(tunLogPtr,"%s %s: ***WARNING: No known fix for ksoftirqd issue on this NIC at this point:::\n", ms_ctime_buf, phase2str(current_phase));
						fprintf(tunLogPtr,"%s %s: ***WARNING: Please use tools like \"ethtool -L and/or ethtool -X\" to see if you can resolve this issue:::\n", 
																			ms_ctime_buf, phase2str(current_phase));
						fprintf(tunLogPtr,"%s %s: ***WARNING: Also, please make sure you are running your application using a core in the Nic's NUMA***\n",
																			ms_ctime_buf, phase2str(current_phase));
					}
			}
		}
	}
}


void fDoCheckSoftirqd(void);
void fDoCheckSoftirqd(void)
{
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	char buffer[128];
	FILE *pipe;
	char try[1024];
	//double vCpuAmountUsed = 0.0;
        char * foundstr = 0;

	sprintf(try,"top -b -n 1 | grep softirqd | awk \'{ printf(\"%s   %s\\n\", $9, $12); }\' | grep -E \'100|[6-9][0-9].\'", "%-8s", "%-8s");
	//sprintf(try,"top -n 1 | grep softirqd | awk \'{ printf(\"%s   %s\\n\", $10, $13); }\'", "%-8s", "%-8s");
	
	pipe = popen(try,"r");
	if (!pipe)
	{
		printf("popen failed!\n");
		printf("here2***\n");
		return;
	}

	while (!feof(pipe))
	{
		// use buffer to read and add to result
		if (fgets(buffer, 128, pipe) != NULL)
		{
			foundstr = strstr(buffer,"ksoftirqd");
		}
		else
			{
				goto finish_up;
			}

		//should look like example: "25.0        ksoftirqd/0"
		//should look like example: "53.0        ksoftirqd/1"
                if (foundstr)
                {
			gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
			fprintf(tunLogPtr,"%s %s: ***WARNING ksoftirqd is using >= 60%c of CPU resources::: %s", ms_ctime_buf, phase2str(current_phase), '%', buffer);
			
			//sudo ethtool -L netro-switch rx 0 tx 28  combined 4
			fDoSetChannels();
		}
		else
			continue;
	}

finish_up:
	pclose(pipe);
	fflush(tunLogPtr);
return;
}

void * fDoRunFindHighestRtt(void * vargp)
{
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	char buffer[128];
	FILE *pipe;
	char try[1024];
	char aApplyDefTunBest[MAX_SIZE_SYSTEM_SETTING_STRING];
	long rtt = 0, highest_rtt = 0;
	double highest_rtt_from_bpftrace = 0.0;
	double highest_rtt_from_ping = 0.0;
	int applied = 0, suggested = 0, nothing_done = 0;
	int tune = 1; //1 = up, 2 = down - tune up initially

	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
	fprintf(tunLogPtr,"%s %s: ***Starting Finding Highest RTT thread ...***\n", ms_ctime_buf, phase2str(current_phase));
        
	//sprintf(try,"sudo bpftrace -e \'BEGIN { @ca_rtt_us; @str_tsock;} kprobe:tcp_ack_update_rtt { @str_tsock = (struct tcp_sock *) arg0; @ca_rtt_us = arg4; } kretprobe:tcp_ack_update_rtt /pid != 0/ { printf(\"%s %s %s\\n\", @ca_rtt_us, @str_tsock->total_retrans, @str_tsock->segs_out); } interval:ms:125 {  exit(); } END { clear(@ca_rtt_us); clear(@str_tsock);}\'", "%ld", "%u", "%u");
	sprintf(try,"sudo bpftrace -e \'BEGIN { @ca_rtt_us;} kprobe:tcp_ack_update_rtt { @ca_rtt_us = arg4; } kretprobe:tcp_ack_update_rtt /pid != 0/ { printf(\"%s\\n\", @ca_rtt_us); } interval:ms:125 {  exit(); } END { clear(@ca_rtt_us); }\'", "%ld");

rttstart:

	if (previous_average_tx_Gbits_per_sec)
	{
		sleep(1);

		if (vIamASrcDtn)
		{
			highest_rtt_from_ping = fFindRttUsingPing();
		}

		if (vDebugLevel > 2) 
		{
			sleep(1);
			fDoCpuMonitoring();	
		}
	}

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
		//sscanf(buffer,"%lu %u %u", &rtt, &retrans, &packets_sent);
		if (rtt > highest_rtt)
			highest_rtt = rtt;

#if 1
		if (vDebugLevel > 7 && previous_average_tx_Gbits_per_sec) 
			fprintf(tunLogPtr,"%s %s: **rtt = %luus, highest rtt = %luus\n", ms_ctime_buf, phase2str(current_phase), rtt, highest_rtt);
#endif
	}

finish_up:
	pclose(pipe);

	if (highest_rtt)
	{
		highest_rtt_from_bpftrace = highest_rtt/(double)1000;
		if (vDebugLevel > 1 && previous_average_tx_Gbits_per_sec)
		{
			gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
			fprintf(tunLogPtr,"\n%s %s: ***Highest RTT using bpftrace is %.3fms\n", ms_ctime_buf, phase2str(current_phase), highest_rtt_from_bpftrace);
		}

		if (	highest_rtt_from_ping &&  //sometimes highest_rtt_from_ping is zero if not pinging anyone
			((highest_rtt_from_ping > rtt_threshold) || (highest_rtt_from_bpftrace > rtt_threshold)) &&
		    	(((rtt_factor * highest_rtt_from_ping) <= highest_rtt_from_bpftrace) || ((rtt_factor * highest_rtt_from_bpftrace) <= highest_rtt_from_ping))
		   )
		{
			if (vDebugLevel > 0)
			{
				gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
				fprintf(tunLogPtr,"%s %s: !!!***WARNING: RTT from bpftrace and ping differs by a factor of %d and at least 1 is above the threshold of %.2fms***\n", 
						ms_ctime_buf, phase2str(current_phase), rtt_factor, rtt_threshold);
				fprintf(tunLogPtr,"%s!!!**RTT from bpftrace is %.3fms **** !!!**RTT from ping is %.3fms\n", 
						pLearningSpaces, highest_rtt_from_bpftrace, highest_rtt_from_ping);
			}
			//leave line below in for now			
			fDoManageRtt(highest_rtt_from_bpftrace, &applied, &suggested, &nothing_done, &tune, aApplyDefTunBest, 1); //1 is from bpftrace
		}
#if 0	
		if (highest_rtt_from_ping >= RTT_THRESHOLD)
			fDoManageRtt(highest_rtt_from_ping, &applied, &suggested, &nothing_done, &tune, aApplyDefTunBest, 0); //0 is from ping
#endif
	}

	if (vDebugLevel > 6 && previous_average_tx_Gbits_per_sec)
	{
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(tunLogPtr, "%s %s: ***Sleeping for 250000 microseconds before resuming RTT checking...\n", ms_ctime_buf, phase2str(current_phase)); //2 x 250000
	}

	fflush(tunLogPtr);
	my_usleep(250000); //sleeps in microseconds	
	if (vDebugLevel > 0)
		fDoCheckSoftirqd(); //Just added
	my_usleep(250000); 
	goto rttstart;

return ((char *) 0);
}

void * fDoRunHelperDtn(void * vargp)
{
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	struct stat sb;

	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
	fprintf(tunLogPtr,"%s %s: ***Starting HelperDtn thread ...***\n", ms_ctime_buf, phase2str(current_phase));
	fflush(tunLogPtr);
	//check if already running
	system("ps -ef | grep -v grep | grep help_dtn.sh  > /tmp/help_dtn_alive.out 2>/dev/null");
	stat("/tmp/help_dtn_alive.out", &sb);
	if (sb.st_size == 0); //good - no runaway process
	else //kill it
	{
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Killing runaway help_dtn.sh process\n", ms_ctime_buf, phase2str(current_phase));
		system("pkill -9 help_dtn.sh");
	}

	system("rm -f /tmp/help_dtn_alive.out");
	sleep(1); //relax

restart_fork:
	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
	fprintf(tunLogPtr, "%s %s: ***About to fork new help_dtn.sh process\n", ms_ctime_buf, phase2str(current_phase));
	fflush(tunLogPtr);

	pid_t ppid_before_fork = getpid();
	pid_t pid = fork();
	if (pid == 0)
	{ 
		int r = prctl(PR_SET_PDEATHSIG, SIGTERM); //tell me if my parent went away
		if (r == -1) { perror(0); exit(1); }
		// test in case the original parent exited just
		// before the prctl() call
		if (getppid() != ppid_before_fork)
			exit(1);
		// continue child execution ...
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
			goto restart_fork;
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
	time_t clk;
        char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	int sigret;
	static struct sigaction act;
        memset(&act, 0, sizeof(act));

        act.sa_handler = SIG_IGN;;
        sigemptyset(&act.sa_mask); //no additional signals will be blocked
        act.sa_flags = 0;

	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);

        sigret = sigaction(SIGCHLD, &act, NULL);
	if (sigret == 0)
		fprintf(tunLogPtr, "%s %s: SIGCHLD ignored***\n", ms_ctime_buf, phase2str(current_phase));
	else
		fprintf(tunLogPtr, "%s %s: SIGCHLD notignored***\n", ms_ctime_buf, phase2str(current_phase));
	
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

#ifdef HPNSSH_QFACTOR
void * doProcessHpnClientReq(void * arg)
{
	ssize_t	n;
#ifdef HPNSSH_QFACTOR_BINN
        struct ClientBinnMsg sMsg;
	char from_cli[BUFFER_SIZE_FROM_CLIENT];
#else
	struct PeerMsg	from_cli;
#endif
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];

	int sockfd = (int)arg;

	pthread_detach(pthread_self());

	for ( ; ; ) 
	{
		//struct binn_struct from_cli;

#ifdef HPNSSH_QFACTOR_BINN
		if ( (n = Readn(sockfd, from_cli, sizeof(from_cli))) == 0)
#else
		if ( (n = Readn(sockfd, &from_cli, sizeof(from_cli))) == 0)
#endif
		{
			if (vDebugLevel > 0)
			{
				fprintf(tunLogPtr,"\n%s %s: ***Hpn Client Connection closed***\n", ms_ctime_buf, phase2str(current_phase));
				fflush(tunLogPtr);
			}

			Close(sockfd);
			return (NULL);         /* connection closed by other end */
		}
			
#ifdef HPNSSH_QFACTOR_BINN
#if 0
		if (vDebugLevel > 1)
		{
			fprintf(tunLogPtr,"\n%s %s: ***num bytes read from Hpn Client = %lu***\n", ms_ctime_buf, phase2str(current_phase),n);
			fflush(tunLogPtr);
		}
#endif
		fRead_Binn_Client_Object(&sMsg, (binn *)&from_cli);
#endif
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
#ifdef HPNSSH_QFACTOR_BINN
		//if (ntohl(sMsg.msg_type) == HPNSSH_MSG)
		if (sMsg.msg_type == HPNSSH_MSG)
		{
			if (vDebugLevel > 0)
			{
				fprintf(tunLogPtr,"\n%s %s: ***Received Hpnssh message from Hpnssh Client...***\n", ms_ctime_buf, phase2str(current_phase));
				fprintf(tunLogPtr,"%s %s: ***msg type = %d, msg op = %u\n", ms_ctime_buf, phase2str(current_phase), sMsg.msg_type, sMsg.op);
			}
				
			fDoHpnAssessment(sMsg.op, sockfd);
		}
			else
				if (vDebugLevel > 0)
				{
					fprintf(tunLogPtr,"\n%s %s: ***Received unknown message from some Hpn client???...***\n", ms_ctime_buf, phase2str(current_phase));
					fprintf(tunLogPtr,"%s %s: ***msg_type = %d", ms_ctime_buf, phase2str(current_phase), sMsg.msg_type);
				}

		fflush(tunLogPtr);
	}
}
#else
		if (ntohl(from_cli.msg_no) == HPNSSH_MSG)
		{
			if (vDebugLevel > 1)
			{
				fprintf(tunLogPtr,"\n%s %s: ***Received Hpnssh message %u from Hpnssh Client...***\n", 
									ms_ctime_buf, phase2str(current_phase), ntohl(from_cli.seq_no));
				fprintf(tunLogPtr,"%s %s: ***msg_no = %d, msg value = %u, msg buf = %s\n", 
						ms_ctime_buf, phase2str(current_phase), ntohl(from_cli.msg_no), ntohl(from_cli.value), from_cli.msg);
			}
				
			fDoHpnAssessment(ntohl(from_cli.value), sockfd);
		}
			else
				if (vDebugLevel > 0)
				{
					fprintf(tunLogPtr,"\n%s %s: ***Received a message %u from some Hpn client???...***\n", ms_ctime_buf, phase2str(current_phase), ntohl(from_cli.seq_no));
					fprintf(tunLogPtr,"%s %s: ***msg_no = %d, msg buf = %s", ms_ctime_buf, phase2str(current_phase), ntohl(from_cli.msg_no), from_cli.msg);
				}

		fflush(tunLogPtr);
	}
}
#endif
#endif

void
process_request(int sockfd)
{
	ssize_t	n;
	struct PeerMsg	from_cli;
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];

	for ( ; ; ) 
	{
		if ( (n = Readn(sockfd, &from_cli, sizeof(from_cli))) == 0)
		{
			return;         /* connection closed by other end */
		}

		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		if (ntohl(from_cli.msg_no) == QINFO_MSG)
		{
			if (vDebugLevel > 0)
			{
				fprintf(tunLogPtr,"\n%s %s: ***Received Qinfo message %u from destination DTN...***\n", ms_ctime_buf, phase2str(current_phase), ntohl(from_cli.seq_no));
				fprintf(tunLogPtr,"%s %s: ***msg_no = %d, msg value = %u, msg buf = %s", ms_ctime_buf, phase2str(current_phase), ntohl(from_cli.msg_no), ntohl(from_cli.value), from_cli.msg);
			}

			fDoQinfoAssessment(ntohl(from_cli.value));
		}
		else
			if (vDebugLevel > 0)
			{
				fprintf(tunLogPtr,"\n%s %s: ***Received a message %u from destination DTN...***\n", 
								ms_ctime_buf, phase2str(current_phase), ntohl(from_cli.seq_no));
				fprintf(tunLogPtr,"%s %s: ***msg_no = %d, msg buf = %s", 
								ms_ctime_buf, phase2str(current_phase), ntohl(from_cli.msg_no), from_cli.msg);
			}

		fflush(tunLogPtr);
	}
}

#ifdef HPNSSH_QFACTOR
void * doHandleHpnsshQfactorEnv(void * vargp)
{
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	int listenfd, connfd;
	pthread_t tid;
	socklen_t clilen;
	struct sockaddr_in cliaddr, servaddr;
	
#if 1
			struct sockaddr_in peeraddr;
			socklen_t peeraddrlen;
			struct sockaddr_in localaddr;
			socklen_t localaddrlen;

			peeraddrlen = sizeof(peeraddr);
			localaddrlen = sizeof(localaddr);
#endif
	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
	fprintf(tunLogPtr,"%s %s: ***Starting Listener for receiving messages from HPNSSH...***\n", ms_ctime_buf, phase2str(current_phase));
	fflush(tunLogPtr);
	
	listenfd = Socket(AF_INET, SOCK_STREAM, 0);

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family      = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port        = htons(gSource_HpnsshQfactor_Port);

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
#if 1
		fprintf(tunLogPtr,"%s %s: ***Accepted connection with Listener for receiving messages from HPNSSH...***\n", ms_ctime_buf, phase2str(current_phase));
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);

		int retval = getpeername(connfd, (struct sockaddr *) &peeraddr, &peeraddrlen);
		if (retval == -1) 
		{
			fprintf(tunLogPtr,"%s %s: ***Peer error:***\n", ms_ctime_buf, phase2str(current_phase));
		//	perror("getpeername()");
		}
		else
			{
				char *peeraddrpresn = inet_ntoa(peeraddr.sin_addr);
				//total_time_passed = 0;
				if (vDebugLevel > 1)
				{
					fprintf(tunLogPtr,"%s %s: ***Peer information: ip long %s\n", ms_ctime_buf, phase2str(current_phase), aDest_Ip2_Binary);
					fprintf(tunLogPtr,"%s %s: ***Peer information:\n", ms_ctime_buf, phase2str(current_phase));
					fprintf(tunLogPtr,"%s %s: ***Peer Address Family: %d\n", ms_ctime_buf, phase2str(current_phase), peeraddr.sin_family);
					fprintf(tunLogPtr,"%s %s: ***Peer Port: %d\n", ms_ctime_buf, phase2str(current_phase), peeraddr.sin_port);
					fprintf(tunLogPtr,"%s %s: ***Peer IP Address: %s***\n\n", ms_ctime_buf, phase2str(current_phase), peeraddrpresn);
				}
			}

		retval = getsockname(connfd, (struct sockaddr *) &localaddr, &localaddrlen);
		if (retval == -1) 
		{
			fprintf(tunLogPtr,"%s %s: ***sock error:***\n", ms_ctime_buf, phase2str(current_phase));
		}
		else
			{
				char *localaddrpresn = inet_ntoa(localaddr.sin_addr);

				if (vDebugLevel > 1)
				{
					fprintf(tunLogPtr,"%s %s: ***Socket information:\n", ms_ctime_buf, phase2str(current_phase));
					fprintf(tunLogPtr,"%s %s: ***Local Address Family: %d\n", ms_ctime_buf, phase2str(current_phase), localaddr.sin_family);
					fprintf(tunLogPtr,"%s %s: ***Local Port: %d\n", ms_ctime_buf, phase2str(current_phase), ntohs(localaddr.sin_port));
					fprintf(tunLogPtr,"%s %s: ***Local IP Address: %s***\n\n", ms_ctime_buf, phase2str(current_phase), localaddrpresn);
				}
				//strcpy(aLocal_Ip,localaddrpresn);
			}

		fflush(tunLogPtr);
#endif


#if 0
		if ( (childpid = Fork()) == 0) 
		{        /* child process */

			Close(listenfd); /* close listening socket */
			process_request(connfd);/* process the request */
			exit(0);
		}
#endif	
		pthread_create(&tid, NULL, &doProcessHpnClientReq, (void *) connfd);
		//process_request(connfd);/* process the request */
		
		//Close(connfd); /* parent closes connected socket */
	}

	return ((char *)0);
}
#endif

void * fDoRunGetMessageFromPeer(void * vargp)
{
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	int listenfd, connfd;
	pid_t childpid;
	socklen_t clilen;
	struct sockaddr_in cliaddr, servaddr;
	
#if 1
			struct sockaddr_in peeraddr;
			socklen_t peeraddrlen;
			struct sockaddr_in localaddr;
			socklen_t localaddrlen;

			peeraddrlen = sizeof(peeraddr);
			localaddrlen = sizeof(localaddr);
#endif
	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
	fprintf(tunLogPtr,"%s %s: ***Starting Listener for receiving messages from destination DTN...***\n", ms_ctime_buf, phase2str(current_phase));
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
#if 1
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);

		int retval = getpeername(connfd, (struct sockaddr *) &peeraddr, &peeraddrlen);
		if (retval == -1) 
		{
			fprintf(tunLogPtr,"%s %s: ***Peer error:***\n", ms_ctime_buf, phase2str(current_phase));
		//	perror("getpeername()");
		}
		else
			{
				char *peeraddrpresn = inet_ntoa(peeraddr.sin_addr);
				sprintf(aDest_Ip2_Binary,"%02X",peeraddr.sin_addr.s_addr);
				//total_time_passed = 0;
				if (vDebugLevel > 1)
				{
					fprintf(tunLogPtr,"%s %s: ***Peer information: ip long %s\n", ms_ctime_buf, phase2str(current_phase), aDest_Ip2_Binary);
					fprintf(tunLogPtr,"%s %s: ***Peer information:\n", ms_ctime_buf, phase2str(current_phase));
					fprintf(tunLogPtr,"%s %s: ***Peer Address Family: %d\n", ms_ctime_buf, phase2str(current_phase), peeraddr.sin_family);
					fprintf(tunLogPtr,"%s %s: ***Peer Port: %d\n", ms_ctime_buf, phase2str(current_phase), peeraddr.sin_port);
					fprintf(tunLogPtr,"%s %s: ***Peer IP Address: %s***\n\n", ms_ctime_buf, phase2str(current_phase), peeraddrpresn);
				}

				vIamASrcDtn = 1;	
				strcpy(aDest_Ip2,peeraddrpresn);
			}

		retval = getsockname(connfd, (struct sockaddr *) &localaddr, &localaddrlen);
		if (retval == -1) 
		{
			fprintf(tunLogPtr,"%s %s: ***sock error:***\n", ms_ctime_buf, phase2str(current_phase));
		}
		else
			{
				char *localaddrpresn = inet_ntoa(localaddr.sin_addr);

				if (vDebugLevel > 1)
				{
					fprintf(tunLogPtr,"%s %s: ***Socket information:\n", ms_ctime_buf, phase2str(current_phase));
					fprintf(tunLogPtr,"%s %s: ***Local Address Family: %d\n", ms_ctime_buf, phase2str(current_phase), localaddr.sin_family);
					fprintf(tunLogPtr,"%s %s: ***Local Port: %d\n", ms_ctime_buf, phase2str(current_phase), ntohs(localaddr.sin_port));
					fprintf(tunLogPtr,"%s %s: ***Local IP Address: %s***\n\n", ms_ctime_buf, phase2str(current_phase), localaddrpresn);
				}

				strcpy(aLocal_Ip,localaddrpresn);
			}

		fflush(tunLogPtr);
#endif


#if 1
		if ( (childpid = Fork()) == 0) 
		{        /* child process */

			Close(listenfd); /* close listening socket */
			process_request(connfd);/* process the request */
			exit(0);
		}
#endif	
		
		Close(connfd); /* parent closes connected socket */
	}

	return ((char *)0);
}

void read_sock(int sockfd)
{
	ssize_t                 n;
	struct PeerMsg             from_cli;

	for ( ; ; ) 
	{
		if ( (n = Readn(sockfd, &from_cli, sizeof(from_cli))) == 0)
			return;         /* connection closed by other end */

		printf("msg seq_no = %d, msg buf = %s", from_cli.seq_no, from_cli.msg);
	}
}

int str_cli(int sockfd, struct PeerMsg *sThisMsg) //str_cli09
{
	int y;
#ifdef HPNSSH_QFACTOR_BINN
        binn *myobj = binn_object();
        fMake_Binn_Server_Object(sThisMsg, myobj);
#if 0
	fprintf(tunLogPtr,"***!!!!!!!Size of binn object = %u...***\n", binn_size(myobj));
	fflush(tunLogPtr);
#endif
        y = Writen(sockfd, binn_ptr(myobj), binn_size(myobj));
	binn_free(myobj);
#else
	y = Writen(sockfd, sThisMsg, sizeof(struct PeerMsg));
#endif
	return y;
}

int str_cli_nohpn(int sockfd, struct PeerMsg *sThisMsg) //str_cli09
{
	int y;
	y = Writen(sockfd, sThisMsg, sizeof(struct PeerMsg));
	return y;
}

void * fDoRunSendMessageToPeer(void * vargp)
{
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	int sockfd;
	struct sockaddr_in servaddr;
	struct PeerMsg sMsg2;
	int check = 0;

	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
	fprintf(tunLogPtr,"%s %s: ***Starting Client for sending messages to source DTN...***\n", ms_ctime_buf, phase2str(current_phase));
	fflush(tunLogPtr);

cli_again:
	Pthread_mutex_lock(&dtn_mutex);
	
	while(cdone == 0)
		Pthread_cond_wait(&dtn_cond, &dtn_mutex);
	memcpy(&sMsg2,&sMsg,sizeof(sMsg2));
	cdone = 0;
	Pthread_mutex_unlock(&dtn_mutex);

	if (vDebugLevel > 1)
	{
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(tunLogPtr,"%s %s: ***Sending message %d to source DTN...***\n", ms_ctime_buf, phase2str(current_phase), sleep_count);
		fflush(tunLogPtr);
	}

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
	str_cli_nohpn(sockfd, &sMsg2);         /* do it all */
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

	int vRetFromRunFindRetransmissionRateThread, vRetFromRunFindRetransmissionRateJoin;
	pthread_t doRunFindRetransmissionRateThread_id;

#ifdef HPNSSH_QFACTOR
	int vRetFromHandleHpnsshQfactorEnvThread, vRetFromHandleHpnsshQfactorEnvJoin;
	pthread_t doHandleHpnsshQfactorEnvThread_id;
#endif

	sArgv_t sArgv;
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	int vExitValue = 0;

	/*
	 * Make a daemon process
	 * - run in the backgound
	 * - prevent output from process from going to the controlling terminal
	 */

	if (argc == 2 && (strcmp(argv[1],"rf") == 0));
	else
	{
		if (fork() != 0) /* make daemon process */
			exit(0);
	}

	system("sh ./user_menu.sh"); //make backup of tuningLog first if already exist
	tunLogPtr = fopen("/tmp/tuningLog","w");
	if (!tunLogPtr)
	{
		printf("Could not open tuning Logfile, exiting...\n");
		exit(-1);
	}

	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
	fprintf(tunLogPtr, "%s %s: tuning Log opened***\n", ms_ctime_buf, phase2str(current_phase));

	ignore_sigchld(); //won't leave zombie processes

	sArgv.argc = argc;
	sArgv.argv = argv;
	
	catch_sigint();

	fDoGetUserCfgValues();
	if (argc == 3)
	{
		int vRet;
		strcpy(netDevice,argv[2]);
		fprintf(tunLogPtr, "%s %s: using Device name %s supplied from command line***\n", ms_ctime_buf, phase2str(current_phase), netDevice);
		vRet = fCheckInterfaceExist();
		if (!vRet)
		{
			int vSpeedInGb;
			fprintf(tunLogPtr, "%s %s: Found Device %s***\n", ms_ctime_buf, phase2str(current_phase), argv[2]);
			fDoGetDeviceCap(); //Will set netDeviceSpeed if device is UP
			vSpeedInGb = netDeviceSpeed/1000; //Should become zero if invalid speed (0 or -1)
			if (!vSpeedInGb)
			{
				fprintf(tunLogPtr, "%s %s: Device *%s* link is probably DOWN as its speed in invalid.***\n", ms_ctime_buf, phase2str(current_phase), argv[2]);
				fprintf(tunLogPtr, "%s %s: Please use a device whose link is UP. Exiting...***\n", ms_ctime_buf, phase2str(current_phase));
				fflush(tunLogPtr);
				vExitValue = -3;
				goto leave;
			}
		}
		else
			{
				gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
				fprintf(tunLogPtr, "%s %s: Device not found, Invalid device name *%s*, Exiting...***\n", ms_ctime_buf, phase2str(current_phase), argv[2]);
				vExitValue = -1;
				goto leave;
			}
	}
	else
		{
			gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
			if (gNic_to_use)
			{
				int vRet;
				strcpy(netDevice,gNic_to_use);
				fprintf(tunLogPtr, "%s %s: using Device name %s supplied from file *user_config.txt*\n", ms_ctime_buf, phase2str(current_phase), netDevice);
				vRet = fCheckInterfaceExist();
				if (!vRet)
				{
					int vSpeedInGb;
					fprintf(tunLogPtr, "%s %s: Found Device %s***\n", ms_ctime_buf, phase2str(current_phase), netDevice);
					fDoGetDeviceCap(); //Will set netDeviceSpeed if device is UP
					vSpeedInGb = netDeviceSpeed/1000; //Should become zero if invalid speed (0 or -1)
					if (!vSpeedInGb)
					{
						fprintf(tunLogPtr, "%s %s: Device *%s* link is probably DOWN as its speed in invalid.***\n", ms_ctime_buf, phase2str(current_phase), netDevice);
						fprintf(tunLogPtr, "%s %s: Please use a device whose link is UP. Exiting...***\n", ms_ctime_buf, phase2str(current_phase));
						fflush(tunLogPtr);
						vExitValue = -4;
						goto leave;
					}
				}
				else
					{
						gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
						fprintf(tunLogPtr, "%s %s: Device not found, Invalid device name *%s*, Exiting...***\n", ms_ctime_buf, phase2str(current_phase), netDevice);
						vExitValue = -5;
						goto leave;
					}
			}
			else //shouldn't happen
				{
					fprintf(tunLogPtr, "%s %s: Device name not supplied, exiting***\n", ms_ctime_buf, phase2str(current_phase));
					exit(-3);
				}
		}

	fflush(tunLogPtr);

	open_csv_file();	
	user_assess(argc, argv);
	fCheck_log_limit();
	
	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
	current_phase = LEARNING;

	memset(metaData,0,sizeof(metaData));
	memset(qinfo_ms_ctime_buf_min,0,sizeof(qinfo_ms_ctime_buf_min));
	memset(qinfo_ms_ctime_buf_max,0,sizeof(qinfo_ms_ctime_buf_max));
	memset(&sMsg,0,sizeof(sMsg));
	memset(sFlowCounters,0,sizeof(sFlowCounters));
	memset(aSrc_Ip,0,sizeof(aSrc_Ip));
	memset(aDest_Ip2,0,sizeof(aDest_Ip2));
	memset(aDest_Ip2_Binary,0,sizeof(aDest_Ip2_Binary));
	memset(aLocal_Ip,0,sizeof(aLocal_Ip));
	src_ip_addr.y = 0;
#ifdef INCLUDE_SRC_PORT
	src_port = 0;
#endif
	vGoodBitrateValue = (((97/(double)100) * netDeviceSpeed)/(double)1000); //97% of NIC speed is a good bitrate threshold
	vGoodBitrateValueThatDoesntNeedMessage = (((88/(double)100) * netDeviceSpeed)/(double)1000); //Won't print 'BITRATE IS LOW' message in this case - log gets cumbersome
	fprintf(tunLogPtr, "%s %s: ***vGoodBitrateValue = %.1fGb/s*** //97%% of NIC speed is a good bitrate threshold \n", ms_ctime_buf, phase2str(current_phase), vGoodBitrateValue);
	fprintf(tunLogPtr, "%s %s: ***Number of CPUs on system = %d***\n", ms_ctime_buf, phase2str(current_phase), nProc);
	fprintf(tunLogPtr, "%s %s: ***Numa Node for %s is %d***\n", ms_ctime_buf, phase2str(current_phase), netDevice, numaNode);
	if (numaNodeString[0])
	{
		fprintf(tunLogPtr, "%s %s: ***You should use one of the following cores for application use when using the %s Device:\n", ms_ctime_buf, phase2str(current_phase), netDevice);
		fprintf(tunLogPtr, "%s %s: ***%s\n", ms_ctime_buf, phase2str(current_phase), numaNodeString);
	}
	fflush(tunLogPtr);

	system("rm -f /tmp/facil-io-sock-*"); //clean up old facil-io links
	fprintf(tunLogPtr, "%s %s: ***Debug level is set to %d\n", ms_ctime_buf, phase2str(current_phase), vDebugLevel);

	shm = shm_new(sizeof vResetPacingBack);

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
	//Find Retransmission rate to help determine congestion
	vRetFromRunFindRetransmissionRateThread = pthread_create(&doRunFindRetransmissionRateThread_id, NULL, doRunFindRetransmissionRate, &sArgv); 

#ifdef HPNSSH_QFACTOR
	//Handle messages from hpnssh client
	vRetFromHandleHpnsshQfactorEnvThread = pthread_create(&doHandleHpnsshQfactorEnvThread_id, NULL, doHandleHpnsshQfactorEnv, &sArgv);
	memset(&sHpnRetMsg,0,sizeof(sHpnRetMsg));
	strcpy(sHpnRetMsg.msg, "Hello there!!! This is a Hpn msg...\n");
	sHpnRetMsg.msg_no = htonl(HPNSSH_MSG);
	
	memset(&sHpnRetMsg2,0,sizeof(sHpnRetMsg));
	strcpy(sHpnRetMsg2.msg, "Hello there!!! This is a Hpn msg...\n");
	sHpnRetMsg2.msg_no = htonl(HPNSSH_MSG);

	memset(&sTimeoutMsg,0,sizeof(sTimeoutMsg));
	strcpy(sTimeoutMsg.msg, "Hello there!!! This is  a dummy message ..., Here's some data\n");
        sTimeoutMsg.msg_no = htonl(HPNSSH_MSG);
        sTimeoutMsg.value = htonl(HPNSSH_DUMMY);;
        memcpy(sTimeoutMsg.timestamp, ms_ctime_buf, MS_CTIME_BUF_LEN);
        sTimeoutMsg.hop_latency = htonl(1);
        sTimeoutMsg.queue_occupancy = htonl(2);
        sTimeoutMsg.switch_id = htonl(3);
        sTimeoutMsg.seq_no = htonl(4);

	//Send messages tp HpnsshQfactor server for simulated testing
#endif
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

	if (vRetFromRunFindRetransmissionRateThread == 0)
		vRetFromRunFindRetransmissionRateJoin = pthread_join(doRunFindRetransmissionRateThread_id, NULL); 

#ifdef HPNSSH_QFACTOR
	if (vRetFromHandleHpnsshQfactorEnvThread == 0)
		vRetFromHandleHpnsshQfactorEnvJoin = pthread_join(doHandleHpnsshQfactorEnvThread_id, NULL);
#endif

leave:
	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
	fprintf(tunLogPtr, "%s %s: Closing tuning Log***\n", ms_ctime_buf, phase2str(current_phase));
	fclose(tunLogPtr);

return vExitValue;
}

