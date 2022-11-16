#ifndef __user_dtn_h
#define __user_dtn_h
//extern enum workflow_phases;

#define WORKFLOW_NAMES_MAX      4

enum workflow_phases {
        STARTING,
        ASSESSMENT,
        LEARNING,
        TUNING,
};

#define TUNING_NUMS_10GandUnder 9
#define TUNING_NUMS_Over10GtoUnder100G  9
#define TUNING_NUMS_100G        11
#define MAX_SIZE_SYSTEM_SETTING_STRING  768
typedef struct {
        char * setting;
        unsigned int  minimum;
        int xDefault; //if default is -1, then default and max are nops
        unsigned int maximum;
}host_tuning_vals_t;

extern host_tuning_vals_t aTuningNumsToUse10GandUnder[TUNING_NUMS_10GandUnder];
extern host_tuning_vals_t aTuningNumsToUse_Over10GtoUnder100G[TUNING_NUMS_Over10GtoUnder100G];
extern host_tuning_vals_t aTuningNumsToUse100Gb[TUNING_NUMS_100G];

extern const char *phase2str(enum workflow_phases phase);
extern FILE * tunLogPtr;
extern enum workflow_phases current_phase;
extern int gInterval;
extern int gAPI_listen_port;
extern int gSource_Dtn_Port;
extern char gTuningMode;
extern char netDevice[];
extern char *gNic_to_use;
extern int netDeviceSpeed;

extern void gettime(time_t *clk, char *ctime_buf);
extern int user_assess(int argc, char **argv);
extern int fCheckInterfaceExist();
extern void fDoGetDeviceCap(void);
extern void fDoGetUserCfgValues(void);
extern void fDoBiosTuning(void);
extern void fDoNicTuning(void);
extern void fDoSystemtuning(void);
extern void fDo_lshw(void);
extern void fCheck_log_limit(void);

extern void Pthread_mutex_lock(pthread_mutex_t *);
extern void Pthread_mutex_unlock(pthread_mutex_t *);
extern void Pthread_cond_signal(pthread_cond_t *cptr);
extern void Pthread_cond_wait(pthread_cond_t *cptr, pthread_mutex_t *mptr);
#endif /* __user_dtn_h */
