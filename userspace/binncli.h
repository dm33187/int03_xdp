#ifndef __binncli_h
#define __binncli_h

#include "/usr/local/include/binn.h"
#define BUFFER_SIZE_FROM_SERVER 77
#define BUFFER_SIZE_FROM_CLIENT 19

#define CTIME_BUF_LEN           27
#define MS_CTIME_BUF_LEN        48

//For HPNSSH_MSGs operations
#define HPNSSH_MSG		 2

#define HPNSSH_READ		 33
#define HPNSSH_READALL		 44
#define HPNSSH_SHUTDOWN		 55
#define HPNSSH_START		 99
#define HPNSSH_READ_FS		133
#define HPNSSH_READALL_FS  	144  //from server

struct ServerBinnMsg {
	unsigned int msg_type;
	unsigned int op;
	unsigned int hop_latency;
	unsigned int queue_occupancy;
	unsigned int switch_id;
        char timestamp[MS_CTIME_BUF_LEN];
};

struct ClientBinnMsg {
	unsigned int msg_type;
	unsigned int op;
};
#endif //__binncli_h
