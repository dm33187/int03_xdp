/* include unph */
/* Our own header.  Tabs are set for 4 spaces, not 8 */

#ifndef	__unp_h
#define	__unp_h

/* If anything changes in the following list of #includes, must change
   acsite.m4 also, for configure's tests. */

#include	<sys/types.h>	/* basic system data types */
#include	<sys/socket.h>	/* basic socket definitions */
#if TIME_WITH_SYS_TIME
#include	<sys/time.h>	/* timeval{} for select() */
#include	<time.h>		/* timespec{} for pselect() */
#else
#if HAVE_SYS_TIME_H
#include	<sys/time.h>	/* includes <time.h> unsafely */
#else
#include	<time.h>		/* old system? */
#endif
#endif
#include	<netinet/in.h>	/* sockaddr_in{} and other Internet defns */
#include	<arpa/inet.h>	/* inet(3) functions */
#include	<errno.h>
#include	<fcntl.h>		/* for nonblocking */
#include	<netdb.h>
#include	<signal.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<sys/stat.h>	/* for S_xxx file mode constants */
#include	<sys/uio.h>		/* for iovec{} and readv/writev */
#include	<unistd.h>
#include	<sys/wait.h>
#include	<sys/un.h>		/* for Unix domain sockets */

# include	<pthread.h>

#if 0 //keep for reference
#ifndef INET6_ADDRSTRLEN
/* $$.Ic INET6_ADDRSTRLEN$$ */
#define	INET6_ADDRSTRLEN	46	/* max size of IPv6 address string:
				   "xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx" or
				   "xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:ddd.ddd.ddd.ddd\0"
				    1234567890123456789012345678901234567890123456 */
#endif
#endif

/* Following could be derived from SOMAXCONN in <sys/socket.h>, but many
   kernels still #define it as 5, while actually supporting many more */
#define	LISTENQ		1024	/* 2nd argument to listen() */

/* Miscellaneous constants */
#define	MAXLINE		4096	/* max text line length */

/* Following shortens all the typecasts of pointer arguments: */
#define	SA	struct sockaddr

//Added for Q-Factor
#define CTIME_BUF_LEN		27
#define MS_CTIME_BUF_LEN	48

#if 1
#define HPNSSH_QFACTOR  1
#endif

#define TEST_MSG	0
#define QINFO_MSG	1
#define HPNSSH_MSG 	2

//For HPNSSH_MSGs value will be whether to do a read or readall or shutdown
#define HPNSSH_READ	33
#define HPNSSH_READALL	44
#define HPNSSH_SHUTDOWN	55
#define	HPNSSH_START	99
#define	HPNSSH_DUMMY	166

struct PeerMsg {
	unsigned int msg_no;
	unsigned int seq_no;
	unsigned int value;
	unsigned int hop_latency;
	unsigned int queue_occupancy;
	unsigned int switch_id;
	char timestamp[MS_CTIME_BUF_LEN];
	char msg[80];
	char * pts;
};
/*****************/
int str_cli(int sockfd, struct PeerMsg *sThisMsg);
void     process_request(int);
void     read_sock(int);
//void     str_cli(FILE *, int);
const char              *Inet_ntop(int, const void *, char *, size_t);
void                     Inet_pton(int, const char *, void *);
			/* prototypes for our Unix wrapper functions: see {Sec errors} */
void	 Close(int);
pid_t	 Fork(void);

/* prototypes for our socket wrapper functions: see {Sec errors} */
int	 Accept(int, SA *, socklen_t *);
void	 Bind(int, const SA *, socklen_t);
int	 Connect(int, const SA *, socklen_t);
void	 Listen(int, int);
int	 Socket(int, int, int);
int	 Writen(int, void *, size_t);

int	 err_sys(const char *, ...);
#endif	/* __unp_h */
