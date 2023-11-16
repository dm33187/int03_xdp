#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/time.h>    /* timeval{} for select() */
#include <time.h>                /* timespec{} for pselect() */
#include <pthread.h>
#include <stdarg.h>              /* ANSI C header file */
#include <syslog.h>              /* for syslog() */
#include "binncli.h"

#define WORKFLOW_NAMES_MAX      4
#define	MAXLINE		4096	/* max text line length */

typedef struct {
	int argc;
	char ** argv;
} sArgv_t;

int vDebugLevel = 2;
int vPort = 5525; //default listening port
int vShutdown = 0;
FILE * pHpnServerLogPtr = 0;

#define SA struct sockaddr
#define	LISTENQ	1024	/* 2nd argument to listen() */
/* prototypes for socket wrapper functions */
int     Accept(int, SA *, socklen_t *);
void    Bind(int, const SA *, socklen_t);
void    Listen(int, int);
int     Socket(int, int, int);
int     Writen(int, void *, size_t);
int	err_sys(const char *, ...);

int	daemon_proc;            /* set nonzero by daemon_init() */
static void err_doit(int, int, const char *, va_list);

/* Print message and return to caller
 * Caller specifies "errnoflag" and "level" */
static void
err_doit(int errnoflag, int level, const char *fmt, va_list ap)
{
	int errno_save, n;
	char buf[MAXLINE + 1];

	errno_save = errno;             /* value caller might want printed */
#ifdef  HAVE_VSNPRINTF
	vsnprintf(buf, MAXLINE, fmt, ap);       /* safe */
#else
	vsprintf(buf, fmt, ap);                                 /* not safe */
#endif
	n = strlen(buf);
	if (errnoflag)
		snprintf(buf + n, MAXLINE - n, ": %s", strerror(errno_save));
	
	strcat(buf, "\n");

	if (daemon_proc) 
	{
		syslog(level, "%s", buf);
	} 
	else 
		{
			fflush(stdout);         /* in case stdout and stderr are the same */
			fputs(buf, stderr);
			fflush(stderr);
		}
	
	return;
}

int
err_sys(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	err_doit(1, LOG_ERR, fmt, ap);
	va_end(ap);

	return 1;
}

void Close(int fd)
{
	if (close(fd) == -1)
		printf("close error\n");

	return;
}

int Socket(int family, int type, int protocol)
{
	int             n;

	if ( (n = socket(family, type, protocol)) < 0)
	{
		printf("socket error\n");
		exit(2);
        }
	
	return(n);
}

ssize_t writen(int fd, const void *vptr, size_t n)
{
	size_t nleft;
	ssize_t nwritten;
	const char *ptr;

	ptr = vptr;
	nleft = n;
	while (nleft > 0)
	{
		if ( (nwritten = write(fd, ptr, nleft)) <= 0)
		{
			if (nwritten < 0 && errno == EINTR)
			{
				nwritten = 0;   /* and call write() again */
			}
			else
				return(-1);     /* error */
		}

		nleft -= nwritten;
		ptr   += nwritten;
	}

	return(n);
}

/* include Listen */
void
Listen(int fd, int backlog)
{
	char    *ptr;

	/*4can override 2nd argument with environment variable */
	if ( (ptr = getenv("LISTENQ")) != NULL)
		backlog = atoi(ptr);

	if (listen(fd, backlog) < 0)
		err_sys("listen error");
}
/* end Listen */

void gettime(time_t *clk, char *ctime_buf)
{
	*clk = time(NULL);
	ctime_r(clk,ctime_buf);
	ctime_buf[24] = ':';

	return;
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

enum work_phases {
	STARTING,
	RUNNING,
	SHUTDOWN
};

enum work_phases current_phase = STARTING;

#define NUM_NAMES_MAX 3
const char *workflow_names[NUM_NAMES_MAX] = {
	"STARTING", "RUNNING", "SHUTDOWN"
};


const char *phase2str(enum work_phases phase)
{
	if (phase < WORKFLOW_NAMES_MAX)
		return workflow_names[phase];

	return NULL;
}

int str_cli(int sockfd, struct ServerBinnMsg *sThisMsg);
void fDoHpnAssessment(unsigned int val, int sockfd);

#define HPNSSH_MSG      2

//For HPNSSH_MSGs value will be whether to do a read or readall or shutdown
#define HPNSSH_READ             33
#define HPNSSH_READ_FS          133
#define HPNSSH_DUMMY            166

void fDoHpnRead(unsigned int val, int sockfd);

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

void fRead_Binn_Client_Object(struct ClientBinnMsg *pMsg, binn * obj)
{
	pMsg->msg_type = binn_object_uint32(obj, "msg_type");
	pMsg->op = binn_object_uint32(obj, "op");

	return;
}


void * doProcessHpnClientReq(void * arg)
{
	ssize_t n;
	struct ClientBinnMsg sMsg;
	char from_cli[BUFFER_SIZE_FROM_CLIENT];
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];

	int sockfd = (int)arg;
	pthread_detach(pthread_self());
	current_phase = RUNNING;
	srand(time(0));

	for ( ; ; )
	{
		if ( (n = Readn(sockfd, from_cli, sizeof(from_cli))) == 0)
		{
			if (vDebugLevel > 0)
			{
				fprintf(pHpnServerLogPtr,"\n%s %s: ***Hpn Client Connection closed***\n", ms_ctime_buf, phase2str(current_phase));
				fflush(pHpnServerLogPtr);
			}

			Close(sockfd);
			return (NULL);         /* connection closed by other end */
		}

#if 0
		if (vDebugLevel > 1)
		{
			fprintf(pHpnServerLogPtr,"\n%s %s: ***num bytes read from Hpn Client = %lu***\n", ms_ctime_buf, phase2str(current_phase),n);
			fflush(pHpnServerLogPtr);
		}
#endif
		fRead_Binn_Client_Object(&sMsg, (binn *)&from_cli);
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
                
		if (sMsg.msg_type == HPNSSH_MSG)
		{
			if (vDebugLevel > 1)
			{
				fprintf(pHpnServerLogPtr,"\n%s %s: ***Received Hpnssh message from Hpnssh Client...***\n", ms_ctime_buf, phase2str(current_phase));
				fprintf(pHpnServerLogPtr,"%s %s: ***msg type = %d, msg op = %u\n", ms_ctime_buf, phase2str(current_phase), sMsg.msg_type, sMsg.op);
			}

			fDoHpnAssessment(sMsg.op, sockfd);
		}
		else
			if (vDebugLevel > 0)
			{
				fprintf(pHpnServerLogPtr,"\n%s %s: ***Received unknown message from some Hpn client???...***\n", ms_ctime_buf, phase2str(current_phase));
				fprintf(pHpnServerLogPtr,"%s %s: ***msg_type = %d", ms_ctime_buf, phase2str(current_phase), sMsg.msg_type);
			}

		fflush(pHpnServerLogPtr);
	}

}

void fMake_Binn_Server_Object(struct ServerBinnMsg *pMsg, binn * obj)
{
	binn_object_set_blob(obj, "Msg", pMsg, sizeof(struct ServerBinnMsg));

	return;
}

void fDoHpnRead(unsigned int val, int sockfd)
{
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	struct ServerBinnMsg sRetMsg;

	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
	if (vDebugLevel > 2)
		fprintf(pHpnServerLogPtr,"%s %s: ***INFO***: In fDoHpnRead(), value is %u***\n", ms_ctime_buf, phase2str(current_phase), val);

	//BINN objects are cross platform - no need for big endian, little endian worries 
	sRetMsg.msg_type = HPNSSH_MSG;
	sRetMsg.op = HPNSSH_READ_FS;

	memcpy(sRetMsg.timestamp, ms_ctime_buf, MS_CTIME_BUF_LEN);
	sRetMsg.hop_latency = rand() % 10000;
	sRetMsg.queue_occupancy = rand() % 10000;;
	sRetMsg.switch_id = rand() % 10;
	
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
		default:
			gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
			fprintf(pHpnServerLogPtr,"%s %s: ***WARNING***: Invalid Hpnmessage value from client. Value is %u***\n", ms_ctime_buf, phase2str(current_phase), val);
			break;
	}

	return;
}
	
void * doHandleHpnsshQfactorEnv(void * vargp)
{
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	int listenfd, connfd;
	pthread_t tid;
	socklen_t clilen;
	struct sockaddr_in cliaddr, servaddr;
	struct sockaddr_in peeraddr;
	socklen_t peeraddrlen;
	struct sockaddr_in localaddr;
	socklen_t localaddrlen;

	peeraddrlen = sizeof(peeraddr);
	localaddrlen = sizeof(localaddr);
	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
	
	fprintf(pHpnServerLogPtr,"%s %s: ***Starting Listener for receiving messages from HPNSSH...***\n", ms_ctime_buf, phase2str(current_phase));
	fflush(pHpnServerLogPtr);

	listenfd = Socket(AF_INET, SOCK_STREAM, 0);

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family      = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port        = htons(vPort);

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
	
		fprintf(pHpnServerLogPtr,"%s %s: ***Accepted connection with Listener for receiving messages from HPNSSH...***\n", ms_ctime_buf, phase2str(current_phase));
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);

		int retval = getpeername(connfd, (struct sockaddr *) &peeraddr, &peeraddrlen);
		if (retval == -1)
		{
			fprintf(pHpnServerLogPtr,"%s %s: ***Peer error:***\n", ms_ctime_buf, phase2str(current_phase));
		}
		else
			{
				char *peeraddrpresn = inet_ntoa(peeraddr.sin_addr);
				if (vDebugLevel > 3)
				{
					fprintf(pHpnServerLogPtr,"%s %s: ***Peer information:\n", ms_ctime_buf, phase2str(current_phase));
					fprintf(pHpnServerLogPtr,"%s %s: ***Peer Address Family: %d\n", ms_ctime_buf, phase2str(current_phase), peeraddr.sin_family);
					fprintf(pHpnServerLogPtr,"%s %s: ***Peer Port: %d\n", ms_ctime_buf, phase2str(current_phase), peeraddr.sin_port);
					fprintf(pHpnServerLogPtr,"%s %s: ***Peer IP Address: %s***\n\n", ms_ctime_buf, phase2str(current_phase), peeraddrpresn);
				}
			}

		retval = getsockname(connfd, (struct sockaddr *) &localaddr, &localaddrlen);
		if (retval == -1)
		{
			fprintf(pHpnServerLogPtr,"%s %s: ***sock error:***\n", ms_ctime_buf, phase2str(current_phase));
		}
		else
			{
				char *localaddrpresn = inet_ntoa(localaddr.sin_addr);

				if (vDebugLevel > 3)
				{
					fprintf(pHpnServerLogPtr,"%s %s: ***Socket information:\n", ms_ctime_buf, phase2str(current_phase));
					fprintf(pHpnServerLogPtr,"%s %s: ***Local Address Family: %d\n", ms_ctime_buf, phase2str(current_phase), localaddr.sin_family);
					fprintf(pHpnServerLogPtr,"%s %s: ***Local Port: %d\n", ms_ctime_buf, phase2str(current_phase), ntohs(localaddr.sin_port));
					fprintf(pHpnServerLogPtr,"%s %s: ***Local IP Address: %s***\n\n", ms_ctime_buf, phase2str(current_phase), localaddrpresn);
				}
			}

		fflush(pHpnServerLogPtr);
                
		pthread_create(&tid, NULL, &doProcessHpnClientReq, (void *) connfd);
	}

	return ((char *)0);
}

int Writen(int fd, void *ptr, size_t nbytes)
{
	if (writen(fd, ptr, nbytes) != nbytes)
	{
		if (errno == EPIPE)
			return(1);
		else
			{
				printf("writen error\n");
				return 1;
			}
	}

	return 0;
}

void Inet_pton(int family, const char *strptr, void *addrptr)
{
	int             n;

	if ( (n = inet_pton(family, strptr, addrptr)) < 0)
		printf("inet_pton error for %s", strptr);      /* errno set */
	else 
		if (n == 0)
		{
			printf("inet_pton error for %s", strptr);     /* errno not set */
			exit(1);
		}
	return;
}

void Bind(int fd, const struct sockaddr *sa, socklen_t salen)
{
	if (bind(fd, sa, salen) < 0)
		printf("bind error\n");

	return;
}

void sig_int_handler(int signum, siginfo_t *info, void *ptr)
{
	fprintf(pHpnServerLogPtr,"Caught SIGINT, exiting...\n");
	fflush(pHpnServerLogPtr);
	printf("Caught SIGINT, Shutting down server and exiting...\n");

	vShutdown = 1;
	exit(1);
}

void catch_sigint()
{
	static struct sigaction _sigact;

	memset(&_sigact, 0, sizeof(_sigact));
	_sigact.sa_sigaction = sig_int_handler;
	_sigact.sa_flags = SA_SIGINFO;

	sigaction(SIGINT, &_sigact, NULL);
}

#define DEBUGLEVELMAX	4
void sig_usr1_handler(int signum, siginfo_t *info, void *ptr)
{
	fprintf(pHpnServerLogPtr,"Caught SIGUSR1...\n");
	fprintf(pHpnServerLogPtr,"Debug Level is currently %d...\n",vDebugLevel);
	if (vDebugLevel < DEBUGLEVELMAX)
		vDebugLevel++;
	else
		vDebugLevel = 0;

	fprintf(pHpnServerLogPtr,"Debug Level is now %d...\n",vDebugLevel);
	fflush(pHpnServerLogPtr);
	return;
}

void catch_sigusr1()
{
	static struct sigaction _sigact;

	memset(&_sigact, 0, sizeof(_sigact));
	_sigact.sa_sigaction = sig_usr1_handler;
	_sigact.sa_flags = SA_SIGINFO;

	sigaction(SIGUSR1, &_sigact, NULL);
}

int str_cli(int sockfd, struct ServerBinnMsg *sThisMsg) //str_cli09
{
	int y;
        
	binn *myobj = binn_object();
	fMake_Binn_Server_Object(sThisMsg, myobj);
#if 0
	fprintf(pHpnServerLogPtr,"***!!!!!!!Size of binn object = %u...***\n", binn_size(myobj));
	fflush(pHpnServerLogPtr);
#endif
	y = Writen(sockfd, binn_ptr(myobj), binn_size(myobj));
	binn_free(myobj);
	return y;
}

int main(int argc, char *argv[])
{
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	char aLogFile[256];
	sArgv_t sArgv;

	sArgv.argc = argc;
	sArgv.argv = argv;

	int vRetFromHandleHpnsshQfactorEnvThread, vRetFromHandleHpnsshQfactorEnvJoin;
	pthread_t doHandleHpnsshQfactorEnvThread_id;

	sprintf(aLogFile,"/tmp/hpnServerLog");
	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);

	pHpnServerLogPtr = fopen(aLogFile,"w");
	if (!pHpnServerLogPtr)
	{
		printf("%s %s: ***Couldn't open HPN Server log for testing, exiting...\n", ms_ctime_buf, phase2str(current_phase));
		exit(1);
	}

	catch_sigint();
	catch_sigusr1();

	vRetFromHandleHpnsshQfactorEnvThread = pthread_create(&doHandleHpnsshQfactorEnvThread_id, NULL, doHandleHpnsshQfactorEnv, &sArgv);

	fprintf(pHpnServerLogPtr,"%s %s: ***Starting simulated HPN-QFACTOR server...***\n", ms_ctime_buf, phase2str(current_phase));
	if (argc == 3 && ((strcmp(argv[1],"-p") == 0)))
	{
		if (strcmp(argv[1],"-p") == 0)
			vPort = atoi(argv[2]);
	}

	fprintf(pHpnServerLogPtr,"%s %s: ***Starting simulated HPN-QFACTOR server, listening on port %d*\n", ms_ctime_buf, phase2str(current_phase), vPort);
	fflush(pHpnServerLogPtr);

	if (vRetFromHandleHpnsshQfactorEnvThread == 0)
		vRetFromHandleHpnsshQfactorEnvJoin = pthread_join(doHandleHpnsshQfactorEnvThread_id, NULL);

	return 0;
}
