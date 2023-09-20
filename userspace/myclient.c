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
#include <pthread.h>
#include <sys/prctl.h>
#include <signal.h>
#include <sys/wait.h>

#include <linux/bpf.h>
#include <arpa/inet.h>
#include <sys/ipc.h>

#include "unp.h"
#include "user_dtn.h"

#ifdef HPNSSH_QFACTOR_BINN
#undef HPNSSH_QFACTOR_BINN
#endif

struct PeerMsg sHpnRetMsg;
unsigned int hpnRetMsgSeqNo = 0;
struct PeerMsg hpnMsg;
unsigned int hpnMsgSeqNo = 0;
struct PeerMsg sMsg;
unsigned int sMsgSeqNo = 0;
int vPort = 5525; //default listening port
int vShutdown = 0;
enum workflow_phases current_phase = STARTING;

const char *workflow_names[WORKFLOW_NAMES_MAX] = {
	"STARTING",
"ASSESSMENT",
"LEARNING",
"TUNING",
};

const char *phase2str(enum workflow_phases phase)
{
	if (phase < WORKFLOW_NAMES_MAX)
		return workflow_names[phase];
return NULL;
}


int vDebugLevel = 1;

FILE * pHpnClientLogPtr = 0;

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


#define SIGINT_MSG "SIGINT received.\n"
void sig_int_handler(int signum, siginfo_t *info, void *ptr)
{
	//write(STDERR_FILENO, SIGINT_MSG, sizeof(SIGINT_MSG));
	fprintf(pHpnClientLogPtr,"Caught SIGINT, exiting...\n");
	fflush(pHpnClientLogPtr);
	printf("Caught SIGINT, Shutting down client and exiting...\n");

	vShutdown = 1;
}

void catch_sigint()
{
	static struct sigaction _sigact;

	memset(&_sigact, 0, sizeof(_sigact));
	_sigact.sa_sigaction = sig_int_handler;
	_sigact.sa_flags = SA_SIGINFO;

	sigaction(SIGINT, &_sigact, NULL);
}

#define DEBUGLEVELMAX	3
void sig_usr1_handler(int signum, siginfo_t *info, void *ptr)
{
	//write(STDERR_FILENO, SIGINT_MSG, sizeof(SIGINT_MSG));
	fprintf(pHpnClientLogPtr,"Caught SIGUSR1...\n");
	fprintf(pHpnClientLogPtr,"Debug Level is currently %d...\n",vDebugLevel);
	if (vDebugLevel < DEBUGLEVELMAX)
		vDebugLevel++;
	else
		vDebugLevel = 0;

	fprintf(pHpnClientLogPtr,"Debug Level is now %d...\n",vDebugLevel);
	fflush(pHpnClientLogPtr);
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


ssize_t                                         /* Read "n" bytes from a descriptor. */
readn(int fd, void *vptr, size_t n)
{
	size_t  nleft;
	ssize_t nread;
	char    *ptr;

	ptr = vptr;
	nleft = n;
	while (nleft > 0) 
	{
		if ( (nread = read(fd, ptr, nleft)) < 0) 
		{
			if (errno == EINTR)
			{ 	if (vShutdown) //shutdown requested
					return (-1);
				else
                            		nread = 0;              /* and call read() again */
			}
		else
			return(-1);
		} 
		else 
			if (nread == 0)
				break;	/* EOF */

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
	{
		if (vShutdown)
			fprintf(pHpnClientLogPtr,"***INFO*** WARNING!!!!: Shutdown of Client requested*****\n");
		else	
			err_sys("readn error");
	}
return(n);
}

void fDoHpnReadFS(unsigned int val, int sockfd, struct PeerMsg *from_server);
void fDoHpnReadAllFS(unsigned int val, int sockfd, struct PeerMsg *from_server);
void fDoHpnShutdownFS(unsigned int val, int sockfd);
void fDoHpnStartFS(unsigned int val, int sockfd);
void fDoHpnTimeoutFS(unsigned int val, int sockfd, struct PeerMsg *from_server);
void fDoHpnFromserver(unsigned int val, int sockfd, struct PeerMsg *from_server);


void fDoHpnTimeoutFS(unsigned int val, int sockfd, struct PeerMsg *from_server)
{
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];

	if (vDebugLevel > 0)
	{
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(pHpnClientLogPtr,"%s %s: ***INFO***: In fDoHpnTimeoutFS(), value is %u***\n", ms_ctime_buf, phase2str(current_phase), val);
	}

	if (vDebugLevel > 1)
	{
		fprintf(pHpnClientLogPtr, "\n%s %s: ***********************HPN_CLIENT_TIMEOUT************************",
								from_server->timestamp, phase2str(current_phase));
		fprintf(pHpnClientLogPtr, "\n%s %s: HPN_CLIENT    : hop_switch_id = %u\n",
								from_server->timestamp, phase2str(current_phase), ntohl(from_server->switch_id));
		fprintf(pHpnClientLogPtr, "%s %s: HPN_CLIENT    : queue_occupancy = %u\n",
								from_server->timestamp, phase2str(current_phase), ntohl(from_server->queue_occupancy));
		fprintf(pHpnClientLogPtr, "%s %s: HPN_CLIENT    : hop_latency = %u\n",
								from_server->timestamp, phase2str(current_phase), ntohl(from_server->hop_latency));
	}
return;
}

void fDoHpnReadFS(unsigned int val, int sockfd, struct PeerMsg *from_server)
{
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];

	if (vDebugLevel > 0)
	{
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(pHpnClientLogPtr,"\n%s %s: ***INFO***: In fDoHpnReadFS(), value is %u***", ms_ctime_buf, phase2str(current_phase), val);

		fprintf(pHpnClientLogPtr, "\n%s %s: ***********************HPN_CLIENT************************",
								from_server->timestamp, phase2str(current_phase));
		fprintf(pHpnClientLogPtr, "\n%s %s: HPN_CLIENT    : hop_switch_id = %u\n",
								from_server->timestamp, phase2str(current_phase), ntohl(from_server->switch_id));
		fprintf(pHpnClientLogPtr, "%s %s: HPN_CLIENT    : queue_occupancy = %u\n",
								from_server->timestamp, phase2str(current_phase), ntohl(from_server->queue_occupancy));
		fprintf(pHpnClientLogPtr, "%s %s: HPN_CLIENT    : hop_latency = %u\n",
								from_server->timestamp, phase2str(current_phase), ntohl(from_server->hop_latency));
	}
return;
}

void fDoHpnReadAllFS(unsigned int val, int sockfd, struct PeerMsg *from_server)
{
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];

	if (vDebugLevel > 1)
	{
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(pHpnClientLogPtr,"\n%s %s: ***INFO***: In fDoHpnReadAllFS(), value is %u***", ms_ctime_buf, phase2str(current_phase), val);
	}

	if (vDebugLevel > 0)
	{
		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		fprintf(pHpnClientLogPtr, "\n%s %s: ***********************HPN_CLIENT************************",
								from_server->timestamp, phase2str(current_phase));
		fprintf(pHpnClientLogPtr, "\n%s %s: HPN_CLIENT    : hop_switch_id = %u\n",
								from_server->timestamp, phase2str(current_phase), ntohl(from_server->switch_id));
		fprintf(pHpnClientLogPtr, "%s %s: HPN_CLIENT    : queue_occupancy = %u\n",
								from_server->timestamp, phase2str(current_phase), ntohl(from_server->queue_occupancy));
		fprintf(pHpnClientLogPtr, "%s %s: HPN_CLIENT    : hop_latency = %u\n",
								from_server->timestamp, phase2str(current_phase), ntohl(from_server->hop_latency));
	}
return;
}


void fDoHpnFromServer(unsigned int val, int sockfd, struct PeerMsg *from_server)
{
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];

	switch (val) {
		case 133:
			fDoHpnReadFS(val, sockfd, from_server);
			break;
		//case HPNSSH_SHUTDOWN:
		//      fDoHpnShutdownFS(val, sockfd);
		//      break;
		case 144:
			fDoHpnReadAllFS(val, sockfd, from_server);
			break;
		case 199:
			//fDoHpnStartFS(val, sockfd);
			break;
		case  166:
			fDoHpnTimeoutFS(val, sockfd, from_server);
			break;
		default:
			gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
			fprintf(pHpnClientLogPtr,"%s %s: ***WARNING***: Invalid Hpnmessage value from client. Value is %u***\n", ms_ctime_buf, phase2str(current_phase), val);
			break;
	}

return;
}

void process_request_fs2(int sockfd)
{
	ssize_t n;
	struct PeerMsg from_cli;
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];

	for ( ; ; )
	{
		if ( (n = Readn(sockfd, &from_cli, sizeof(from_cli))) == 0)
		{
			if (vDebugLevel > 0)
			{
				fprintf(pHpnClientLogPtr,"\n%s %s: ***Connection 1 closed***\n", ms_ctime_buf, phase2str(current_phase));
				fflush(pHpnClientLogPtr);
			}

			return;         /* connection closed by other end */
		}
		else
			{
				if (vShutdown)
					return;
			}

		gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
		if (ntohl(from_cli.msg_no) == HPNSSH_MSG)
		{
			if (vDebugLevel > 2)
                	{
                		fprintf(pHpnClientLogPtr,"\n%s %s: ***Received Hpnssh message %u from Hpnssh Server...***\n", 
										ms_ctime_buf, phase2str(current_phase), ntohl(from_cli.seq_no));
                       		 fprintf(pHpnClientLogPtr,"%s %s: ***msg_no = %d, msg value = %u, msg buf = %s", 
						ms_ctime_buf, phase2str(current_phase), ntohl(from_cli.msg_no), ntohl(from_cli.value), from_cli.msg);
			}

			fDoHpnFromServer(ntohl(from_cli.value), sockfd, &from_cli);
		}
		else
			{
				fprintf(pHpnClientLogPtr,"\n%s %s: ***Received Invalid message %u from Hpnssh Server...***\n", 
									ms_ctime_buf, phase2str(current_phase), ntohl(from_cli.seq_no));
				fprintf(pHpnClientLogPtr,"%s %s: ***msg_no = %d, msg buf = %s", 
								ms_ctime_buf, phase2str(current_phase), ntohl(from_cli.msg_no), from_cli.msg);
			}
		
		fflush(pHpnClientLogPtr);
	}
}

int process_request_fs(int sockfd)
{
	ssize_t n;
	struct PeerMsg from_cli;
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];

	if ( (n = Readn(sockfd, &from_cli, sizeof(from_cli))) == 0)
	{
		if (vDebugLevel > 0)
		{
			fprintf(pHpnClientLogPtr,"\n%s %s: ***Connection from HpnQfactor Server closed***\n", ms_ctime_buf, phase2str(current_phase));
			fflush(pHpnClientLogPtr);
		}
		return 0;         /* connection closed by other end */
	}
	else
		{
			if (vShutdown)
 				return 0;
		}

	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);
	if (ntohl(from_cli.msg_no) == HPNSSH_MSG)
	{
		if (vDebugLevel > 2)
		{
			fprintf(pHpnClientLogPtr,"\n%s %s: ***Received Hpnssh message %u from Hpnssh Server...***\n", ms_ctime_buf, phase2str(current_phase), ntohl(from_cli.seq_no));
			fprintf(pHpnClientLogPtr,"%s %s: ***msg_no = %d, msg value = %u, msg buf = %s", ms_ctime_buf, phase2str(current_phase), ntohl(from_cli.msg_no), ntohl(from_cli.value), from_cli.msg);
		}

		fDoHpnFromServer(ntohl(from_cli.value), sockfd, &from_cli);
	}
	else
		{
			fprintf(pHpnClientLogPtr,"\n%s %s: ***Received Invalid message %u from Hpnssh Server...***\n", ms_ctime_buf, phase2str(current_phase), ntohl(from_cli.seq_no));
			fprintf(pHpnClientLogPtr,"%s %s: ***msg_no = %d, msg buf = %s", ms_ctime_buf, phase2str(current_phase), ntohl(from_cli.msg_no), from_cli.msg);
		}

	fflush(pHpnClientLogPtr);

return (ntohl(from_cli.value));
}

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

void read_sock(int sockfd)
{
	ssize_t                 n;
	struct PeerMsg             from_cli;

	for ( ; ; )
	{
		if ( (n = Readn(sockfd, &from_cli, sizeof(from_cli))) == 0)
 			return;         /* connection closed by other end */
	}
}

int str_cli(int sockfd, struct PeerMsg *sThisMsg) //str_cli09
{
	Writen(sockfd, sThisMsg, sizeof(struct PeerMsg));
return 0;
}

int main(int argc, char *argv[])
{
	time_t clk;
	char ctime_buf[27];
	char ms_ctime_buf[MS_CTIME_BUF_LEN];
	int sockfd;
	struct sockaddr_in servaddr;
	struct PeerMsg hpnMsg2;
	char aMySrc_Ip[32];
	//pid_t mypid;
	char aLogFile[256];

	//mypid = getpid();

	//system("rm -f /tmp/hpnClientLog.*");
	//sprintf(aLogFile,"/tmp/hpnClientLog.%u",mypid);
	sprintf(aLogFile,"/tmp/hpnClientLog");
	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);

	pHpnClientLogPtr = fopen(aLogFile,"w");
	if (!pHpnClientLogPtr)
	{
		printf("%s %s: ***Couldn't open HPN Client log for testing, exiting...\n", ms_ctime_buf, phase2str(current_phase));
		exit(1);
	}

	fprintf(pHpnClientLogPtr,"%s %s: ***Starting Client for testing with HPN-QFACTOR server...***\n", ms_ctime_buf, phase2str(current_phase));
	sprintf(aMySrc_Ip,"127.0.0.1");
	if (argc > 1 && argc < 6) //5 args max
	{
		if (argc == 3 && ((strcmp(argv[1],"-p") == 0) || 
				  (strcmp(argv[1],"-d") == 0)))
		{
			if (strcmp(argv[1],"-d") == 0)
				sprintf(aMySrc_Ip, argv[2]);
			if (strcmp(argv[1],"-p") == 0)
				vPort = atoi(argv[2]);
		}
		else
			if (argc == 5 && (((strcmp(argv[3],"-p") == 0) || (strcmp(argv[3],"-d") == 0)) || 
					  ((strcmp(argv[3],"-d") == 0) || (strcmp(argv[3],"-p") == 0))))
			{

				//do nothing yet
			}
	}

	fprintf(pHpnClientLogPtr,"%s %s: ***Connecting to HPNSSN-QFACTOR Server %s, using port %d...***\n", 
							ms_ctime_buf, phase2str(current_phase), aMySrc_Ip, vPort);
	fflush(pHpnClientLogPtr);

	catch_sigint();
	catch_sigusr1();

	memset(&hpnMsg2,0,sizeof(hpnMsg2));
	hpnMsg2.value  = HPNSSH_START;


cli_again:
	gettimeWithMilli(&clk, ctime_buf, ms_ctime_buf);

	hpnMsg2.msg_no = htonl(HPNSSH_MSG);
	hpnMsgSeqNo++;
	hpnMsg2.seq_no = htonl(hpnMsgSeqNo);	
	strcpy(hpnMsg2.msg,"This is a START message");

	switch (hpnMsg2.value) {
		case  HPNSSH_START: //connect
			if (vDebugLevel > 0)
			{
				fprintf(pHpnClientLogPtr,"%s %s: ***Sending START message to HPNSSN_QFACTOR server, seqno = %u...***\n", 
											ms_ctime_buf, phase2str(current_phase), hpnMsgSeqNo);
				fflush(pHpnClientLogPtr);
			}

			hpnMsg2.value = htonl(hpnMsg2.value);
		
			sockfd = Socket(AF_INET, SOCK_STREAM, 0);
			bzero(&servaddr, sizeof(servaddr));
			servaddr.sin_family = AF_INET;
			servaddr.sin_port = htons(vPort);

			Inet_pton(AF_INET, aMySrc_Ip, &servaddr.sin_addr);

			if (Connect(sockfd, (SA *) &servaddr, sizeof(servaddr)))
			{
				goto cli_again;
			}
		
			str_cli(sockfd, &hpnMsg2);       

			if (vDebugLevel > 1)
			{
				fprintf(pHpnClientLogPtr,"%s %s: ***Finish sending START message to HPNSSN_QFACTOR server, seqno = %u...***\n", 
												ms_ctime_buf, phase2str(current_phase), hpnMsgSeqNo);
				fflush(pHpnClientLogPtr);
			}

			process_request_fs(sockfd);
			hpnMsg2.value = HPNSSH_READALL; //next state
			current_phase = LEARNING;
			break;

		case HPNSSH_SHUTDOWN:
			fprintf(pHpnClientLogPtr,"%s %s: ***Shutting down this client...***\n", ms_ctime_buf, phase2str(current_phase));
			fflush(pHpnClientLogPtr);
			Close(sockfd);
			exit(0);
			break;
	
		case HPNSSH_READ:		
			if (vDebugLevel > 1)
			{
				fprintf(pHpnClientLogPtr,"%s %s: ***Sending READ message to HPNSSN_QFACTOR server, seqno = %u...***\n", 
											ms_ctime_buf, phase2str(current_phase), hpnMsgSeqNo);
				fflush(pHpnClientLogPtr);
			}

			hpnMsg2.value = htonl(hpnMsg2.value);
			str_cli(sockfd, &hpnMsg2);        
				
			if (vDebugLevel > 1)
			{
				fprintf(pHpnClientLogPtr,"%s %s: ***Finished sending READ message to HPNSSN_QFACTOR server, seqno = %u...***\n", 
												ms_ctime_buf, phase2str(current_phase), hpnMsgSeqNo);
				fflush(pHpnClientLogPtr);
			}

			process_request_fs(sockfd);
				
			if (vShutdown)
			{
				hpnMsg2.value = HPNSSH_SHUTDOWN;
				vShutdown = 0;
			}
			else
				hpnMsg2.value = HPNSSH_READ;
			break;
		
		case HPNSSH_READALL:		
			if (vDebugLevel > 1)
			{
				fprintf(pHpnClientLogPtr,"%s %s: ***Sending READALL message to HPNSSN_QFACTOR server, seqno = %u...***\n", 
											ms_ctime_buf, phase2str(current_phase), hpnMsgSeqNo);
				fflush(pHpnClientLogPtr);
			}

			hpnMsg2.value = htonl(hpnMsg2.value);
			strcpy(hpnMsg2.msg,"This is a READALL message");
			str_cli(sockfd, &hpnMsg2);        
				
			if (vDebugLevel > 1)
			{
				fprintf(pHpnClientLogPtr,"%s %s: ***Finished sending READALL message to HPNSSN_QFACTOR server, seqno = %u...***\n", 
												ms_ctime_buf, phase2str(current_phase), hpnMsgSeqNo);
				fflush(pHpnClientLogPtr);
			}

			process_request_fs2(sockfd);
				
			if (vShutdown)
			{
				hpnMsg2.value = HPNSSH_SHUTDOWN;
				vShutdown = 0;
			}
			else
				hpnMsg2.value = HPNSSH_READALL;
			break;
			
			default:
				fprintf(pHpnClientLogPtr,"%s %s: ***Invalid hpnMsg2 value %d...***\n", ms_ctime_buf, phase2str(current_phase), hpnMsg2.value);
				fflush(pHpnClientLogPtr);
				exit(1);
				break;
	}

	goto cli_again;

return 0;
}

