#include "fio_cli.h"
#include "http.h"

static void on_response(http_s *h);

static char * Usage = "This is an HTTP client to talk to Tuning Module. \
		       \nUse \"tuncli -t\" to apply tunings that were recommended during assessment phase. \
		       \nUse \"tuncli -l on\" to turn learning mode on (default). \
		       \nUse \"tuncli -l off\" to turn learning mode off. \
		       \nUse \"tuncli -pc\" to provide counters of activities performed per flow. \
		       \nUse \"tuncli -b rx [value]\" to change RX ring buffer size of the NIC. \
		       \nUse \"tuncli -b tx [value]\" to change TX ring buffer size of the NIC. \
		       \nUse \"tuncli -b sock_rx_buff [value]\" to change the maximum OS receive buffer size for all types of connections. \
		       \nUse \"tuncli -b sock_tx_buff [value]\" to change the maximum OS send buffer size for all types of connections. \
		       \nUse \"tuncli -d [value]\" to change the debug value of the Tuning Module. Values range from 0 to 10. \
		       \nUse \"tuncli -r [value]\" to use retransmission rate in adjusting pacing. 0 (don't use), 1 (use). \
		       \nUse \"tuncli -ct hop_late [value]\" to change the value of the hop latency delta. \
		       \nUse \"tuncli -ct flow_late [value]\" to change the value of the flow latency delta. \
		       \nUse \"tuncli -ct q_occ [value]\" to change the value of the queue occupancy delta. \
		       \nUse \"tuncli -ct flow_sink [value]\" to change the value of the flow sink time delta. \
		       \nUse \"tuncli -ct retrans_rate [value]\" to change maximum retransmission rate allowed.\
		       \nUse \"tuncli -ct pacing_rate [value]\" to change pacing rate to use. This is a percentage value.\
		       \nUse \"tuncli -rtt thresh [value]\" to change the value of the rtt threshold. \
		       \nUse \"tuncli -rtt factor [value]\" to change the value of the rtt factor.\n";

		      
//Was using thisin there. Took out for now
/* \nUse \"tuncli -ct q_user_occ [value]\" to change the value of what Qinfo should check to send msg to peer. \ */
int main(int argc, const char *argv[]) 
{
	int argc_try = 2;
	char *localaddr = "http://127.0.0.1";
	char aTmp[512];
	char aSecondPart[128];
	char aListenPort[32];
	char *gAPI_listen_port = "5523"; //default
	char *pAPI_listen_port_name = "API_listen_port";
	const char * argv_try[2];
	char *pUserCfgFile = "user_config.txt";
	FILE *userCfgPtr = 0;
	int found = 0;
	char *line = NULL;
	size_t len = 0;
	ssize_t nread;
	char *p = 0;
	char setting[256];

	if (argc < 2 || argc > 4)
		goto leave;

	if (((strcmp(argv[1],"-t") == 0) || (strcmp(argv[1], "-pc") == 0)) && argc == 2)
	{
		strcpy(aSecondPart,argv[1]);
		goto carry_on;
	}
	else
		if (((strcmp(argv[1],"-b") == 0) || (strcmp(argv[1],"-ct") == 0) || (strcmp(argv[1],"-rtt") == 0)) && argc == 4)
		{
			sprintf(aSecondPart,"%s#%s#%s",argv[1], argv[2],argv[3]);
			goto carry_on;
		}
		else
			if (argc == 3)
			{
				if (strcmp(argv[1],"-d") == 0)
				{
					if (isdigit(*argv[2]))
			//		if ((strcmp(argv[2],"0") == 0) || (strcmp(argv[2],"1") == 0) || (strcmp(argv[2],"2") == 0) || (strcmp(argv[2],"3") == 0) || (strcmp(argv[2],"4") == 0))
					{
						sprintf(aSecondPart,"%s#%s",argv[1], argv[2]);
						goto carry_on;
					}
				}
				else
					if (strcmp(argv[1],"-r") == 0)
					{
						if (isdigit(*argv[2]))
						{
							sprintf(aSecondPart,"%s#%s",argv[1], argv[2]);
							goto carry_on;
						}
					}
					else
						if (strcmp(argv[1],"-l") == 0)
						{
							if ((strcmp(argv[2],"on") == 0) || (strcmp(argv[2],"off") == 0))
							{
								sprintf(aSecondPart,"%s#%s",argv[1], argv[2]);
								goto carry_on;
							}
						}
				/* fall thru */
			}
	
	goto leave;

carry_on:	
	userCfgPtr = fopen(pUserCfgFile,"r");
	if (!userCfgPtr)
	{
		int save_errno = errno;
		printf("\n***ERROR : Opening of %s failed, errno = %d\n", pUserCfgFile, save_errno);
		printf("\n***Exiting...\n");
                return -1;
        }

	while ((nread = getline(&line, &len, userCfgPtr)) != -1)
	{
		int ind = 0;
		memset(setting,0,sizeof(setting));
		p = line;
		while (!isblank((int)p[ind]))
		{
			setting[ind] = p[ind];
			ind++;
		}

		/* compare with known item in list now */
		if (strcmp(pAPI_listen_port_name, setting) == 0) //found
		{
			int y = 0;
			memset(setting,0,sizeof(setting));
			while (isblank((int)p[ind])) //get past blanks etc
				ind++;

			setting[y++] = p[ind++];

			while (isalnum((int)p[ind]))
			{
				setting[y++] = p[ind++]; 
			}

			strcpy(aListenPort, setting);
			found = 1;
			break;
		}
	}

	if (!found)
		strcpy(aListenPort,gAPI_listen_port);

	//sprintf(aTmp,"%s:%s/%s",localaddr,aListenPort,argv[1]);
	sprintf(aTmp,"%s:%s/",localaddr,aListenPort);
	strcat(aTmp,aSecondPart);
	/* a hack so I could use 127.0.0.1 */
	argv_try[0] = "tuncli";
	argv_try[1] = aTmp;

	fio_cli_start(
		argc_try, argv_try, 1, 1, NULL,
		//"This is an HTTP client to talk to Tuning Module, use\n"
		//"\n\ttuncli - http://example.com/foo\n",
		FIO_CLI_STRING("-unix -u Unix Socket address (has no place in url)."),
		FIO_CLI_STRING("-test -t test (has no place in url).")
	);
    
	http_connect(fio_cli_unnamed(0), fio_cli_get("-u"),
		.on_response = on_response);
	fio_start(.threads = 1);

	if (line)
		free(line);
	return 0;

leave:
	printf("%s",Usage);
	exit(-1);
}

static void on_response(http_s *h) 
{
	if (h->status_str == FIOBJ_INVALID) 
	{
		/* first response is always empty, nothing was sent yet */
		http_finish(h);
		return;
	}
  	
	/* Second response is actual response */
	FIOBJ r = http_req2str(h);
	fprintf(stderr, "%s\n", fiobj_obj2cstr(r).data);
	fio_stop();
}
