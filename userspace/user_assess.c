#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
//#include <bits/stdint-uintn.h>
#include <ctype.h>
#include <getopt.h>
#include <time.h>

#include "user_dtn.h"

#ifndef  uint32_t
typedef unsigned int uint32_t;
#endif

void fDoGetUserCfgValues(void);
int fCheckInterfaceExist();
void fDoGetDeviceCap(void);
void fDoBiosTuning(void);
void fDoNicTuning(void);
void fDoSystemtuning(void);

int gInterval = 500000; //default
int vUseEvalutaionTimerDefaultValue = 0;
int gAPI_listen_port = 5523; //default listening port
int gSource_Dtn_Port = 5524; //default listening port
int netDeviceSpeed = 0;
int numaNode = 0;
static int netDevice_rx_ring_buff_cfg_max_val = 0;
static int netDevice_tx_ring_buff_cfg_max_val = 0;

char *pUserCfgFile = "user_config.txt";
char gTuningMode = 0;
char gApplyBiosTuning = 'n';
char gApplyNicTuning = 'n';
char gApplyDefSysTuning = 'n';
char gMakeTuningPermanent = 'n';
int gMaxnum_tuning_logs = 10; //default
char *gNic_to_use = 0;
char *gNic_attach_type = 0;

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

/* Must change NUMUSERVALUES below if adding more values */
#define NUMUSERVALUES	11
#define USERVALUEMAXLENGTH	256
typedef struct {
	char aUserValues[USERVALUEMAXLENGTH];
	char default_val[32];
	char cfg_value[32];
} sUserValues_t[NUMUSERVALUES];

sUserValues_t userValues = {{"evaluation_timer", "500000", "-1"},
			{"learning_mode_only","y","-1"},
			{"API_listen_port","5523","-1"},
			{"apply_default_system_tuning","n","-1"},
			{"apply_bios_tuning","n","-1"},
			{"apply_nic_tuning","n","-1"},
			{"make_default_system_tuning_perm","n","-1"},
			{"maxnum_tuning_logs","10","-1"},
			{"source_dtn_port","5524","-1"},
			{"nic_to_use","na","-1"},
			{"nic_attach_type","xdpoffload","-1"}
			};

void fCheck_log_limit(void)
{
	FILE * logCountPtr = 0;	
	char * fTuningLogCountFile = "/tmp/tuningLog.count";
	char *line = NULL;
	size_t len = 0;
	ssize_t nread;
	char *p = 0;
	char setting[256];
	int count = 0;
	time_t clk;
	char ctime_buf[27];
    
	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"\n%s %s: Checking number of log file backups already made...\n",ctime_buf, phase2str(current_phase));
	logCountPtr = fopen(fTuningLogCountFile,"r");
	if (!logCountPtr)
	{
		int save_errno = errno;
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"\n%s %s: Opening of %s failed, errno = %d\n",ctime_buf, phase2str(current_phase), fTuningLogCountFile, save_errno);
		return;
	}

	if ((nread = getline(&line, &len, logCountPtr)) != -1) 
	{
		int ind = 0;
		int cfg_val = 0;
		memset(setting,0,sizeof(setting));
		p = line;
		while (isdigit((int)p[ind])) {
			setting[ind] = p[ind];
			ind++;
		}

		cfg_val = atoi(setting);
		if (cfg_val >= gMaxnum_tuning_logs)
		{
			fclose(logCountPtr);
			logCountPtr = 0;
			sprintf(setting,"echo 0 > %s",fTuningLogCountFile);
			system(setting);
	
			gettime(&clk, ctime_buf);
			fprintf(tunLogPtr,"%s %s ***Log files limit of %d reached. Will start over backups of tuningLog next time***\n", ctime_buf, phase2str(current_phase), gMaxnum_tuning_logs);
		}
	}
	
	if (logCountPtr)
		fclose(logCountPtr);

	free(line); //must free

return;
}

void fDoGetUserCfgValues(void)
{
	FILE * userCfgPtr = 0;	
	char *line = NULL;
	size_t len = 0;
	ssize_t nread;
	char *p = 0;
	char setting[256];
	char key[256];
	int count = 0;
	time_t clk;
	char ctime_buf[27];
	char *header[] = {"Name", "Default Value", "Configured Value"};
    
	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"\n%s %s: Opening user provided config file: *%s*\n",ctime_buf, phase2str(current_phase), pUserCfgFile);
	userCfgPtr = fopen(pUserCfgFile,"r");
	if (!userCfgPtr)
	{
		int save_errno = errno;
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"\n%s %s: Opening of %s failed, errno = %d\n",ctime_buf, phase2str(current_phase), pUserCfgFile, save_errno);
		return;
	}

	while ((nread = getline(&line, &len, userCfgPtr)) != -1) 
	{
		int ind = 0;
		memset(setting,0,sizeof(setting));
		p = line;
		while (!isblank((int)p[ind])) {
			setting[ind] = p[ind];
			ind++;
		}

		/* compare with known list now */
		for (count = 0; count < NUMUSERVALUES; count++)
		{
			if (strcmp(userValues[count].aUserValues, setting) == 0) //found
			{
				int y = 0;
				memset(key,0,sizeof(key));
				strcpy(key,setting);
				memset(setting,0,sizeof(setting));

				while (isblank((int)p[ind])) //get past blanks etc
					ind++;
					
				setting[y++] = p[ind++];

				while (isalnum((int)p[ind])) 
				{
					setting[y++] = p[ind++];
				}

				if (strcmp(key,"nic_to_use") == 0) //the value could be a hyphen
				{
					while (!isspace((int)p[ind])) 
					{
						setting[y++] = p[ind++];
					}
				}
				
				strcpy(userValues[count].cfg_value, setting);
				
				break;
			}
		}
	}

#define PAD_MAX	49
#define HEADER_PAD	45
#define CONST_PAD	12
	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"%s %s: Final user config values after using settings from %s:\n",ctime_buf, phase2str(current_phase), pUserCfgFile);
	fprintf(tunLogPtr,"%s %s: A configured value of -1 means the setting was not configured and the default value will be used.\n",ctime_buf, phase2str(current_phase));
	fprintf(tunLogPtr,"\n%s %*s %20s\n", header[0], HEADER_PAD, header[1], header[2]);
	for (count = 0; count < NUMUSERVALUES; count++) 
	{	int vPad = PAD_MAX-(strlen(userValues[count].aUserValues));
		//int vPad = PAD_MAX-(strlen(userValues[count].aUserValues) - CONST_PAD);
		fprintf(tunLogPtr,"%s %*s %20s\n",userValues[count].aUserValues, vPad, userValues[count].default_val, userValues[count].cfg_value);
		if (strcmp(userValues[count].aUserValues,"evaluation_timer") == 0)
		{
			int cfg_val = atoi(userValues[count].cfg_value);
			if (cfg_val == 0) //wasn't set properly - error
				gInterval = atoi(userValues[count].default_val);
			else 
			{
				//gInterval can't be less than 1000 microseconds
				if (cfg_val > 999)
					gInterval = cfg_val;
				else //use gInterval default - currently 500000 microsecs
					vUseEvalutaionTimerDefaultValue = 1;
			}
		}
		else
			if (strcmp(userValues[count].aUserValues,"learning_mode_only") == 0)
			{
				if (userValues[count].cfg_value[0] == 'n') 
					gTuningMode = 1;
			}
			else
				if (strcmp(userValues[count].aUserValues,"apply_default_system_tuning") == 0)
				{
					if (userValues[count].cfg_value[0] == 'y') 
						gApplyDefSysTuning = 'y';
				}
				else
					if (strcmp(userValues[count].aUserValues,"apply_bios_tuning") == 0)
					{
						if (userValues[count].cfg_value[0] == 'y')
							gApplyBiosTuning = 'y';
					}
					else
						if (strcmp(userValues[count].aUserValues,"apply_nic_tuning") == 0)
						{
							if (userValues[count].cfg_value[0] == 'y')
								gApplyNicTuning = 'y';
						}
						else
							if (strcmp(userValues[count].aUserValues,"make_default_system_tuning_perm") == 0)
							{
								if (userValues[count].cfg_value[0] == 'y') 
									gMakeTuningPermanent = 'y';
							}
							else
								if (strcmp(userValues[count].aUserValues,"API_listen_port") == 0)
								{
									int cfg_val = atoi(userValues[count].cfg_value);
									if (cfg_val == 0) //wasn't set properly - error
										gAPI_listen_port = atoi(userValues[count].default_val);
									else
										gAPI_listen_port = cfg_val;
								}
								else
									if (strcmp(userValues[count].aUserValues,"maxnum_tuning_logs") == 0)
									{
										int cfg_val = atoi(userValues[count].cfg_value);
										if (cfg_val == -1) //no value in txt file
											gMaxnum_tuning_logs = atoi(userValues[count].default_val);
										else
											gMaxnum_tuning_logs = atoi(userValues[count].cfg_value);
									}
									else
										if (strcmp(userValues[count].aUserValues,"source_dtn_port") == 0)
										{
											int cfg_val = atoi(userValues[count].cfg_value);
											if (cfg_val == 0) //wasn't set properly - error
												gSource_Dtn_Port = atoi(userValues[count].default_val);
											else
												gSource_Dtn_Port = cfg_val;
										}
										else 
											if (strcmp(userValues[count].aUserValues,"nic_to_use") == 0)
											{
												if (strcmp(userValues[count].cfg_value, "-1") == 0); //no value in text file - don't use default val
												else
												{
													gNic_to_use = userValues[count].cfg_value;
												}
											}
											else 
												if (strcmp(userValues[count].aUserValues,"nic_attach_type") == 0)
												{
													if (strcmp(userValues[count].cfg_value, "-1") == 0) //no value in text file 
														gNic_attach_type = userValues[count].default_val;
													else
														gNic_attach_type = userValues[count].cfg_value;
												}
	}

	gettime(&clk, ctime_buf);
	if (!vUseEvalutaionTimerDefaultValue)
		fprintf(tunLogPtr,"\n%s %s: ***Using 'evaluation_timer' with value %d microseconds***\n", ctime_buf, phase2str(current_phase), gInterval);
	else
		{
			fprintf(tunLogPtr,"\n%s %s: ***'evaluation_timer' cannot be set to a value less than 1000 microseconds***\n", ctime_buf, phase2str(current_phase));
			fprintf(tunLogPtr,"%s %s: ***Using 'evaluation_timer' with the default value of %d microseconds***\n", ctime_buf, phase2str(current_phase), gInterval);
		}

	free(line); //must free
	return;
}

#define bbr 		0
#define fq		1
#define htcp	 	2
#define	reno		3
#define	cubic		4
#define getvalue	5
char *aStringval[] ={"bbr", "fq", "htcp", "reno", "cubic", "getvalue"};

/* 
 * Suggestion for net.ipv4.tcp_mem...
 *
 * for tcp_mem, set it to twice the maximum value for tcp_[rw]mem multiplied by  * the maximum number of running network applications divided by 4096 bytes per  * page.
 * Increase rmem_max and wmem_max so they are at least as large as the third 
 * values of tcp_rmem and tcp_wmem.
 *
 * A minimum value of "getvalue" means that I'm just intereste in the value.
 */
#define NUM_SYSTEM_SETTINGS	100
int aApplyKernelDefTunCount = 0;
int aApplyNicDefTunCount = 0;
int aApplyBiosDefTunCount = 0;
int vModifySysctlFile = 0;
char aApplyKernelDefTun2DArray[NUM_SYSTEM_SETTINGS][MAX_SIZE_SYSTEM_SETTING_STRING];
char aApplyNicDefTun2DArray[NUM_SYSTEM_SETTINGS][MAX_SIZE_SYSTEM_SETTING_STRING];
char aApplyBiosDefTun2DArray[NUM_SYSTEM_SETTINGS][MAX_SIZE_SYSTEM_SETTING_STRING];

int my_tune_max = 0;

/* Must change TUNING_NUMS_10GandUnder if adding more to the array below in user_dtn.h*/
host_tuning_vals_t aTuningNumsToUse10GandUnder[TUNING_NUMS_10GandUnder] = {
	{"net.core.rmem_max",				67108864,          -1,      	0},
	{"net.core.wmem_max",				67108864,          -1,      	0},
	{"net.ipv4.tcp_mtu_probing",			       1,          -1,      	0},
	{"net.ipv4.tcp_available_congestion_control",	getvalue,   	   -1,		0},
	{"net.ipv4.tcp_congestion_control",	    	    htcp,	   -1,		0}, //uses #defines to help
	{"net.core.default_qdisc",			      fq, 	   -1,		0}, //uses #defines
	{"net.ipv4.tcp_rmem",				    4096,      	87380,   33554432},
	{"net.ipv4.tcp_wmem",				    4096,       65536,   33554432},
	{"MTU",						       0, 	   84, 		0} //Will leave here but not using for now
};

/* Must change TUNING_NUMS_Over10GtoUnder100G if adding more to the array below */
host_tuning_vals_t aTuningNumsToUse_Over10GtoUnder100G[TUNING_NUMS_Over10GtoUnder100G] = {
	{"net.core.rmem_max",				134217728,         -1,      	0},
	{"net.core.wmem_max",				134217728,         -1,      	0},
	{"net.ipv4.tcp_mtu_probing",			       1,          -1,      	0},
	{"net.ipv4.tcp_available_congestion_control",	getvalue,   	   -1,		0},
	{"net.ipv4.tcp_congestion_control",	    	    htcp,	   -1,		0}, //uses #defines to help
	{"net.core.default_qdisc",			      fq, 	   -1,		0}, //uses #defines
	{"net.ipv4.tcp_rmem",				    4096,      	87380,   67108864},
	{"net.ipv4.tcp_wmem",				    4096,       65536,   67108864},
	{"MTU",						       0, 	   84, 		0} //Will leave here but not using for now
};

/* Must change TUNING_NUMS_100G if adding more to the array below */
host_tuning_vals_t aTuningNumsToUse100Gb[TUNING_NUMS_100G] = {
	{"net.core.rmem_max",				2147483647,          -1,      		0},
	{"net.core.wmem_max",				2147483647,          -1,      		0},
	{"net.ipv4.tcp_mtu_probing",				 1,          -1,      		0},
	{"net.ipv4.tcp_available_congestion_control",	  getvalue,	     -1,		0},
	{"net.ipv4.tcp_congestion_control",		      htcp,	     -1,		0}, //uses #defines to help
	{"net.core.default_qdisc",				fq,	     -1,		0}, //uses #defines
	{"net.ipv4.tcp_rmem",				      4096,	  87380,       2147483647},
	{"net.ipv4.tcp_wmem",				      4096,       65536,       2147483647},
	{"net.core.netdev_max_backlog",			    250000,	     -1,		0},
	{"net.ipv4.tcp_no_metrics_save",			 1,	     -1,		0},
	{"MTU",							 0,	     84, 		0} //leave here not use for now
};

void fDoSystemTuning(void)
{

	char *line = NULL;
	size_t len = 0;
	ssize_t nread;
	char *q, *r, *p = 0;
	char setting[256];
	char value[256];
	host_tuning_vals_t  aTuningNumsToUse[TUNING_NUMS_100G]; 
	int TUNING_NUMS;
	int congestion_control_recommended_avail = 0;
	int x, count, intvalue, found = 0;
	FILE * tunDefSysCfgPtr = 0;	
	time_t clk;
	char ctime_buf[27];
	char *pFileCurrentConfigSettings = "/tmp/current_config.orig";
	char *header2[] = {"Setting", "Current Value", "Recommended Value", "Applied"};
	char aApplyDefTun[MAX_SIZE_SYSTEM_SETTING_STRING];

	gettime(&clk, ctime_buf);

	fprintf(tunLogPtr,"\n\n%s %s: ***Start of Default System Tuning***\n", ctime_buf, phase2str(current_phase));
	fprintf(tunLogPtr,"%s %s: ***------------------------------***\n", ctime_buf, phase2str(current_phase));
	if (netDeviceSpeed <= 10000) //less than or equal to 10 Gb/s
	{
		TUNING_NUMS = TUNING_NUMS_10GandUnder;
		for (x = 0; x < TUNING_NUMS; x++)
		{
			memcpy(&aTuningNumsToUse[x], &aTuningNumsToUse10GandUnder[x], sizeof(host_tuning_vals_t));
		}
		fprintf(tunLogPtr, "%s %s: Running gdv.sh - Shell script to Get current config settings***\n", ctime_buf, phase2str(current_phase));
		system("sh ./gdv.sh");
	}
	else
		if (netDeviceSpeed < 100000) //less than 100 Gb/s and greater than 10 Gb/s
		{
			TUNING_NUMS = TUNING_NUMS_Over10GtoUnder100G;
			for (x = 0; x < TUNING_NUMS; x++)
			{
				memcpy(&aTuningNumsToUse[x], &aTuningNumsToUse_Over10GtoUnder100G[x], sizeof(host_tuning_vals_t));
			}
			fprintf(tunLogPtr, "%s %s: Running gdv.sh - Shell script to Get current config settings***\n", ctime_buf, phase2str(current_phase));
			system("sh ./gdv.sh");
		}
		else
			{
				TUNING_NUMS = TUNING_NUMS_100G;
				for (x = 0; x < TUNING_NUMS; x++)
				{
					memcpy(&aTuningNumsToUse[x], &aTuningNumsToUse100Gb[x], sizeof(host_tuning_vals_t));
				}
				fprintf(tunLogPtr, "%s %s: Running gdv_100.sh - Shell script to Get current config settings***\n", ctime_buf, phase2str(current_phase));
				system("sh ./gdv_100.sh");
			}
	
	tunDefSysCfgPtr = fopen(pFileCurrentConfigSettings,"r");
	if (!tunDefSysCfgPtr)
	{
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: Could not open Tuning Module default current config file, '%s', exiting...\n", ctime_buf, phase2str(current_phase), pFileCurrentConfigSettings);
		fclose(tunLogPtr);
		exit(-2);
	}

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr, "%s %s: Tuning Module default current configuration file, '%s', opened***\n", ctime_buf, phase2str(current_phase), pFileCurrentConfigSettings);
	fprintf(tunLogPtr, "%s %s: ***NOTE - Some settings have a minimum, default and maximum values, while others only have a single value***\n", ctime_buf, phase2str(current_phase));
	fprintf(tunLogPtr, "%s %s: ***NOTE - If the recommended value is less than or equal to the current value, no changes will be made for that setting***\n\n", ctime_buf, phase2str(current_phase));

#define SETTINGS_PAD_MAX 58
#define HEADER_SETTINGS_PAD  50
	fprintf(tunLogPtr, "%s %*s %25s %20s\n", header2[0], HEADER_SETTINGS_PAD, header2[1], header2[2], header2[3]);
	fflush(tunLogPtr);

	while ((nread = getline(&line, &len, tunDefSysCfgPtr)) != -1) {
		memset(setting,0,256);
		p = line;
		q = strchr(line,' '); //search for space	
		len = (q-p) + 1;
		strncpy(setting,p,len);
		if (setting[len-1] == ' ')
			setting[--len] = 0;
		else
			setting[len] = 0;

		if (strcmp(setting, "net.ipv4.tcp_available_congestion_control") != 0) //print in this case
			fprintf(tunLogPtr,"%s",setting);

		/* compare with known list now */
		for (count = 0; count < TUNING_NUMS; count++)
		{
			memset(value,0,256);
			if (strcmp(aTuningNumsToUse[count].setting, setting) == 0) //found
			{
				int vPad = SETTINGS_PAD_MAX-(strlen(setting));
				q++;// move it up past the space
				q = strchr(q,' '); //search for next space	
				q++; // move to the beginning of 1st (maybe only) number
				r = strchr(q,'\n'); //search for newline
				len = (r-q) + 1;
				strncpy(value,q,len);
				value[--len] = 0;
	
				if(isdigit(value[0]))
				{
					intvalue = atoi(value);
					if(intvalue <= aTuningNumsToUse[count].minimum)
					{
						if (aTuningNumsToUse[count].xDefault == -1) //only one value
						{
							fprintf(tunLogPtr,"%*s", vPad, value);	
							if (intvalue == aTuningNumsToUse[count].minimum)
								fprintf(tunLogPtr,"%26d %20s\n",aTuningNumsToUse[count].minimum, "na");
							else
								{
									fprintf(tunLogPtr,"%26d %20c\n",aTuningNumsToUse[count].minimum, gApplyDefSysTuning);
							
									if (gApplyDefSysTuning == 'y')
									{
										//Apply Inital DefSys Tuning
										sprintf(aApplyDefTun,"sysctl -w %s=%d",setting,aTuningNumsToUse[count].minimum);
										system(aApplyDefTun);
										if (gMakeTuningPermanent == 'y')
										{
											if (vModifySysctlFile == 0)
											{
												sprintf(aApplyDefTun,"echo \"#Start of tuningMod modifications\" >> /etc/sysctl.conf");
												system(aApplyDefTun);
												vModifySysctlFile = 1;
											}
											sprintf(aApplyDefTun,"sysctl -w %s=%d >> /etc/sysctl.conf",setting,aTuningNumsToUse[count].minimum);
											system(aApplyDefTun);
										}
												
									}
									else
										{
											//Save in Case Operator want to apply from menu
											sprintf(aApplyDefTun,"sysctl -w %s=%d",setting,aTuningNumsToUse[count].minimum);
											memcpy(aApplyKernelDefTun2DArray[aApplyKernelDefTunCount], aApplyDefTun, strlen(aApplyDefTun));
											aApplyKernelDefTunCount++;
										}
								}
						}
						else
							{//has min, default and max values - get them...
							 //Let's parse the value stringand get the min, etc. separately
								int i, j, currmax;
								char min[256];
								char def[256];
								char max[256];
								memset(min,0,256);
								memset(def,0,256);
								memset(max,0,256);
								i = 0;
								while (isdigit(value[i]))
								{
									min[i] = value[i];
									i++;
								}

								while(!isdigit(value[i]))
									i++;
							
								j = 0;
								while (isdigit(value[i]))
								{
									def[j] = value[i];
									i++;
									j++;
								}
								
								while(!isdigit(value[i]))
									i++;

								j = 0;
								while (isdigit(value[i]))
								{
									max[j] = value[i];
									i++;
									j++;
								}
#define SETTINGS_PAD_MAX2 43
								vPad = SETTINGS_PAD_MAX2-(strlen(min) + strlen(def) + strlen(max));
								fprintf(tunLogPtr,"%*s %s %s", vPad, min, def, max);	
								currmax = atoi(max);
#define SETTINGS_PAD_MAX3 28
								{
									char strValmin[128];
									char strValdef[128];
									char strValmax[128];
									int total;
									int y = sprintf(strValmin,"%d",aTuningNumsToUse[count].minimum);
									total = y;
									y = sprintf(strValdef,"%d",aTuningNumsToUse[count].xDefault);
									total += y;
									y = sprintf(strValmax,"%d",aTuningNumsToUse[count].maximum);

									if (strcmp("net.ipv4.tcp_wmem",setting) == 0)
										my_tune_max = atoi(strValmax);

									total += y;
									vPad = SETTINGS_PAD_MAX3-total;
									if (aTuningNumsToUse[count].maximum > currmax)
									{
										fprintf(tunLogPtr,"%*s %s %s %20c\n", vPad, strValmin, strValdef, strValmax, gApplyDefSysTuning);
										if (gApplyDefSysTuning == 'y')
										{
											//Apply Inital DefSys Tuning
											sprintf(aApplyDefTun,"sysctl -w %s=\"%s %s %s\"",setting, strValmin, strValdef, strValmax);
											system(aApplyDefTun);
											if (gMakeTuningPermanent == 'y')
											{
												if (vModifySysctlFile == 0)
												{
													sprintf(aApplyDefTun,"echo \"#Start of tuningMod modifications\" >> /etc/sysctl.conf");
													system(aApplyDefTun);
													vModifySysctlFile = 1;
												}
												sprintf(aApplyDefTun,"sysctl -w %s=\"%s %s %s\" >> /etc/sysctl.conf",setting, strValmin, strValdef, strValmax);
												system(aApplyDefTun);
											}
										}
										else
											{
												//Save in Case Operator want to apply from menu
												sprintf(aApplyDefTun,"sysctl -w %s=\"%s %s %s\"",setting, strValmin, strValdef, strValmax);
												memcpy(aApplyKernelDefTun2DArray[aApplyKernelDefTunCount], aApplyDefTun, strlen(aApplyDefTun));
												aApplyKernelDefTunCount++;
											}
									}
									else
										fprintf(tunLogPtr,"%*s %s %s %20s\n", vPad, strValmin, strValdef, strValmax, "na");
								}

							}
					}
					else
						{ //intvalue > aTuningNumsToUse[count].minimum
							if (aTuningNumsToUse[count].xDefault == -1) //only one value
							{
								fprintf(tunLogPtr,"%*s", vPad, value);
								fprintf(tunLogPtr,"%26d %20s\n",aTuningNumsToUse[count].minimum, "na");
							}
							else
								{//has min, default and max values - get them...
								 //Let's parse the value stringand get the min, etc. separately
									int i, j;
									char min[256];
									char def[256];
									char max[256];
									memset(min,0,256);
									memset(def,0,256);
									memset(max,0,256);
									i = 0;
									while (isdigit(value[i]))
									{
										min[i] = value[i];
										i++;
									}

									while(!isdigit(value[i]))
									i++;

									j = 0;
									while (isdigit(value[i]))
									{
										def[j] = value[i];
										i++;
										j++;
									}

									while(!isdigit(value[i]))
                                        				i++;

                                    					j = 0;
                                    					while (isdigit(value[i]))
                                    					{
                                        					max[j] = value[i];
                                        					i++;
                                        					j++;
                                    					}
#define SETTINGS_PAD_MAX2 43
									vPad = SETTINGS_PAD_MAX2-(strlen(min) + strlen(def) + strlen(max));
									fprintf(tunLogPtr,"%*s %s %s", vPad, min, def, max);
#define SETTINGS_PAD_MAX3 28
									{
										char strValmin[128];
										char strValdef[128];
										char strValmax[128];
										int total;
										int y = sprintf(strValmin,"%d",aTuningNumsToUse[count].minimum);
										total = y;
										y = sprintf(strValdef,"%d",aTuningNumsToUse[count].xDefault);
										total += y;
										y = sprintf(strValmax,"%d",aTuningNumsToUse[count].maximum);
										total += y;
										vPad = SETTINGS_PAD_MAX3-total;
			
										fprintf(tunLogPtr,"%*s %s %s %20s\n", vPad, strValmin, strValdef, strValmax, "na");
									}
								}
						}
				}	
				else
					{ //must be a string
						if (strcmp(value, aStringval[aTuningNumsToUse[count].minimum]) != 0)
						{
#if 1
							if (strcmp(setting, "net.ipv4.tcp_available_congestion_control") == 0)
                            				{
                                				if (strstr(value,"htcp"))
                                    					congestion_control_recommended_avail = 1;

                                				break;
                            				}
#endif
							
							fprintf(tunLogPtr,"%*s", vPad, value);	

							if (strcmp(setting, "net.ipv4.tcp_congestion_control") == 0)
							{
								if (!congestion_control_recommended_avail)
								{ //try modprobe
									char modprobe_str[64];
									char *line2 = NULL;
									size_t len2 = 0;
									ssize_t nread2;
									FILE * modprobeFilePtr = 0;

									sprintf(modprobe_str,"%s","modprobe tcp_htcp > /tmp/modprobe_result 2>&1");
									system(modprobe_str);

									modprobeFilePtr = fopen("/tmp/modprobe_result", "r");	
									if (!modprobeFilePtr)
									{
										int save_errno = errno;
							       			gettime(&clk, ctime_buf);
        									fprintf(tunLogPtr,"\n%s %s: Opening of %s failed, errno = %d\n",ctime_buf, phase2str(current_phase), "/tmp/modprobe_result", save_errno);
										fprintf(tunLogPtr,"%s %s: ***Could not determine what value to set net.ipv4.tcp_congestion_control", ctime_buf, phase2str(current_phase));
										break;
									}

									nread2 = getline(&line2, &len2, modprobeFilePtr);
									fclose(modprobeFilePtr);
									system("rm -f /tmp/modprobe_result");	

									if (nread2 != -1)
									{
										fprintf(tunLogPtr,"%26s %20s\n",aStringval[aTuningNumsToUse[count].minimum], "*htcp na");
										break; //skip
									}
								}
							}

							fprintf(tunLogPtr,"%26s %20c\n",aStringval[aTuningNumsToUse[count].minimum], gApplyDefSysTuning);
							if (gApplyDefSysTuning == 'y')
							{
								//Apply Inital DefSys Tuning
								sprintf(aApplyDefTun,"sysctl -w %s=%s",setting,aStringval[aTuningNumsToUse[count].minimum]);
								system(aApplyDefTun);
								if (gMakeTuningPermanent == 'y')
								{
									if (vModifySysctlFile == 0)
									{
										sprintf(aApplyDefTun,"echo \"#Start of tuningMod modifications\" >> /etc/sysctl.conf");
										system(aApplyDefTun);
										vModifySysctlFile = 1;
									}
									sprintf(aApplyDefTun,"sysctl -w %s=%s >> /etc/sysctl.conf",setting,aStringval[aTuningNumsToUse[count].minimum]);
									system(aApplyDefTun);
								}
							}
							else
								{
									//Save in Case Operator want to apply from menu
									sprintf(aApplyDefTun,"sysctl -w %s=%s",setting,aStringval[aTuningNumsToUse[count].minimum]);
									memcpy(aApplyKernelDefTun2DArray[aApplyKernelDefTunCount], aApplyDefTun, strlen(aApplyDefTun));
									aApplyKernelDefTunCount++;
								}
						}
						else
							{
								fprintf(tunLogPtr,"%*s %25s %20s\n", vPad, value, aStringval[aTuningNumsToUse[count].minimum], "na");	
							}
					}

				found = 1;
				break;
			}
		}

		if (!found)
		{
			gettime(&clk, ctime_buf);
			fprintf(tunLogPtr,"%s %s: ERR*** Could not find the following setting **%s**\n", ctime_buf, phase2str(current_phase), setting);
		}
	}

	fprintf(tunLogPtr, "\n%s %s: ***Closing Tuning Module default system configuration file***\n", ctime_buf, phase2str(current_phase));
	fclose(tunDefSysCfgPtr);

	{
		char rem_file[512];
		sprintf(rem_file,"rm -f %s", pFileCurrentConfigSettings);
		system(rem_file);
	}

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"\n%s %s: ***End of Default System Tuning***\n", ctime_buf, phase2str(current_phase));
	fprintf(tunLogPtr,"%s %s: ***----------------------------***\n\n", ctime_buf, phase2str(current_phase));

	free(line);

	if (vModifySysctlFile)
	{
		sprintf(aApplyDefTun,"echo \"#End of tuningMod modifications\" >> /etc/sysctl.conf");
		system(aApplyDefTun);
		vModifySysctlFile = 0;
	}

	return;
}

void fDoCpuPerformance()
{
	char ctime_buf[27];
	time_t clk;
	char *line = NULL;
	size_t len = 0;
	ssize_t nread;
	struct stat sb;
	char aBiosSetting[256];
	char aBiosValue[256];
	int vPad;
	int other_way = 0;
	char * req_governor = "performance";
	FILE *biosCfgFPtr = 0;

	memset(aBiosValue,0,sizeof(aBiosValue));
	sprintf(aBiosSetting,"cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /tmp/BIOS.cfgfile 2>/dev/null");
	system(aBiosSetting);

	stat("/tmp/BIOS.cfgfile", &sb);
	if (sb.st_size == 0)
	{
		//doesn't support scaling Gov this way - could be Debian - lets try another way
		sprintf(aBiosSetting,"sudo cpupower frequency-info | grep \"The governor\" > /tmp/BIOS.cfgfile");
		system(aBiosSetting);
		
		biosCfgFPtr = fopen("/tmp/BIOS.cfgfile","r");
		while((nread = getline(&line, &len, biosCfgFPtr)) != -1)
		{
			char * g = strstr(line, "The governor");
			if (g)
			{
				int count = 0;
				g = g + strlen("The governor");
				while (!isalpha(*g)) g++;
				while (isalpha(g[count]))
				{
					aBiosValue[count] = g[count];
					count++;
				}
				other_way = 1;
				goto get_freq_other_way;
			}
		}
	}

	biosCfgFPtr = fopen("/tmp/BIOS.cfgfile","r");

get_freq_other_way:
	if (!biosCfgFPtr)
	{
		int save_errno = errno;
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: Could not open file /tmp/BIOS.cfgfile to work out CPU performance, errno = %d...\n", ctime_buf, phase2str(current_phase), save_errno);
	}
	else
		{
			while((nread = getline(&line, &len, biosCfgFPtr)) != -1)
			{ 	//getting CPU speed
				char *q = strchr(line,'\n');
				strcpy(aBiosValue,line);
				if (q)
					aBiosValue[strlen(line)-1] = 0;
			}

			vPad = SETTINGS_PAD_MAX-(strlen("CPU Governor"));
			fprintf(tunLogPtr,"%s", "CPU Governor"); //redundancy for visual
			fprintf(tunLogPtr,"%*s", vPad, aBiosValue);

			if (strcmp(aBiosValue, req_governor) != 0)
			{
				fprintf(tunLogPtr,"%26s %20c\n", req_governor, gApplyBiosTuning); //could use %26.4f, 
				if (gApplyBiosTuning == 'y')
				{
					//Apply Bios Tuning
					if (other_way)
						sprintf(aBiosSetting,"sudo cpupower frequency-set -g %s",req_governor);
					else
						sprintf(aBiosSetting,"sh -c \'echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor\'");

					system(aBiosSetting);
				}
				else
					{
						//Save in Case Operator want to apply from menu
						if (other_way)
							sprintf(aBiosSetting,"sudo cpupower frequency-set -g %s",req_governor);
						else
							sprintf(aBiosSetting,"sh -c \'echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor\'");

						memcpy(aApplyBiosDefTun2DArray[aApplyBiosDefTunCount], aBiosSetting, strlen(aBiosSetting));
						aApplyBiosDefTunCount++;
					}
			}
			else
				fprintf(tunLogPtr,"%26s %20s\n", req_governor, "na");

			fclose(biosCfgFPtr);
			system("rm -f /tmp/BIOS.cfgfile"); //cleanup
		}

	if (line)
		free(line);

	return;
}

void fDoIrqBalance()
{
	char ctime_buf[27];
	time_t clk;
	char *line = NULL;
	size_t len = 0;
	ssize_t nread;
	struct stat sb;
	char aBiosSetting[256];
	char aBiosValue[256];
	int vPad;
	char * rec_irq_balance = "inactive";
	FILE *biosCfgFPtr = 0;
	int found = 0;

	sprintf(aBiosSetting,"systemctl status irqbalance > /tmp/BIOS.cfgfile 2>/dev/null");
	system(aBiosSetting);

	stat("/tmp/BIOS.cfgfile", &sb);
	if (sb.st_size == 0)
	{
		//doesn't support checking irqbalance
		goto dns_irqbal;
	}

	biosCfgFPtr = fopen("/tmp/BIOS.cfgfile","r");
	if (!biosCfgFPtr)
	{
		int save_errno = errno;
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: Could not open file /tmp/BIOS.cfgfile to see irqbalance, errno = %d...\n", ctime_buf, phase2str(current_phase), save_errno);
	}
	else
		{
			while((nread = getline(&line, &len, biosCfgFPtr)) != -1)
			{ 	//active or inactive?

				int count = 0, ncount = 0;
                char *y;

                if ((y = strstr(line,"Active:")))
                {
                    y = y + strlen("Active:");
                    while (!isalpha(y[count])) count++;

                    while (isalpha(y[count]))
                    {
                        aBiosValue[ncount] = y[count];
                        ncount++;
                        count++;
                    }

                    aBiosValue[ncount] = 0;
					found = 1;
					break;
                }
			}

			if (found)
			{
				vPad = SETTINGS_PAD_MAX-(strlen("IRQ Balance"));
				fprintf(tunLogPtr,"%s", "IRQ Balance"); //redundancy for visual
				fprintf(tunLogPtr,"%*s", vPad, aBiosValue);

				if (strcmp(aBiosValue, rec_irq_balance) != 0)
				{
					fprintf(tunLogPtr,"%26s %20c\n", rec_irq_balance, gApplyBiosTuning); //could use %26.4f, 
					if (gApplyBiosTuning == 'y')
					{
						//Apply Bios Tuning
						sprintf(aBiosSetting,"systemctl stop irqbalance");
						system(aBiosSetting);
					}
					else
						{
							//Save in Case Operator want to apply from menu
							sprintf(aBiosSetting,"systemctl stop irqbalance");
							memcpy(aApplyBiosDefTun2DArray[aApplyBiosDefTunCount], aBiosSetting, strlen(aBiosSetting));
							aApplyBiosDefTunCount++;
						}
				}
				else
					fprintf(tunLogPtr,"%26s %20s\n", rec_irq_balance, "na");
			}

			fclose(biosCfgFPtr);
			system("rm -f /tmp/BIOS.cfgfile"); //cleanup
		}

	if (line)
		free(line);

	return;

dns_irqbal:
        vPad = SETTINGS_PAD_MAX-(strlen("IRQ Balance"));
        fprintf(tunLogPtr,"%s", "IRQ Balance"); //redundancy for visual
        fprintf(tunLogPtr,"%*s", vPad, "not supported");
        fprintf(tunLogPtr,"%26s %20s\n", "not supported", "na");
        system("rm -f /tmp/BIOS.cfgfile"); //remove file after use

	return;
}

void fDoBiosTuning(void)
{
	char ctime_buf[27];
	time_t clk;
	char *header2[] = {"Setting", "Current Value", "Recommended Value", "Applied"};

	gettime(&clk, ctime_buf);

	fprintf(tunLogPtr,"\n%s %s: -------------------------------------------------------------------\n", ctime_buf, phase2str(current_phase));
	fprintf(tunLogPtr,  "%s %s: ***************Start of Evaluate BIOS configuration****************\n\n", ctime_buf, phase2str(current_phase));

	fprintf(tunLogPtr, "%s %*s %25s %20s\n", header2[0], HEADER_SETTINGS_PAD, header2[1], header2[2], header2[3]);
	fflush(tunLogPtr);

	fDoCpuPerformance();
	fDoIrqBalance();

	gettime(&clk, ctime_buf);
	fprintf(tunLogPtr,"\n%s %s: ***For additional info about your hardware settings and capabilities,\n", ctime_buf, phase2str(current_phase));
	fprintf(tunLogPtr,"%s %s: ***please run 'sudo dmidecode' and/or 'sudo lshw'. \n", ctime_buf, phase2str(current_phase));

	fprintf(tunLogPtr,"\n%s %s: ****************End of Evaluate BIOS configuration*****************\n", ctime_buf, phase2str(current_phase));
	fprintf(tunLogPtr,  "%s %s: -------------------------------------------------------------------\n\n", ctime_buf, phase2str(current_phase));

	return;
}

int fCheckInterfaceExist() 
{
	int vRet;
	char aNicPath[512];

	sprintf(aNicPath,"/sys/class/net/%s",netDevice);
	vRet = access(aNicPath, F_OK);

	return vRet;
}

void fDoGetDeviceCap(void)
{
	char ctime_buf[27];
	time_t clk;
	char *line = NULL;
	size_t len = 0;
	ssize_t nread;
	char aNicSetting[256];
	FILE *nicCfgFPtr = 0;

	gettime(&clk, ctime_buf);
	sprintf(aNicSetting,"cat /sys/class/net/%s/speed > /tmp/NIC.cfgfile",netDevice);
	system(aNicSetting);

	nicCfgFPtr = fopen("/tmp/NIC.cfgfile","r");
	if (!nicCfgFPtr)
	{
		int save_errno = errno;
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: Could not open file /tmp/NIC.cfgfile to retrieve speed value, errno = %d...\n", ctime_buf, phase2str(current_phase), save_errno);
	}
	else
		{
			while((nread = getline(&line, &len, nicCfgFPtr)) != -1)
			{ 
				char sValue[256];
				int cfg_val = 0;
				//printf("Retrieved line of length %zu:\n", nread);
				//printf("&%s&",line);
				strcpy(sValue,line);
				if (sValue[strlen(sValue)-1] == '\n')
					sValue[strlen(sValue)-1] = 0;

				cfg_val = atoi(sValue);
				if (cfg_val == 0) //wasn't set properly - error
				{
					int save_errno = errno;
					gettime(&clk, ctime_buf);
					fprintf(tunLogPtr,"%s %s: Value for speed is invalid, value is %s, errno = %d...\n", ctime_buf, phase2str(current_phase), sValue, save_errno);
				}
				else
					{
						netDeviceSpeed = cfg_val;
					}

				//should only be one item
				break;
			}

			fclose(nicCfgFPtr);
			system("rm -f /tmp/NIC.cfgfile"); //remove file after use
		}

	if (line)
		free(line);

	return;
}

int fDoGetNuma(void)
{
	char ctime_buf[27];
	time_t clk;
	char *line = NULL;
	size_t len = 0;
	ssize_t nread;
	char aNicSetting[256];
	FILE *nicCfgFPtr = 0;
	int numa = -1;
	int found = 0;

	gettime(&clk, ctime_buf);
	sprintf(aNicSetting,"cat /sys/class/net/%s/device/numa_node > /tmp/NIC.cfgfile 2>/dev/null",netDevice);
	system(aNicSetting);

	nicCfgFPtr = fopen("/tmp/NIC.cfgfile","r");
	if (!nicCfgFPtr)
	{
		int save_errno = errno;
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: Could not open file /tmp/NIC.cfgfile to retrieve speed value, errno = %d...\n", ctime_buf, phase2str(current_phase), save_errno);
	}
	else
		{
			while((nread = getline(&line, &len, nicCfgFPtr)) != -1)
			{ 
				char sValue[256];
				int cfg_val = 0;
				//printf("Retrieved line of length %zu:\n", nread);
				//printf("&%s&",line);
				strcpy(sValue,line);
				if (sValue[strlen(sValue)-1] == '\n')
					sValue[strlen(sValue)-1] = 0;

				cfg_val = atoi(sValue);
				if (cfg_val == -1) 
				{
					numa = 0;
				}
				else
					{
						numa = cfg_val;
					}

				found = 1;
				break;
			}

			fclose(nicCfgFPtr);
			system("rm -f /tmp/NIC.cfgfile"); //remove file after use
		
			if (!found)
			{
				fprintf(tunLogPtr,"%s %s: Could not find Numa Node for %s \n", ctime_buf, phase2str(current_phase), netDevice);
			}	
		}

	if (line)
		free(line);

	return numa;
}


static int rec_txqueuelen_Greater10G = 20000; //recommended value for now if greater 10G
//static int rec_txqueuelen_Greater10G = 10000; //recommended value for now if greater 10G
static int rec_txqueuelen = 1000; //recommended value for now if 10G or less
static int rec_mtu = 9200; //recommended value for now
static char * rec_tcqdisc = "fq"; //recommended value for now
void fDoTxQueueLen()
{

	char ctime_buf[27];
	time_t clk;
	char *line = NULL;
	size_t len = 0;
	ssize_t nread;
	char aNicSetting[512];
	FILE *nicCfgFPtr = 0;

	sprintf(aNicSetting,"cat /sys/class/net/%s/tx_queue_len > /tmp/NIC.cfgfile",netDevice);
	system(aNicSetting);

	nicCfgFPtr = fopen("/tmp/NIC.cfgfile","r");
	if (!nicCfgFPtr)
	{
		int save_errno = errno;
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: Could not open file /tmp/NIC.cfgfile to retrieve speed value, errno = %d...\n", ctime_buf, phase2str(current_phase), save_errno);
	}
	else
		{
			while((nread = getline(&line, &len, nicCfgFPtr)) != -1)
			{ //1st keyword txqueuelen
				char sValue[256];
				int cfg_val = 0;
				//printf("Retrieved line of length %zu:\n", nread);
				//printf("&%s&",line);
				strcpy(sValue,line);
				if (sValue[strlen(sValue)-1] == '\n')
					sValue[strlen(sValue)-1] = 0;

				cfg_val = atoi(sValue);
				if (cfg_val == 0) //wasn't set properly
				{
					int save_errno = errno;
					gettime(&clk, ctime_buf);
					fprintf(tunLogPtr,"%s %s: Value for txqueuelen is invalid, value is %s, errno = %d...\n", ctime_buf, phase2str(current_phase), sValue, save_errno);
				}
				else
					{
						int vPad = SETTINGS_PAD_MAX-(strlen("txqueuelen"));
						fprintf(tunLogPtr,"%s", "txqueuelen"); //redundancy for visual
						fprintf(tunLogPtr,"%*s", vPad, sValue);

						if (netDeviceSpeed <= 10000) //10G or less
						{
							if (rec_txqueuelen > cfg_val)
							{
								fprintf(tunLogPtr,"%26d %20c\n", rec_txqueuelen, gApplyNicTuning);
								if (gApplyNicTuning == 'y')
								{
									//Apply Inital DefSys Tuning
									sprintf(aNicSetting,"ifconfig %s txqueuelen %d", netDevice, rec_txqueuelen);
									system(aNicSetting);
								}
								else
									{
										//Save in Case Operator want to apply from menu
										sprintf(aNicSetting,"ifconfig %s txqueuelen %d", netDevice, rec_txqueuelen);
										memcpy(aApplyNicDefTun2DArray[aApplyNicDefTunCount], aNicSetting, strlen(aNicSetting));
										aApplyNicDefTunCount++;
									}
							}
							else
								fprintf(tunLogPtr,"%26d %20s\n", rec_txqueuelen, "na");
						}
						else //greater than 10G
							{
								if (rec_txqueuelen_Greater10G > cfg_val)
								{
									fprintf(tunLogPtr,"%26d %20c\n", rec_txqueuelen_Greater10G, gApplyNicTuning);
									if (gApplyNicTuning == 'y')
									{
										//Apply Inital DefSys Tuning
										sprintf(aNicSetting,"ifconfig %s txqueuelen %d", netDevice, rec_txqueuelen_Greater10G);
										system(aNicSetting);
									}
									else
										{
											//Save in Case Operator want to apply from menu
											sprintf(aNicSetting,"ifconfig %s txqueuelen %d", netDevice, rec_txqueuelen_Greater10G);
											memcpy(aApplyNicDefTun2DArray[aApplyNicDefTunCount], aNicSetting, strlen(aNicSetting));
											aApplyNicDefTunCount++;
										}
								}
								else
									fprintf(tunLogPtr,"%26d %20s\n", rec_txqueuelen_Greater10G, "na");
							}
					}

				//should only be one item
				break;
			}
			
			fclose(nicCfgFPtr);
			system("rm -f /tmp/NIC.cfgfile"); //remove file after use
		}

	if (line)
		free(line);

	return;
}

void fDoRingBufferSize()
{
        char ctime_buf[27];
        time_t clk;
        char *line = NULL;
        size_t len = 0;
        ssize_t nread;
        struct stat sb;
        char aNicSetting[512];
        char sRXMAXValue[256];
        char sRXCURRValue[256];
        char sTXMAXValue[256];
        char sTXCURRValue[256];
        int rxcount = 0;
        int txcount = 0;
        int vPad;
        FILE *nicCfgFPtr = 0;

        sprintf(aNicSetting,"ethtool --show-ring %s > /tmp/NIC.cfgfile 2>/dev/null",netDevice);
        system(aNicSetting);

        stat("/tmp/NIC.cfgfile", &sb);
        if (sb.st_size == 0)
        {
                //doesn't support ethtool -a
                goto dnrb_support;
        }

        nicCfgFPtr = fopen("/tmp/NIC.cfgfile","r");
        if (!nicCfgFPtr)
        {
                int save_errno = errno;
                gettime(&clk, ctime_buf);
                fprintf(tunLogPtr,"%s %s: Could not open file /tmp/NIC.cfgfile to retrieve speed value, errno = %d...\n", ctime_buf, phase2str(current_phase), save_errno);
        }
        else
                {
			while((nread = getline(&line, &len, nicCfgFPtr)) != -1)
                        { //2nd and 3rd keywords RX and tx ring buffer size
                                int count = 0, ncount = 0;

                                if (strstr(line,"RX:") && rxcount == 0)
                                {
                                        rxcount++;

                                        while (!isdigit(line[count])) count++;

                                        while (isdigit(line[count]))
                                        {
                                                sRXMAXValue[ncount] = line[count];
                                                ncount++;
                                                count++;
                                        }

                                        sRXMAXValue[ncount] = 0;
                                }
                                else
                                        if (strstr(line,"RX:"))
                                        {
                                                rxcount++;

                                                while (!isdigit(line[count])) count++;

                                                while (isdigit(line[count]))
                                                {
                                                        sRXCURRValue[ncount] = line[count];
                                                        ncount++;
                                                        count++;
                                                }

                                                sRXCURRValue[ncount] = 0;
                                        }
                                        else
                                                if (strstr(line,"TX:") && txcount == 0)
							{
                                                        txcount++;

                                                        while (!isdigit(line[count])) count++;

                                                        while (isdigit(line[count]))
                                                        {
                                                                sTXMAXValue[ncount] = line[count];
                                                                ncount++;
                                                                count++;
                                                        }

                                                        sTXMAXValue[ncount] = 0;
                                                }
                                                else
                                                        if (strstr(line,"TX:"))
                                                        {
                                                                //should be the last thing I need
                                                                int cfg_max_val = 0;
                                                                int cfg_cur_val = 0;

                                                                txcount++;

                                                                while (!isdigit(line[count])) count++;

                                                                while (isdigit(line[count]))
                                                                {
                                                                        sTXCURRValue[ncount] = line[count];
                                                                        ncount++;
                                                                        count++;
                                                                }

                                                                sTXCURRValue[ncount] = 0;

                                                                cfg_max_val = atoi(sRXMAXValue);
                                                                cfg_cur_val = atoi(sRXCURRValue);

                                                                vPad = SETTINGS_PAD_MAX-(strlen("ring_buffer_RX"));
                                                                fprintf(tunLogPtr,"%s", "ring_buffer_RX"); //redundancy for visual
                                                                fprintf(tunLogPtr,"%*s", vPad, sRXCURRValue);

								netDevice_rx_ring_buff_cfg_max_val = cfg_max_val;
                                                                if (cfg_max_val > cfg_cur_val)
                                                                {
                                                                        if (netDeviceSpeed < 100000) //less than 100 Gb/s and greater than 10 Gb/s
                                                                        {
                                                                                fprintf(tunLogPtr,"%26d %20s\n", cfg_cur_val, "na"); //leave alone for now
                                                                        }
                                                                        else
                                                                                {
                                                                                        if ((cfg_max_val > 8192) && (cfg_cur_val < 8192))
                                                                                                cfg_max_val = 8192; //don't go above that for now on 100G

                                                                                        if ((cfg_max_val > 8192) && (cfg_cur_val > 8192))
                                                                                                cfg_max_val = cfg_cur_val; //don't go above that for now on 100G

                                                                                        fprintf(tunLogPtr,"%26d %20c\n", cfg_max_val, gApplyNicTuning);
                                                                                        if (gApplyNicTuning == 'y')
                                                                                        {
                                                                                                //Apply Initial DefSys Tuning
                                                                                                sprintf(aNicSetting,"ethtool -G %s rx %d", netDevice, cfg_max_val);
                                                                                                system(aNicSetting);
                                                                                        }
                                                                                        else
                                                                                                {
                                                                                                        //Save in Case Operator want to apply from menu
                                                                                                        sprintf(aNicSetting,"ethtool -G %s rx %d", netDevice, cfg_max_val);
                                                                                                        memcpy(aApplyNicDefTun2DArray[aApplyNicDefTunCount], aNicSetting, strlen(aNicSetting));
                                                                                                        aApplyNicDefTunCount++;
                                                                                                }
                                                                                }
                                                                }
                                                                else
                                                                        fprintf(tunLogPtr,"%26d %20s\n", cfg_max_val, "na");

                                                                cfg_max_val = atoi(sTXMAXValue);
                                                                cfg_cur_val = atoi(sTXCURRValue);

                                                                vPad = SETTINGS_PAD_MAX-(strlen("ring_buffer_TX"));
                                                                fprintf(tunLogPtr,"%s", "ring_buffer_TX"); //redundancy for visual
                                                                fprintf(tunLogPtr,"%*s", vPad, sTXCURRValue);

								netDevice_tx_ring_buff_cfg_max_val = cfg_max_val;
                                                                if (cfg_max_val > cfg_cur_val)
                                                                {
                                                                        if (netDeviceSpeed < 100000) //less than 100 Gb/s and greater than 10 Gb/s
                                                                        {
                                                                                fprintf(tunLogPtr,"%26d %20s\n", cfg_cur_val, "na");
                                                                        }
                                                                        else
                                                                                {
                                                                                        if ((cfg_max_val > 8192) && (cfg_cur_val < 8192))
                                                                                                cfg_max_val = 8192; //don't go above that for now on 100G

                                                                                        if ((cfg_max_val > 8192) && (cfg_cur_val > 8192))
                                                                                                cfg_max_val = cfg_cur_val; //don't go above that for now on 100G

                                                                                        fprintf(tunLogPtr,"%26d %20c\n", cfg_max_val, gApplyNicTuning);
                                                                                        if (gApplyNicTuning == 'y')
                                                                                        {
                                                                                                //Apply Initial DefSys Tuning
                                                                                                sprintf(aNicSetting,"ethtool -G %s tx %d", netDevice, cfg_max_val);
                                                                                                system(aNicSetting);
                                                                                        }
                                                                                        else
                                                                                                {
                                                                                                        //Save in Case Operator want to apply from menu
                                                                                                        sprintf(aNicSetting,"ethtool -G %s tx %d", netDevice, cfg_max_val);
                                                                                                        memcpy(aApplyNicDefTun2DArray[aApplyNicDefTunCount], aNicSetting, strlen(aNicSetting));
                                                                                                        aApplyNicDefTunCount++;
                                                                                                }
                                                                                }
                                                                }
                                                                else
                                                                        fprintf(tunLogPtr,"%26d %20s\n", cfg_max_val, "na");

                                                                //should be the last thing I need
                                                                break;
                                                        }
                                                        else
                                                                continue;
                        }

                        fclose(nicCfgFPtr);
                        system("rm -f /tmp/NIC.cfgfile"); //remove file after use
                }

        if (line)
                free(line);

	return;

dnrb_support:
        vPad = SETTINGS_PAD_MAX-(strlen("ring_buffer_rx_tx"));
        fprintf(tunLogPtr,"%s", "ring_buffer_rx_tx"); //redundancy for visual
        fprintf(tunLogPtr,"%*s", vPad, "not supported");
        fprintf(tunLogPtr,"%26s %20s\n", "not supported", "na");
        system("rm -f /tmp/NIC.cfgfile"); //remove file after use

        return;
}

void fDoLRO() 
{
	char ctime_buf[27];
	time_t clk;
	char *line = NULL;
	size_t len = 0;
	ssize_t nread;
	char aNicSetting[512];
	int vPad;
	struct stat sb;
	FILE *nicCfgFPtr = 0;
	int fixed = 0;
	char * recommended_val = "on";

	sprintf(aNicSetting,"ethtool --show-features %s | grep large-receive-offload > /tmp/NIC.cfgfile",netDevice);
	system(aNicSetting);
    
	stat("/tmp/NIC.cfgfile", &sb);
	if (sb.st_size == 0) 
	{
		//doesn't support receive offload
		goto dn_support;
	}
	else
		{
			sprintf(aNicSetting,"ethtool --show-features %s | grep large-receive-offload | grep fixed > /tmp/NIC.cfgfile",netDevice);
			system(aNicSetting);
	
			stat("/tmp/NIC.cfgfile", &sb);
			if (sb.st_size == 0) //not fixed
			{
				//do it again to get the truth
				sprintf(aNicSetting,"ethtool --show-features %s | grep large-receive-offload > /tmp/NIC.cfgfile",netDevice);
				system(aNicSetting);

			}
			else
				{
					fixed = 1;
    				}
		}
    
	nicCfgFPtr = fopen("/tmp/NIC.cfgfile","r");
	if (!nicCfgFPtr)
	{
		int save_errno = errno;
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: Could not open file /tmp/NIC.cfgfile to retrieve speed value, errno = %d...\n", ctime_buf, phase2str(current_phase), save_errno);
	}
	else
		{
			while((nread = getline(&line, &len, nicCfgFPtr)) != -1)
			{ //large receive offload
				int count = 0, ncount = 0;
				char *q;
				char sLROValue[256];

				q = line + strlen("large-receive-offload");
				strcpy(sLROValue,q);

				while (!isalpha(q[count])) count++;

				while (isalpha(q[count]))
				{
					sLROValue[ncount] = q[count];
					ncount++;
					count++;
				}

				sLROValue[ncount] = 0;

				vPad = SETTINGS_PAD_MAX-(strlen("large-receive-offload"));
				fprintf(tunLogPtr,"%s", "large-receive-offload"); //redundancy for visual
				fprintf(tunLogPtr,"%*s", vPad, sLROValue);

				if ((strcmp(recommended_val, sLROValue) != 0) && !fixed)
				{
					fprintf(tunLogPtr,"%26s %20c\n", recommended_val, gApplyNicTuning);
					if (gApplyNicTuning == 'y')
					{
						//Apply Initial DefSys Tuning
						sprintf(aNicSetting,"ethtool -K %s lro %s", netDevice, recommended_val);
						system(aNicSetting);
					}
					else
						{
							//Save in Case Operator want to apply from menu
							sprintf(aNicSetting,"ethtool -K %s lro %s", netDevice, recommended_val);
							memcpy(aApplyNicDefTun2DArray[aApplyNicDefTunCount], aNicSetting, strlen(aNicSetting));
							aApplyNicDefTunCount++;
						}
				}
				else
					if (fixed)
						fprintf(tunLogPtr,"%26s %20s\n", recommended_val, "na - fixed");
					else
						fprintf(tunLogPtr,"%26s %20s\n", recommended_val, "na");

				//should be only one line in the file
				break;
			}
	
			fclose(nicCfgFPtr);
			system("rm -f /tmp/NIC.cfgfile"); //remove file after use
		}
	
	if (line)
		free(line);
	
	return;

dn_support:
	vPad = SETTINGS_PAD_MAX-(strlen("large-receive-offload"));
	fprintf(tunLogPtr,"%s", "large-receive-offload"); //redundancy for visual
	fprintf(tunLogPtr,"%*s", vPad, "not supported");
	fprintf(tunLogPtr,"%26s %20s\n", recommended_val, "na");
			
	fclose(nicCfgFPtr);
	system("rm -f /tmp/NIC.cfgfile"); //remove file after use

	return;
}

void fDoMTU()
{
	char ctime_buf[27];
	time_t clk;
	char *line = NULL;
	size_t len = 0;
	ssize_t nread;
	char aNicSetting[512];
	FILE *nicCfgFPtr = 0;

	sprintf(aNicSetting,"cat /sys/class/net/%s/mtu  > /tmp/NIC.cfgfile",netDevice);
	system(aNicSetting);

	nicCfgFPtr = fopen("/tmp/NIC.cfgfile","r");
	if (!nicCfgFPtr)
	{
		int save_errno = errno;
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: Could not open file /tmp/NIC.cfgfile to retrieve speed value, errno = %d...\n", ctime_buf, phase2str(current_phase), save_errno);
	}
	else
		{
			while((nread = getline(&line, &len, nicCfgFPtr)) != -1)
			{ //mtu
				char sValue[256];
				int cfg_val = 0;
				strcpy(sValue,line);
				if (sValue[strlen(sValue)-1] == '\n')
					sValue[strlen(sValue)-1] = 0;

				cfg_val = atoi(sValue);
				if (cfg_val == 0) //wasn't set properly - error
				{
					int save_errno = errno;
					gettime(&clk, ctime_buf);
					fprintf(tunLogPtr,"%s %s: Value for mtu is invalid, value is %s, errno = %d...\n", ctime_buf, phase2str(current_phase), sValue, save_errno);
				}
				else
					{
						int vPad = SETTINGS_PAD_MAX-(strlen("mtu"));
						fprintf(tunLogPtr,"%s", "mtu"); //redundancy for visual
						fprintf(tunLogPtr,"%*s", vPad, sValue);

						if (rec_mtu > cfg_val)
						{
							fprintf(tunLogPtr,"%26d %20c\n", rec_mtu, gApplyNicTuning);
							if (gApplyNicTuning == 'y')
							{
								//Apply Inital DefSys Tuning
								sprintf(aNicSetting,"sudo ip link set dev %s mtu %d", netDevice, rec_mtu);
								system(aNicSetting);
							}
							else
								{
									//Save in Case Operator want to apply from menu
									sprintf(aNicSetting,"sudo ip link set dev %s mtu %d", netDevice, rec_mtu);
									memcpy(aApplyNicDefTun2DArray[aApplyNicDefTunCount], aNicSetting, strlen(aNicSetting));
									aApplyNicDefTunCount++;
								}
						}
						else
							fprintf(tunLogPtr,"%26d %20s\n", cfg_val, "na");
					}

				//should only be one item
				break;
			}
	
			fclose(nicCfgFPtr);
			system("rm -f /tmp/NIC.cfgfile"); //remove file after use
		}
	
	if (line)
		free(line);

	return;
}

void fDoTcQdiscFq()
{
	char ctime_buf[27];
	time_t clk;
	char *line = NULL;
	size_t len = 0;
	ssize_t nread;
	struct stat sb;
	int found = 0;
	char aQdiscVal[512];
	char aNicSetting[1024];
	FILE *nicCfgFPtr = 0;
			
	sprintf(aNicSetting,"tc qdisc show dev %s root > /tmp/NIC.cfgfile 2>/dev/null",netDevice);
	system(aNicSetting);
	stat("/tmp/NIC.cfgfile", &sb);
	if (sb.st_size == 0) //some OS don't like to have the "root" as an option
	{
		sprintf(aNicSetting,"tc qdisc show dev %s  > /tmp/NIC.cfgfile",netDevice);
		system(aNicSetting);
	}
			
	nicCfgFPtr = fopen("/tmp/NIC.cfgfile","r");
	if (!nicCfgFPtr)
	{
		int save_errno = errno;
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: Could not open file /tmp/NIC.cfgfile to retrieve speed value, errno = %d...\n", ctime_buf, phase2str(current_phase), save_errno);
	}
	else
		{
			while((nread = getline(&line, &len, nicCfgFPtr)) != -1)
			{ //tc qdisc
				char sValue[512];
				char *y = 0;
				strcpy(sValue,line);
				if (sValue[strlen(sValue)-1] == '\n')
					sValue[strlen(sValue)-1] = 0;
					
				y = strstr(sValue,"qdisc");
				if (y)
				{
					int count = 0;
					y = y + strlen("qdisc");
					while isblank((int)*y) y++;
					memset(aQdiscVal,0,sizeof(aQdiscVal));
					while isgraph((int)*y) 
					{
						aQdiscVal[count] = *y;
						y++;	
						count++;
					}
					
					found = 1;
					break;
				}
			}

			if (found)
			{
				int vPad = SETTINGS_PAD_MAX-(strlen("tc_qdisc"));
				found = 0;
				fprintf(tunLogPtr,"%s", "tc_qdisc"); //redundancy for visual
				fprintf(tunLogPtr,"%*s", vPad, aQdiscVal);

				if (strcmp(rec_tcqdisc,aQdiscVal) != 0)
				{
					fprintf(tunLogPtr,"%26s %20c\n", rec_tcqdisc, gApplyNicTuning);
					if (gApplyNicTuning == 'y')
					{
						//Apply Inital DefSys Tuning
						sprintf(aNicSetting,"tc qdisc del dev %s root %s 2>/dev/null; tc qdisc add dev %s root fq", netDevice, aQdiscVal, netDevice);
						system(aNicSetting);
					}
					else
						{
							//Save in Case Operator want to apply from menu
							sprintf(aNicSetting,"tc qdisc del dev %s root %s 2>/dev/null; tc qdisc add dev %s root fq", netDevice, aQdiscVal, netDevice);
							memcpy(aApplyNicDefTun2DArray[aApplyNicDefTunCount], aNicSetting, strlen(aNicSetting));
							aApplyNicDefTunCount++;
						}
				}
				else
					fprintf(tunLogPtr,"%26s %20s\n", aQdiscVal, "na");
			}

			fclose(nicCfgFPtr);
			system("rm -f /tmp/NIC.cfgfile"); //remove file after use
		}
	return;
}

void fDoFlowControl()
{
	char ctime_buf[27];
	time_t clk;
	char *line = NULL;
	size_t len = 0;
	ssize_t nread;
	char aNicSetting[512];
	int vPad;
	struct stat sb;
	FILE *nicCfgFPtr = 0;
	char * rec_rx_val = "on";
	char * rec_tx_val = "on";
	char sRXCURRValue[256];
	char sTXCURRValue[256];

	sprintf(aNicSetting,"ethtool -a %s > /tmp/NIC.cfgfile 2>/dev/null",netDevice);
	system(aNicSetting);

	stat("/tmp/NIC.cfgfile", &sb);
	if (sb.st_size == 0)
	{
		//doesn't support ethtool -a
		goto dnflow_support;
	}

	nicCfgFPtr = fopen("/tmp/NIC.cfgfile","r");
	if (!nicCfgFPtr)
	{
		int save_errno = errno;
		gettime(&clk, ctime_buf);
		fprintf(tunLogPtr,"%s %s: Could not open file /tmp/NIC.cfgfile to retrieve speed value, errno = %d...\n", ctime_buf, phase2str(current_phase), save_errno);
	}
	else
		{
			while((nread = getline(&line, &len, nicCfgFPtr)) != -1)
			{ //RX and TX flow control 
				int count = 0, ncount = 0;
				char *y;

				if ((y = strstr(line,"RX:")))
				{
					y = y + strlen("RX:");
					while (!isalpha(y[count])) count++;

					while (isalpha(y[count]))
					{
						sRXCURRValue[ncount] = y[count];
						ncount++;
						count++;
					}

					sRXCURRValue[ncount] = 0;
				}
				else
					if ((y = strstr(line,"TX:")))
					{
						y = y + strlen("TX:");
						while (!isalpha(y[count])) count++;

						while (isalpha(y[count]))
						{
							sTXCURRValue[ncount] = y[count];
							ncount++;
							count++;
						}

						sTXCURRValue[ncount] = 0;
					}
				}

				vPad = SETTINGS_PAD_MAX-(strlen("flow_control_RX"));
				fprintf(tunLogPtr,"%s", "flow_control_RX"); //redundancy for visual
				fprintf(tunLogPtr,"%*s", vPad, sRXCURRValue);

				if (strcmp(rec_rx_val,sRXCURRValue) != 0)
				{
					fprintf(tunLogPtr,"%26s %20c\n", rec_rx_val, gApplyNicTuning);
					if (gApplyNicTuning == 'y')
					{
							//Apply Initial DefSys Tuning
							sprintf(aNicSetting,"ethtool -A %s rx %s", netDevice, rec_rx_val);
							system(aNicSetting);
					}
					else
						{
							//Save in Case Operator want to apply from menu
							sprintf(aNicSetting,"ethtool -A %s rx %s", netDevice, rec_rx_val);
							memcpy(aApplyNicDefTun2DArray[aApplyNicDefTunCount], aNicSetting, strlen(aNicSetting));
							aApplyNicDefTunCount++;
						}
				}
				else
					fprintf(tunLogPtr,"%26s %20s\n", rec_rx_val, "na");

				vPad = SETTINGS_PAD_MAX-(strlen("flow_control_TX"));
				fprintf(tunLogPtr,"%s", "flow_control_TX"); //redundancy for visual
				fprintf(tunLogPtr,"%*s", vPad, sTXCURRValue);

				if (strcmp(rec_tx_val, sTXCURRValue) != 0)
				{
					fprintf(tunLogPtr,"%26s %20c\n", rec_tx_val, gApplyNicTuning);
					if (gApplyNicTuning == 'y')
					{
						//Apply Initial DefSys Tuning
						sprintf(aNicSetting,"ethtool -A %s tx %s", netDevice, rec_tx_val);
						system(aNicSetting);
					}
					else
						{
							//Save in Case Operator want to apply from menu
							sprintf(aNicSetting,"ethtool -A %s tx %s", netDevice, rec_tx_val);
							memcpy(aApplyNicDefTun2DArray[aApplyNicDefTunCount], aNicSetting, strlen(aNicSetting));
							aApplyNicDefTunCount++;
						}
				}
				else
					fprintf(tunLogPtr,"%26s %20s\n", rec_tx_val, "na");

			fclose(nicCfgFPtr);
			system("rm -f /tmp/NIC.cfgfile"); //remove file after use
		}
	
	if (line)
		free(line);
	
	return;

dnflow_support:
	vPad = SETTINGS_PAD_MAX-(strlen("flow_control_rx_tx"));
	fprintf(tunLogPtr,"%s", "flow_control_rx_tx"); //redundancy for visual
	fprintf(tunLogPtr,"%*s", vPad, "not supported");
	fprintf(tunLogPtr,"%26s %20s\n", "not supported", "na");
	system("rm -f /tmp/NIC.cfgfile"); //remove file after use

	return;
}

void fDoIrqAffinity()
{
	char ctime_buf[27];
	time_t clk;
	char aNicSetting[512];
	gettime(&clk, ctime_buf);

	{
		fprintf(tunLogPtr,"\n%s %s: %s", ctime_buf, phase2str(current_phase), "NOTE: **IRQ Affinity Tuning** *will be done when NIC settings applied*\n"); 
		if (gApplyNicTuning == 'y')
		{
			//Apply 
			sprintf(aNicSetting,"./set_irq_affinity.sh %s", netDevice);
			system(aNicSetting);
		}
		else
			{
				//Save in Case Operator want to apply from menu
				sprintf(aNicSetting,"./set_irq_affinity.sh %s", netDevice);
				memcpy(aApplyNicDefTun2DArray[aApplyNicDefTunCount], aNicSetting, strlen(aNicSetting));
				aApplyNicDefTunCount++;
			}
	}

	return;
}

void fDoNicTuning(void)
{
	char ctime_buf[27];
	time_t clk;
	char *header2[] = {"Setting", "Current Value", "Recommended Value", "Applied"};

	gettime(&clk, ctime_buf);

	fprintf(tunLogPtr,"\n%s %s: -------------------------------------------------------------------\n", ctime_buf, phase2str(current_phase));
	fprintf(tunLogPtr,  "%s %s: ****************Start of Evaluate NIC configuration****************\n\n", ctime_buf, phase2str(current_phase));
	fprintf(tunLogPtr,"%s %s: Speed of device \"%s\" is %dGb/s\n\n", ctime_buf, phase2str(current_phase), netDevice, netDeviceSpeed/1000);

	fprintf(tunLogPtr, "%s %*s %25s %20s\n", header2[0], HEADER_SETTINGS_PAD, header2[1], header2[2], header2[3]);
	fflush(tunLogPtr);
#if 0
	//have to test more and see how this affects the NIC
	fDoTxQueueLen();
#endif
	fDoRingBufferSize();
#if 0
	//have to test more and see how this affects the NIC
	fDoLRO();//large receive offload
#endif
	fDoMTU();
#if 0
	fDoTcQdiscFq();
	fDoFlowControl();
#endif

	//fDoIrqAffinity(); //Skip IRQ affinity for now

/*
 * ethtool -i enoX gives bus info
 * then sudo lspci -vvv -s <bus info> gives speed, width etc.
 * some systems dont dont show it though...
*/

/* numactl --hardware will show number of cores per numa node */

	fprintf(tunLogPtr,"\n%s %s: *****************End of Evaluate NIC configuration*****************\n", ctime_buf, phase2str(current_phase));
	fprintf(tunLogPtr,  "%s %s: -------------------------------------------------------------------\n\n", ctime_buf, phase2str(current_phase));


	return;
}

int user_assess(int argc, char **argv) 
{

	time_t clk;
	char ctime_buf[27];

	current_phase = ASSESSMENT;
	gettime(&clk, ctime_buf);

	gettime(&clk, ctime_buf);

	//fDoGetUserCfgValues();

	//fDoGetDeviceCap();
	numaNode = fDoGetNuma();

	fDoSystemTuning();

	fDoBiosTuning();

	fDoNicTuning();

	gettime(&clk, ctime_buf);
	current_phase = LEARNING;
	
	fflush(tunLogPtr);
	gettime(&clk, ctime_buf);

	{
		// in case the user wants to apply recommended settings interactively
		int x =0;
		FILE * fApplyKernelDefTunPtr = 0;	
		if (aApplyKernelDefTunCount)
		{
			fApplyKernelDefTunPtr = fopen("/tmp/applyKernelDefFile","w"); //open and close to wipe out file - other ways to do this, but this should work...
			if (!fApplyKernelDefTunPtr)
			{
				int save_errno = errno;
				fprintf(tunLogPtr, "%s %s: Could not open */tmp/applyKernelDefFile* for writing, errno = %d***\n", ctime_buf, phase2str(current_phase), save_errno);
				goto leave;
			}

			fprintf(fApplyKernelDefTunPtr, "%d\n",aApplyKernelDefTunCount+2);

			for (x = 0; x < aApplyKernelDefTunCount; x++)
				fprintf(fApplyKernelDefTunPtr, "%s\n",aApplyKernelDefTun2DArray[x]);
				
			fclose(fApplyKernelDefTunPtr);	
		}
		else
			system("rm -f /tmp/applyKernelDefFile");	//There is a way this can be left around by mistake
	}

	{
		// in case the user wants to apply recommended settings interactively
		int x =0;
		FILE * fApplyNicDefTunPtr = 0;	
		if (aApplyNicDefTunCount)
		{
			fApplyNicDefTunPtr = fopen("/tmp/applyNicDefFile","w"); //open and close to wipe out file - other ways to do this, but this should work...
			if (!fApplyNicDefTunPtr)
			{
				int save_errno = errno;
				fprintf(tunLogPtr, "%s %s: Could not open */tmp/applyNicDefFile* for writing, errno = %d***\n", ctime_buf, phase2str(current_phase), save_errno);
				goto leave;
			}

			fprintf(fApplyNicDefTunPtr, "%d\n",aApplyNicDefTunCount+2);

			for (x = 0; x < aApplyNicDefTunCount; x++)
				fprintf(fApplyNicDefTunPtr, "%s\n",aApplyNicDefTun2DArray[x]);
				
			fclose(fApplyNicDefTunPtr);	
		}
		else
			system("rm -f /tmp/applyNicDefFile");	//There is a way this can be left around by mistake
	}

	{
		// in case the user wants to apply recommended settings interactively
		int x =0;
		FILE * fApplyBiosDefTunPtr = 0;	
		if (aApplyBiosDefTunCount)
		{
			fApplyBiosDefTunPtr = fopen("/tmp/applyBiosDefFile","w"); //open and close to wipe out file - other ways to do this, but this should work...
			if (!fApplyBiosDefTunPtr)
			{
				int save_errno = errno;
				fprintf(tunLogPtr, "%s %s: Could not open */tmp/applyBiosDefFile* for writing, errno = %d***\n", ctime_buf, phase2str(current_phase), save_errno);
				goto leave;
			}

			fprintf(fApplyBiosDefTunPtr, "%d\n",aApplyBiosDefTunCount+2);

			for (x = 0; x < aApplyBiosDefTunCount; x++)
				fprintf(fApplyBiosDefTunPtr, "%s\n",aApplyBiosDefTun2DArray[x]);
				
			fclose(fApplyBiosDefTunPtr);	
		}
		else
			system("rm -f /tmp/applyBiosDefFile");	//There is a way this can be left around by mistake
	}

leave:
return 0;
}

