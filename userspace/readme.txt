		Notes on using the dtntune utility
		----------------------------------

dtntune is use to tune the Linux host for networking purposes.
Please type "sudo ./dtnmenu" and follow instructions to tune system

Note: This package requires 'lshw' and 'dmidecode' utilities tools
      to be installed on the system

Additional Notes:
There are 6 files that are used in conjunction with the Tuning Module: 
i.    readme.txt
ii.   user_config.txt 
iii.  gdv.sh 
iv.   gdv_100.sh
v.    /tmp/tuningLog 
vi.   /tmp/csvTuningLog

readme.txt
==========
The file you are currently reading.

user_config.txt 
===============
In the user_config.txt, the operator can use certain well known values to 
control how the Tuning Module operates.  So far, there are 9 parameters 
that can be used.  The following is an explanation for each one: 

a. evaluation timer  
The evaluation time parameter is the time that the tuning module will wait 
before reevalualting new metadata from the Collector  Module. It is measured 
in microseconds and has a default value of 500000. (500 ms) 
 
b. learning_mode_only 
The learning_mode_only parameter is used to tell the Tuning Module if it should 
apply tuning recommendations or not. The default value is “y” which means that 
it should not apply tunning recommendations. A value of “n” means that it 
should apply tuning recommendations. 

c. API_listen_port 
The API_listen_port parameter is used to allow a user to send CLI requests to 
the Tuning Module. The default value is 5523. 

d. apply_default_system_tuning 
The apply_default_system_tuning parameter is used to tell the Tuning Module if 
it should apply the initial tuning recommendations during the ASSESSMENT phase 
or not. The default value is “n” which means it should not apply the initial
tuning recommendations.                  

e. apply_bios_tuning
The apply_bios_tuning parameter is use to tell the Tuning Module if after 
evaluating the BIOS configuration, it should apply the recommendations
itself or not. The default is "n" which means it should make the 
recommendations to the DTN operator, but not apply them itself.

f. apply_nic_tuning
The apply_nic_tuning parameter is use to tell the Tuning Module if after 
evaluating the NIC configuration, it should apply the recommendations
itself or not. The default is "n" which means it should make the 
recommendations to the DTN operator, but not apply them itself.

g. maxnum_tuning_logs
The maxnum_tuning_logs parameter is used to limit the amount of backups
of tuningLogs that the Tuning Module should make. the default is 10.

h. make_default_system_tuning_perm
The make_default_system_tuning_perm is used to tell the Tuning Module if it
should make the default system tunings that it applies permanent or not.
That is, it will remain consistent after a reboot.

i. source_dtn_port
The source_dtn_port parameter is used to allow communication from the 
destination DTN to the source DTN. This enables the peers to send information
regarding performance issues to the source.  The default value is 5524.

gdv_100.sh
==========
Same as gdv.sh below, but used for NICs with speeds >= 100G


gdv.sh 
======
The gdv.sh file is a simple shell script file that get default values using the 
“sysctl” utility which is used to configure kernel parameters at runtime. 
The script saves the current values of certain setting we are interested in, 
in a file called “/tmp/current_config.orig”. The Tuning Module then looks at 
these settings during the ASSESSMENT phase and makes recommendations based on 
suggestions from the  https://fasterdata.es.net/ website. The following is an 
explanation for each of the settings that we are currently interested in. 
Note that some settings have a minimum, default and maximum values: 

a. net.core.rmem_max 
The net.core.rmem_max attribute defines the size of the buffer that receives 
UDP packets. The recommended value is 67108864. 
Note: We found concerning information in the literature that says that setting 
this attribute over 26 MB caused increased packet drop internally in the 
Linux kernel. Additional review and evaluation is needed for rmem_max. (some 
sites have conflicting descriptions – mention this as overall size of buffer 
whether tcp or udp.)  

b. net.core.wmem_max 
The net.core.wmem_max attribute defines the size of the buffer that writes UDP 
packets. The recommended value is 67108864. 

c. net.ipv4.tcp_congestion_control 
The net.ipv4.tcp_congestion_control attribute is used to achieve congestion 
avoidance. Transmission Control Protocol (TCP) uses a network 
congestion-avoidance algorithm that includes various aspects of an additive 
increase/multiplicative decrease(AIMD) scheme, along with other schemes 
including slow start and congestion window, to achieve congestion avoidance. 
The TCP	congestion-avoidance algorithm is the primary basis for congestion 
control in the Internet.[1][2][3][4] Per the end-to-end principle, congestion 
control is largely a function of internet hosts, not the network itself. 
There are several variations and versions of the algorithm implemented in 
protocol stacks of operating systems of computers that connect to the Internet. 
Cubic is usually the default in most Linux distribution, but we have found htcp 
usually works better.  
	You might also want to try BBR if it’s available on your system.  
The recommended value is bbr. 

d. net.ipv4.tcp_mtu_probing 
The net.ipv4.tcp_mtu_probing attribute works by sending small packets initially 
and if they are acknowledged successfully, gradually increasing the packet size 
until the correct Path MTU can be found. It is recommended for hosts with jumbo 
frames enabled. 
Note that there are some downsides to jumbo frames as well. All hosts in a 
single broadcast domain must be configured with the same MTU, and this can be 
difficult and error-prone.  Ethernet has no way of detecting an MTU mismatch - 
this is a layer 3 function that requires ICMP signaling in order to work 
correctly. The recommended setting is “1”. 

e. net.core.default_qdisc              
The net.core.default_qdisc attribute sets the default queuing mechanism for 
Linux networking. It has very significant effects on network performance and 
latency. fq_codel is the current best queuing discipline for performance and 
latency on Linux machines. The recommended setting is “fq”. 

f. net.ipv4.tcp_rmem        
The net.ipv4.tcp_rmem attribute is the amount of memory in bytes for read 
(receive) buffers per open socket. It contains the minimum, default and maximum 
values.  The recommended values are 4096 87380 33554432. 

g. net.ipv4.tcp_wmem 
The net.ipv4.tcp_wmem attribute is the amount of memory in bytes for write 
(transmit) buffers per open socket. It contains the minimum, default and maximum
values.  The recommended values are 4096 65536 33554432. 


/tmp/tuningLog 
==============
The tuningLog file contains the output of all the logging that the 
Tuning Module does. 

/tmp/csvTuningLog
=================
The csvTuningLog file contains a list of comma separated values which
shows any tuning that was applied. This file can be later used to
create JSON formatted data.

==============================================
==============================================
==============================================
Additional specs that may be worth checking out. 
Current settings below are on int03:

/***
 ***Maximum number of microseconds in one NAPI polling cycle. 
 ***Polling will exit when either netdev_budget_usecs have elapsed during 
 ***the poll cycle or the number of packets processed reaches netdev_budget.
 ***
 ***/
net.core.netdev_budget = 300 
net.core.netdev_budget_usecs = 8000 


/***
 ***Maximum number of packets, queued on the INPUT side, when the interface 
 ***receives packets faster than kernel can process them.
 ***
 ***/
net.core.netdev_max_backlog = 1000 

/***
 ***Increase transmission queue of interface. 
 ***Example provided here. Probably can increase more.
 ***
 ***/
ifconfig ethXXX txqueuelen 10000 


