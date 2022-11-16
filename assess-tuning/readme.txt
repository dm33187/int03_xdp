		Notes on using the dtntune utility
		----------------------------------

dtntune is use to tune the Linux host for networking purposes.
Please type "sudo ./dtnmenu" and follow instructions to tune system

Note: This package requires 'lshw' and 'dmidecode' utilities tools
      to be installed on the system

Additional Notes:
There are 3 files that are used in conjunction with the Tuning Module: 
i.   user_config.txt 
ii.  gdv.sh 
iii. /tmp/tuningLog 

user_config.txt 
===============
In the user_config.txt, the operator can use certain well known values to 
control how the Tuning Module operates.  So far, there are 2 parameter 
that can be used.  The following is an explanation for them: 

a. apply_default_system_tuning 
The apply_default_system_tuning parameter is used to tell the Tuning Module if 
it should apply the initial tuning recommendations during the ASSESSMENT phase 
or not. The default value is “n” which means it should not apply the initial
tuning recommendations.                  

b. make_default_system_tuning_perm
The make_default_system_tuning_perm is used to tell the Tuning Module if
it should make permanent any system tunings applied permanent or not. The 
default value is "n" which means it should not make permanent any system
tunings applied. Note that a setting of "y" is only valid if 
apply_default_system_tuning also have a setting of "y".

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


