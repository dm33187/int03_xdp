# Q-Factor: A Framework to Enable Ultra High-Speed Data Transfer Optimization based on Real-Time Network State
- 	Q-Factor is a response to the high-cost of manual and time-consuming tuning of data transfer parameters 
	applied to data-transfer optimization processes.


This repo is comprised of basically two parts:

-	**part 1** deals with creating an assessment package that a DTN operator
 	can use to see what recommendations, if any, can be made based on the 
	current settings of the system.

- 	**part 2** is a superset of part 1 and has 4 phases:
	* Starting
	* Assessment (part 1 and a bit more)
	* Learning
	* Tuning

#### Each part is independent of the other

**Part 1**

There are no known dependencies at this point. 

There are also two relevant directories here:

```assess-tuning``` and ```packaging```

**To Compile:**
-	go to assess-tuning directory and run ```make```
-	For a quick test:
	*	type ```sudo ./dtnmenu``` to run with a menu interaction
	*	type ```sudo ./dtnmenu <device>``` to also configure a device
	*	you will get output on your screen with the menu interaction
	*	type ```sudo ./dtn_tune``` to run without menu interaction
	* 	/tmp/tuningLog will contain the output from the last run

**To make a zip package:**
-	**Note:** you must compile as explained above before trying to make a pkg.
-	go to ```packaging``` directory
-	type ```sh ./createpkg.sh``` to create two zip files, one of which is called ASSESSdtntune.zip. 
-	```ASSESSdtntune.zip``` consist of files from the ```assess-tuning``` directory
-	create a temp directory, copy the ASSESSdtntune.zip file into it,  cd to it and type unzip *.zip
-	after unziping, run the commands as mentioned above "for a quick test"

**Note: Please see <temp_directory>/readme.txt for additional instructions**
-	Basically, there are four files of interest
	*	```user_config.txt```, ```gdv.sh```, ```gdv_100.sh``` and ```/tmp/tuningLog```
	*	```user_config.txt``` contains well known values to control how the application operates
	*	```gdv.sh``` and ```gdv_100.sh``` contains the settings that we are currently interested in
	*	```/tmp/tuningLog``` will contain the output from the last run

**This package has been tested with the following versions of Linux**
-	CentOS 7 ```*Kernels 3.10 and 5.4*```
-	CentOS 8 ```*Kernel 8.4*```
-	Ubuntu 16.04 LTS ```*Kernel 4.15.0-142-generic*```
-	Ubuntu 18.04 LTS ```*Kernel 4.15.0-112-generic, 4.15.0-167-generic*```
-	Ubuntu 21.04 and Ubuntu 20.04 LTS ```*Kernel 5.11*```
-	Debian 9 and 11
-	Debian 10 VM server ```*Kernel 4.19.0-18-amd64*```

**Part 2**

See below under "Compile and Build" section for known dependencies and packages that need to be installed. 

There are a few relevant directories here:

```userspace```
-	Contains the source that will eventually run as the Tuning Module

```cli```
-	Contains source for a HTTP client that is used as a CLI for sending instructions to
	or receiving information from the Tuning Module

```iter```
-	Contains source for a bpf object file that is used for observing number of retransmissions
	associated with a file transfer

**To Compile and Build, the following packages and libraries should be installed:**

- git
- GNU make
- clang
- gcc-multilib
- bpftool v6.7.0
- bpftrace
- librdkafka and libglib2.0-dev (used with Apache Kafka framework)
- pkg-config
- numactl, sysstat

In order to compile and work with the Tuning Module, do the following:
-	Initialize the git submodule ```libbpf```
	* The libbpf source is provided thru the git submodule. 
	* ```libbpf``` is a library that allows the bpf programs to run.
	* To use the module it must be initialized by running the following command in the Tuning Module's root directory:
```bash
git submodule update --init
```

-	Run ```make``` in ```userspace/``` to create Tuning Module's binaries
-	Run ```make``` in ```cli/``` to create a directory call ```tmp``` which contains the binary ```tuncli```
-	Run ```sudo make -f Makefile.iter``` in Tuning Module's root directory to create ```iter``` object file

**Make a zip package to install Tuning Module:**
-	go to ```packaging``` directory
-	type ```sh ./createpkg.sh``` to create two zip files, one of which is called ```SATuning_Module.zip```. 
-	```SATuning_Module.zip``` consist of files from the ```userspace```, ```cli``` and ```iter``` directory
-	create a temp directory, copy the ```SATuning_Module.zip``` file into it,  cd to it and type ```unzip *.zip```
-	after unziping, to install, type ```sudo sh ./install.sh```
-	follow the instructions to install the package 

**Note: Please see <install_directory>/readme.txt for information on how to start the Tuning Module**

**Some notes on mechanism of the Tuning Module**
-	Uses a HTTP client and server to dynamically change settings on the fly, for example:
	* The Debug level
	* Retransmission rate
	* Queue Occupancy Threshold
	* Has a Learning mode and a Tuning mode
-	When set to Tuning mode, will dynamically set the suggested tuning changes without manual intervention
	* Learning mode will only make suggestions which can be found in the log
	* Any changes to the system are automatically logged.
-	Uses "ethtool" to manipulate buffer rings of a network device in order to get better performance
-	If Queue Occupancy on one node gets above some threshold and the retransmission rate on the other node gets too high,
	the Tuning Module will lower the pacing (if in Tuning mode) or suggest some value to lower it to. In addition, it may
	also use the Hop Latency as a factor in deciding how to adjust the pacing if so desired. It will constantly adjust
	the pacing during the life of the transfer. The pacing will be set back to its original state after the transfer 
	is over.
-	Monitors RTT using bpf trace tools and also with the use of "ping".
-	Added the ability for clients (hpnssh, etc.) to connect to the Tuning Module in order to receive data
	for monitoring purposes.
