# Relates to the ongoing XDP/eBPF project at FIU
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
-	type ```sh ./createpkg.sh``` to create a zip file called dtntune.zip
-	```dtntune.zip``` consist of files from the ```assess-tuning``` directory
-	create a temp directory, copy the zip file into it, and type unzip *.zip
-	after unziping, run the commands as mentioned above "for a quick test"

**Note: Please see packaging/readme.txt for additional instructions**
-	Basically, there are three files of interest
	*	```user_config.txt```, ```gdv.sh``` and ```/tmp/tuningLog```
	*	```user_config.txt``` contains well known values to control how the application operates
	*	```gdv.sh``` conatins the settings that we are currently interested in
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

There is one known dependency, apart from compilation requirements at this point. 
-	This package requires the 'bpftrace' utility to be installed on the system

There are a few relevant directories here:

```userspace```
-	Contains the source that will eventually run as the Tuning Module

```cli```
-	Contains source for a HTTP client that is used as a CLI for sending instructions to
	or receiving information from the Tuning Module

**To Compile:**

In order to compile and work with the Tuning Module, do the following:
-	Initialize the git submodule ```libbpf```
	* The libbpf source is provided thru the git submodule. 
	* ```libbpf``` is a library that allows the bpf programs to run.
	* To use the module it must be initialized by running the following commands in the Tuning Module
	root directory:
		*	```git submodule init```
		*	```git submodule update```

-	Run ```make``` in ```userspace/``` and start the Tuning Module eg. ```sudo ./user_dtn -d enp6s0```
	* 	```/tmp/tuningLog``` will contain all the relevant output 
-	Run ```make``` in ```cli/```. This will create a directory call ```tmp``` which contains the binary ```tuncli```.
	Run the binary and follow the instructions onscreen on how to use it
