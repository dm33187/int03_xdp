#!/bin/sh
#
# dtnmenu - scripts launched at runnig of dtn_tune
# to do routine admintstative tasks
#

# when viewing this script, set tabstops to 4

# The main script is at the bottom, after all support functions are defined

return='Return to previous menu'
select_choice='Enter option : '

#
# Get a yes or no answer from the user.  Argument 1 is prompt, 2 is default.
#
yorn()
{
        if [ "$2" = "" ] ; then
                prompt="$1? "
        else
                prompt="$1 [$2]? "
        fi

        while true ; do
                echo "$prompt\c"
                read input
                parsed=$input

                if [ "$parsed" = "" ] ; then
                        answer=$2
                else
                        answer=$input
                fi

                case $answer in
                        [yY]|[yY][eE]|[yY][eE][sS])
                                yorn_rsp=0
                                return 0 ; break ;;
                        [nN]|[nN][oO])
                                yorn_rsp=1
                                return 1 ; break ;;
                        *)
                                echo "Please answer yes or no."
                esac
        done
}

Get_OS_Type()
{
	OS="`uname -s`"
	case  $OS in
		"Linux")
			OS_TYPE="linux"
			MAJOR_OS_REL="`uname -r | cut -f1 -d'.'`"
			MINOR_OS_REL="`uname -r | cut -f2 -d'.'`"
			break;;
		*)
			OS_TYPE="XXX"
			MAJOR_OS_REL="YYY"
			MINOR_OS_REL="ZZZ"
			break;;
	esac
}

Get_OS_Type
#if [ "$OS_TYPE" = "linux" ]
#then
#	alias echo='echo -e'
#fi

Check_OS_Type()
{
	case  $OS_TYPE in
		"linux")
			break;;
		*)
			echo "Only the Linux operating system is supported."
			exit 1 ;;
	esac
}

Check_And_Remove_Earlier_Versions()
{
    if [ $# -ge 1 ]
    then
        Rel2Check=$1
        CheckSupplied=YES
    else
        Rel2Check=
        CheckSupplied=NO
    fi

    case $OS_TYPE in
        linux)
            rmpkg="rpm -e"
            lspkg="rpm -q"
            ;;
    esac

    InstallList=
    PackagesToRemove=
        for Pkg in $CheckList
    do
        if [ $CheckSupplied = NO ]
        then
            Rel2Check=`cat ./$OS_TYPE/$Pkg/info | cut -d',' -f2`
        fi
        Get_Installed_Version $Pkg
        if [ "$CurVers" ]
        then
            PackagesToRemove="$PackagesToRemove $Pkg"
        fi
        InstallList="$Pkg $InstallList"
    done

    if [ "$PackagesToRemove" ]
    then
        echo "There are earlier/same/newer versions of some of the"
        echo "packages that your have selected that are already installed:"
        for Pkg in $PackagesToRemove
        do
            Get_Installed_Version $Pkg
            echo "     $Pkg $CurVers"
        done
        echo "These installed packages must be removed prior to installing"
        echo "version $Rel2Check."
        echo
        yorn "Do you wish to remove these packages? (Yes/No)" "N"
        [ $? -ne 0 ] && exit 1
        for Pkg in $PackagesToRemove
        do
            $rmpkg $Pkg
            if $lspkg $Pkg > /dev/null 2>&1
            then
                echo " Component $Pkg not removed!!."
                echo " <Enter> to continue: \c"
                read input
                exit 1
            fi
            if [ $OS_TYPE = solaris ]
            then
                PatchesToRemove=`ls -1 /var/sadm/patch | grep -i $Pkg`
                if [ "$PatchesToRemove.x" != ".x" ]
                then
                (
                    cd /var/sadm/patch; rm -rf $PatchesToRemove
                )
                fi
            fi
        done
    fi
}

clear_screen()
{
	tput clear
}

enter_to_continue()
{
	printf '\n\t%s' "Hit ENTER to continue: "
	read junk
}

copy_files()
{
	mv tuncli $pathname
	mv user_dtn $pathname
	mv userdtn_adm $pathname
	mv common_irq_affinity.sh $pathname
	mv set_irq_affinity.sh $pathname
	mv help_dtn.sh $pathname
	mv user_config.txt $pathname
	mv user_menu.sh $pathname
	mv gdv_100.sh $pathname
	mv gdv.sh $pathname
	mv readme.txt $pathname
	mv plotgraph.py $pathname
	mv conv_csv_to_json.py $pathname
}

default_dir="/usr/tuningmod"
install_tm()
{
logcount=
	clear_screen
	printf '\n%s' "Welcome to the Tuning Module installation procedure."
	printf '\n%s' "Please see the readme.txt file for important information "
	printf '\n%s\n' "after installing this package..."
	printf '\n%s' "NOTE: The user_config.txt file contains default behavior for"
	printf '\n%s' "the Tuning module. You may wish to configure it first before"
	printf '\n%s\n' "starting the Tuning Module..."
	sleep 2
	printf '\n###%s\n\n' "Preparing to install the Tuning Module..."
	sleep 1
	echo "This product normally installs into the ${default_dir} directory."
	echo "If you would like to install to a different directory you can enter"
	echo "that directory name now or press <ENTER> to continue."
	echo ""
	read pathname

	if [ "$pathname" = "" ]
	then
		pathname=${default_dir}
	fi
	
	if [ ! -d ${pathname} ]
	then
		mkdir -p ${pathname}
		copy_files
		echo "The Tuning Module product has been installed in ${pathname}"
		echo "Press <ENTER> to exit installation program."
		enter_to_continue
		exit 0
	else
		echo "Directory ${pathname} already exists..."
		yorn "Are you sure you wish to install in the ${pathname} directory? (Yes/No)" "Y"	
		if [ $? -ne 0 ] 
		then
			echo "Installation of the Tuning Module product will not occur."
		else
			if [ -f ${pathname}/user_config.txt ]	#save off config just in case
			then
				echo "Saving ${pathname}/user_config.txt ${pathname}/user_config.txt.$$"
				cp ${pathname}/user_config.txt ${pathname}/user_config.txt.$$
			fi
			copy_files
			echo "The Tuning Module product has been installed in ${pathname}"
			echo "Press <ENTER> to exit installation program."
			enter_to_continue
			exit 0
		fi

	fi

	enter_to_continue
	return 0
}

UsageString="\
Usage:\\t[sudo ./dtnmenu]\\t\\t- Configure Tunables \\n\
\\t[sudo ./dtnmenu <device>]\\t- Configure Tunables and Device"

# main execution thread

if [ `id -u` = 0 ]
then
	:
else
	printf '\n***%s\n' "You must be superuser to install the Tuning Module..."
	printf '***%s\n\n' "Exiting..."
	exit 1
fi

Check_OS_Type
Check_And_Remove_Earlier_Versions
repeat_main=1
while  [ $repeat_main = 1 ]
do
	clear_screen
	printf '\n\n\t%s\n\n\t%s\n\t%s\n\t%s\n\t%s' \
		"Tuning Module Installation" \
		"1) Install Tuning Module package" \
		"2) Escape to Linux Shell" \
		"3) Exit" \
		"$select_choice"

	read answer
	case "$answer" in
		1)
			install_tm "$1"
			;;
		2)
			clear_screen
			$SHELL
			clear_screen
			enter_to_continue
			;;
		q|3)
			clear_screen
			exit 0
			;;
		*)
			;;
	esac
done
echo
