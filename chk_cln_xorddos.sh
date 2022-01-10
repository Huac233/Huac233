#!/bin/bash
#-----------------------------------------------------------------------------------------
# Filename:             chk_cln_xorddos.sh
# Version:              1.0
# Date:                 2019-10-17
# Author:               binlmmhc
# Description:          Kill script for XorDDos virus                  
#-----------------------------------------------------------------------------------------

starttime=$(date)

#create a sangfor backup directory
if [ ! -d "/tmp/sangfor/" ];then
    mkdir "/tmp/sangfor/"
fi

if [ ! -d "/tmp/sangfor/$starttime" ];then
    mkdir "/tmp/sangfor/$starttime"
fi

echo "[*]Begin scanning time:"$starttime >> "/tmp/sangfor/$starttime/log.txt"
echo "[*]=============All remove files save at /tmp/sangfor/$starttime/================"
echo "[*]=============All remove files save at /tmp/sangfor/$starttime/================" >> "/tmp/sangfor/$starttime/log.txt"

#check crontab list with */3 * * * * root /etc/cron.hourly/gcc*.sh
echo "[*]Start checking /etc/crontab . . ." >> "/tmp/sangfor/$starttime/log.txt"
malicious_crontab=$(sed -n '/\*\/3 \* \* \* \* root \/etc\/cron\.hourly\//p' /etc/crontab)
if [ "$malicious_crontab" ];then
    echo "[+]Found malicious crontab:" >> "/tmp/sangfor/$starttime/log.txt"
    echo "$malicious_crontab" >> "/tmp/sangfor/$starttime/log.txt"
    echo "[+]Delete malicious crontab." >> "/tmp/sangfor/$starttime/log.txt"
fi
echo "" >> "/tmp/sangfor/$starttime/log.txt"

#check cron.hourly malicious files
echo "[*]Start checking /etc/cron.hourly/ . . ." >> "/tmp/sangfor/$starttime/log.txt"
malicious_cron_files=("udev.sh" "gcc.sh" "gcc4.sh" "cron.sh")
cron_hourly_files=$(ls /etc/cron.hourly/)
for cron_hour_file in ${cron_hourly_files[@]};do
    for malicious_cron_file in ${malicious_cron_files[@]};do
        if [ $cron_hour_file == $malicious_cron_file ];then
            echo "[+]Found malicious cron hourly file:/etc/cron.hourly/$cron_hour_file" >> "/tmp/sangfor/$starttime/log.txt"
            cp "/etc/cron.hourly/$cron_hour_file" "/tmp/sangfor/$starttime/"
            sed -i "/\*\/3 \* \* \* \* root \/etc\/cron\.hourly\/$cron_hour_file"/d /etc/crontab
            #backup /etc/crontab file
            cp "/etc/crontab" "/tmp/sangfor/$starttime/"
            rm -f "/etc/cron.hourly/$cron_hour_file"
            echo "[+]Delete malicious cron hourly file:/etc/cron.hourly/$cron_hour_file" >> "/tmp/sangfor/$starttime/log.txt"
            #then we need lock the crontab file
            chattr +i "/etc/crontab"
            chattr +i "/etc/cron.hourly/"
        fi
    done
done
echo "" >> "/tmp/sangfor/$starttime/log.txt"

#check xorddos source files in /lib/udev/ and /lib
echo "[*]Start checking /lib/udev /lib . . ." >> "/tmp/sangfor/$starttime/log.txt"
malicious_libudev_files=("udev" "debug")
malicious_lib_files=("libgcc4.so" "libgcc4.4.so" "libudev.so" "libudev.so.6" "libudev4.so" "libdev4.so.6" )
lib_udev_files=$(ls /lib/udev/)
for lib_udev_file in ${lib_udev_files[@]};do
    for malicious_libudev_file in ${malicious_libudev_files[@]};do
        if [ $lib_udev_file == $malicious_libudev_file ];then
            echo "[+]Found malicious file:/lib/udev/$lib_udev_file" >> "/tmp/sangfor/$starttime/log.txt"
            cp "/lib/udev/$lib_udev_file" "/tmp/sangfor/$starttime/"
            rm -f "/lib/udev/$lib_udev_file"
            echo "[+]Delete malicious file:/lib/udev/$lib_udev_file" >> "/tmp/sangfor/$starttime/log.txt"
            #then we need lock the /lib/udev directory
            chattr +i "/lib/udev/"
        fi
    done
done
lib_files=$(ls /lib/)
for lib_file in ${lib_files[@]};do
    for malicious_lib_file in ${malicious_lib_files[@]};do
        if [ $lib_file == $malicious_lib_file ];then
            echo "[+]Found malicious file:/lib/$lib_file" >> "/tmp/sangfor/$starttime/log.txt"
            cp "/lib/$lib_file" "/tmp/sangfor/$starttime/"
            rm -f "/lib/$lib_file"
            echo "[+]Delete malicious file:/lib/$lib_file" >> "/tmp/sangfor/$starttime/log.txt"
            chattr +i "/lib/"
        fi
    done
done
echo "" >> "/tmp/sangfor/$starttime/log.txt"

#check pid file in /var/run
echo "[*]Start checking /var/run . . ." >> "/tmp/sangfor/$starttime/log.txt"
malicious_var_run_files=("udev.pid" "gcc.pid" "gcc4.pid" "sftp.pid")
var_run_files=$(ls /var/run/)
for var_run_file in ${var_run_files[@]};do
    for malicious_var_run_file in ${malicious_var_run_files[@]};do
        if [ $var_run_file == $malicious_var_run_file ];then
            echo "[+]Found malicious file:/var/run/$var_run_file" >> "/tmp/sangfor/$starttime/log.txt"
            cp "/var/run/$var_run_file" "/tmp/sangfor/$starttime/"
            rm -f "/var/run/$var_run_file"
            echo "[+]Delete malicious file:/var/run/$var_run_file" >> "/tmp/sangfor/$starttime/log.txt"
            chattr +i "/var/run/"
        fi
    done
done
echo "" >> "/tmp/sangfor/$starttime/log.txt"

#actually, we can't clean it more elegant(not in bash script) due to data problems
#check rc*.d with S90 in rc0-5.d and K90 in rc6.d
#check rc0-5.d
rc_directorys=("/etc/rc0.d/" "/etc/rc1.d/" "/etc/rc2.d/" "/etc/rc3.d/" "/etc/rc4.d/" "/etc/rc5.d/" "/etc/rc6.d/")
for rc_dir in ${rc_directorys[@]};do
    cd $rc_dir
    echo "[*]Start checking S90* in "$rc_dir >> "/tmp/sangfor/$starttime/log.txt"
    malicious_start_links=$(ls -al $rc_dir | grep "S90[a-z]\{10,10\}" | awk '{print $9}')
    if [ "$malicious_start_links" ];then
        for malicious_start_link in ${malicious_start_links[@]};do
            link_start_file=$(readlink "$rc_dir$malicious_start_link")
            if [ -f "$link_start_file" ];then
                check1=$(sed -n "/# chkconfig: 12345 90 90"/p "$link_start_file")
                check2=$(sed -n "/### BEGIN INIT INFO"/p "$link_start_file")
                check3=$(sed -n "/# Default-Start:	1 2 3 4 5"/p "$link_start_file")
                malicious_elf_path=$(sed -n "/	\/usr\/bin\/[a-z]\{10,10\}"/p "$link_start_file")
                if [ "$check1" -a "$check2" -a "$check3" -a "$malicious_elf_path" ];then
                    ls -al "$rc_dir$malicious_start_link" | grep "S90[a-z]\{10,10\}" | awk '{print $9$10$11}' >> "/tmp/sangfor/$starttime/log.txt"
                    #backup file
                    cp "$rc_dir$malicious_start_link" "/tmp/sangfor/$starttime/"
                    #unlink malicious link
                    echo "[+]Unlink malicious link file $rc_dir$malicious_start_link" >> "/tmp/sangfor/$starttime/log.txt"
                    unlink "$rc_dir$malicious_start_link"
                fi
            fi
        done
    fi

    echo "[*]Start checking K90* in "$rc_dir >> "/tmp/sangfor/$starttime/log.txt"
    malicious_stop_links=$(ls -al $rc_dir | grep "K90[a-z]\{10,10\}" | awk '{print $9}')
    if [ "$malicious_stop_links" ];then
        for malicious_stop_link in ${malicious_stop_links[@]};do
            link_stop_file=$(readlink "$rc_dir$malicious_stop_link")
            if [ -f "$link_stop_file" ];then
                check1=$(sed -n "/# chkconfig: 12345 90 90"/p "$link_stop_file")
                check2=$(sed -n "/### BEGIN INIT INFO"/p "$link_stop_file")
                check3=$(sed -n "/# Default-Start:	1 2 3 4 5"/p "$link_stop_file")
                malicious_elf_path=$(sed -n "/	\/usr\/bin\/[a-z]\{10,10\}"/p "$link_stop_file")
                if [ "$check1" -a "$check2" -a "$check3" -a "$malicious_elf_path" ];then
                    ls -al "$rc_dir$malicious_stop_link" | grep "K90[a-z]\{10,10\}" | awk '{print $9$10$11}' >> "/tmp/sangfor/$starttime/log.txt"
                    #backup file
                    cp "$rc_dir$malicious_stop_link" "/tmp/sangfor/$starttime/"
                    #unlink malicious link
                    echo "[+]Unlink malicious link file $rc_dir$malicious_stop_link" >> "/tmp/sangfor/$starttime/log.txt"
                    unlink "$rc_dir$malicious_stop_link"
                fi
            fi
        done
    fi
    echo "" >> "/tmp/sangfor/$starttime/log.txt"
done


#check /etc/init.d/ malicious file
malicious_init_files=$(ls -al /etc/init.d/ | grep "[a-z]\{10,10\}" | awk '{print $9}')
if [ "$malicious_init_files" ];then
    #chanage the work directory
    cd /etc/init.d/
    if [ ! -d "/tmp/sangfor/$starttime/init.d" ];then
        mkdir "/tmp/sangfor/$starttime/init.d"
    fi

    for malicious_init_file in ${malicious_init_files[@]};do
        check1=$(sed -n "/# chkconfig: 12345 90 90"/p "$malicious_init_file")
        check2=$(sed -n "/### BEGIN INIT INFO"/p "$malicious_init_file")
        check3=$(sed -n "/# Default-Start:	1 2 3 4 5"/p "$malicious_init_file")

        if [ "$check1" -a "$check2" -a "$check3" ];then
            malicious_elf_path=$(sed -n "/[a-z/]\{15,19\}"/p "$malicious_init_file" | sort | uniq | tr -d [:space:])
        fi

        if [ "$check1" -a "$check2" -a "$check3" -a "$malicious_elf_path" ];then
            mkdir -p "/tmp/sangfor/$starttime$malicious_elf_path"
            echo "[+]Found malicious init.d file /etc/init.d/$malicious_init_file" >> "/tmp/sangfor/$starttime/log.txt"
            #backup file
            cp "/etc/init.d/$malicious_init_file" "/tmp/sangfor/$starttime/init.d/"
            cp "$malicious_elf_path" "/tmp/sangfor/$starttime$malicious_elf_path"

            #delete malicious file
            echo "[+]Delete malicious init.d file /etc/init.d/$malicious_init_file" >> "/tmp/sangfor/$starttime/log.txt"
            rm -f "/etc/init.d/$malicious_init_file"

            if [ -f "$malicious_elf_path" ];then
                echo "[+]Delete malicious elf file $malicious_elf_path" >> "/tmp/sangfor/$starttime/log.txt"
                rm -f "$malicious_elf_path"
            fi

            #kill malicious process
            #malicious_pid=$(pidof "/usr/bin/$malicious_init_file")
            #if [ "$malicious_pid" ];then
            #    echo "[+]Found & kill malicious process with pid $malicious_pid" >> "/tmp/sangfor/$starttime/log.txt"
            #    kill -9 "$malicious_pid"
            #fi
        fi
    done
    chattr +i "/usr/bin/"
    chattr +i "/bin/"
    chattr +i "/tmp/"
fi

#we need sleep 10s, and then recovery everything
echo "[*]Please wait 10s . . ."
sleep 10
chattr -i "/etc/crontab"
chattr -i "/etc/cron.hourly/"
chattr -i "/lib/"
chattr -i "/lib/udev/"
chattr -i "/var/run/"
chattr -i "/usr/bin/"
chattr -i "/bin/"
chattr -i "/tmp/"


endtime=$(date)
echo "[+]check & clean XorDDos finished:$endtime" >> "/tmp/sangfor/$starttime/log.txt"
chmod 666 "/tmp/sangfor/$starttime/"
cat "/tmp/sangfor/$starttime/log.txt"