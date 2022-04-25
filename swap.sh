#!/bin/bash

############################################################
#  Azure设置虚拟内存
#  脚本链接：https://huacha.ml/swap.sh
############################################################


# 检查是否是root账户
check_root(){
	if [[ $EUID != 0 ]];then
		echo -e " 当前非ROOT账号，无法继续操作。\n 请更换ROOT账号登录服务器。 " 
		exit 1
	else
		echo -e "\n 管理员权限检查通过 "
	fi
}


# 设置交换分区
set_swap(){
	echo -e " 开始设置虚拟内存容量，建议为内存的2倍。但过大的交换分区会影响磁盘IO，请悉知。 "
	read -p " 请输入需要添加的虚拟内存容量，单位MB: " swap_capacity
	check_root
	sed -i "s/ResourceDisk.Format=n/ResourceDisk.Format=y/g" /etc/waagent.conf
	sed -i "s/ResourceDisk.EnableSwap=n/ResourceDisk.EnableSwap=y/g" /etc/waagent.conf
	sed -i "s/ResourceDisk.SwapSizeMB=0/ResourceDisk.SwapSizeMB=${swapsize}/g" /etc/waagent.conf
	service waagent restart
	swapon -s
}

############################################################
 
echo -e " -------------------------"
echo -e " Azure设置虚拟内存"
echo -e " 版本：1.0"
echo -e " -------------------------"
echo -e " 1、添加虚拟内存"
echo -e " -------------------------"
 
read -p " 请输入要执行的操作:" num
case "$num" in
1)
	set_swap
	;;
esac
 
############################################################
