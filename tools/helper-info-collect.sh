#!/bin/bash
# Collection items for the .py of the same name in this directory (read-only by convention).
#
# This file is never run as a whole.  The .py of the same name reads it, picks the items you ask
# for, and sends only those to each switch (ssh ... bash -s); nothing is written on the switch.
#
# Two levels: a group holds items.  Select a whole group (`firmware`) or one item
# (`firmware.ssd`), several separated by commas; `--list` shows everything below.
#
#   #@group <group-name>  <description>
#   #@item  <item-name>   <description>
#   #@family ib,nvl            optional: device families the item applies to (ib, eth, nvl);
#                              default all.  Other devices skip the item and say so.
#   #@pick  <regex>            optional: the value shown in the summary is the first match's
#                              group 1 (or whole match); default the first non-empty line.
#   #@compare <csv-column> <mac|text>
#                              optional: compare the picked value with that inventory column.
#   <shell commands ...>       until the next #@item / #@group or the end of the file.
#
# Names: letters, digits, '-' and '_'.  Keep items read-only: they run as the login user.
# To add your own: append a #@group (or reuse one) and #@item blocks in the same format.

# Run directly it only prints usage: the items below are for the collector, not for this host.
case "${1:-}" in
    -h|--help) echo "usage: python3 <same name>.py --list   (this file only holds the collection items)"; exit 0 ;;
    *) echo "usage: python3 <same name>.py --list   (this file only holds the collection items)" >&2; exit 2 ;;
esac

#@group identity  设备身份
#@item  eth0-mac  eth0 MAC（身份核对用，与清单 eth0_mac 比对）
#@compare eth0_mac mac
cat /sys/class/net/eth0/address

#@item  hostname  交换机报的主机名
#@compare hostname text
hostname

#@item  platform  型号、system-type、序列号等（sw-info 第 1 条）
#@pick  ^\s*system-type\s+(\S+)
nv show platform

#@group version  版本与固件
#@item  os  当前运行的系统版本
#@family ib,nvl
#@pick  ^\s*image\s+(\S+)
nv show system version

#@item  image  两个分区装的版本、当前和下次启动分区
#@family ib,nvl
#@pick  ^current\s+(\S+)
nv show system image

#@item  firmware  ASIC/BIOS/CPLD/SSD 实际版本
#@family ib,nvl
#@pick  ^BIOS\s+(\S+)
nv show platform firmware

#@item  ssd  SSD 固件版本
#@family ib,nvl
#@pick  ^SSD\s+(\S+)
nv show platform firmware | awk 'NR<=2 || $1=="SSD"'

#@item  bios  BIOS 版本
#@family ib,nvl
#@pick  ^BIOS\s+(\S+)
nv show platform firmware | awk 'NR<=2 || $1=="BIOS"'

#@item  cumulus  Cumulus 系统版本
#@family eth
#@pick  ^\s*build\s+(.+)$
nv show system

#@group health  健康与硬件
#@item  system  交换机自己的健康检查
#@pick  ^\s*status\s+(\S+)
nv show system health

#@item  inventory  PSU/风扇等部件在位与状态
nv show platform inventory

#@item  temperature  温度传感器
nv show platform environment temperature

#@item  disk  登录用户家目录剩余空间（放升级镜像用）
#@pick  (\d+%)
df -Ph "$HOME" | tail -1

#@item  staged  家目录下已放好的升级包（第一行是个数）
#@pick  ^(\d+)$
ls -l "$HOME"/*.bin "$HOME"/*.cab "$HOME"/*.vme 2>/dev/null | wc -l; ls -l "$HOME"/*.bin "$HOME"/*.cab "$HOME"/*.vme 2>/dev/null

#@group system  系统资源与时间
#@item  uptime  运行时间和负载
uptime

#@item  time  时间、时区和 NTP 同步
#@pick  synchronized:\s*(\S+)
timedatectl

#@item  filesystems  全部文件系统用量
df -PT

#@item  memory  内存
free -b

#@item  cpu  CPU 与进程快照
top -bn2 -d 1

#@group config  配置
#@item  pending  未提交的配置改动（为空说明没有 pending）
#@pick  ^(.+)$
nv config diff 2>&1 | head -200

#@item  history  最近几次配置 apply
nv config history 2>&1 | head -20

#@item  applied  当前生效的完整配置（输出较大）
nv config show

#@group link  端口与光模块
#@item  interfaces  全部端口状态（输出较大）
nv show interface

#@item  transceiver  光模块详情（输出很大）
nv show platform transceiver detail

#@group ib  IB 专有
#@item  device  IB 设备（ASIC）
#@family ib
nv show ib device

#@group nvl  NVLink 专有
#@item  device  NVLink 设备
#@family nvl
nv show nvlink device

#@item  port  NVLink 端口
#@family nvl
nv show nvlink port

#@group eth  以太网专有
#@item  clag  MLAG 状态
#@family eth
clagctl

#@item  evpn-esi  EVPN multihoming ESI
#@family eth
nv show evpn multihoming esi

#@item  bgp  BGP 邻居
#@family eth
nv show vrf default router bgp neighbor
