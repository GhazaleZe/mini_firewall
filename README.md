# Packet Droper LKM

[![N|Solid](https://cldup.com/dTxpPi9lDf.thumb.png)](https://nodesource.com/products/nsolid)

[![Build Status](https://travis-ci.org/joemccann/dillinger.svg?branch=master)](https://travis-ci.org/joemccann/dillinger)

### Note
>This project can be harmful for your machine ,you'd better try it on virtual machine or virtual box
# What does it do?
This loadable kernel module is  a simple firewall.
Get a balcklist or whitelist file from a user and drop wanted packets.A test file send a list to kernel by "write" ,kernel get the list and understand it's black or white.This module support differnt users.

# what does this project contian

  - an "firewall.c" file : a LKM code
  - a "test.c" file : test file for LKM
  - a "Makefile" 
  - a "config.txt" file :blacklist or whitelist of user

# firewall.c
-First I create device with the name "firewall"
- Important point here is that name of function is icmp_drop but don't care name it drop all packats from a blacklis ip or recive all packets from a whitelist ip.
- This module compare ips[0] whit blacklist and whitelist and then decide what to do.
- It has 2 hook which are used for white and black
- NF_DROP drop a packet and NF_ACCEPT accept packet
- In log prints ip and port of destination an source and it prints that packet is droped or accepted
- Variable in kernel must be static so that can't be change by other users
- Pay attention to your warnnig while copmilig ,they are important
- Pay attention to function "copy_from_user" which get data from user in "mydev_write",I got lots of "KILLED" error because of using other functions.
# test.c
- open users file and send to kernel 
- Note: after make, run it with sudo 
> sudo ./test
# Makefile
- compile LKM and test files and make .ko (this file can be loaded to kernel)
# config.txt
- start with blacklist or withlist and continue whit IPs.
### How to add module to kernel and run test
```sh
$ make
$ sudo insmod firewall.ko
$ lsmod 
$ sudo ./test
```
> now go to log file and monitor mini firwall module(e.g ping from black list)
>By lsmod check module is added or not
>It was told in our TA class you may need to insmod wiht -f but that was not needed for main.
 ### Remove module from kernel and clean
 ```sh
$ sudo rmmod firewall.ko
$ make clean
```
# Resources
http://derekmolloy.ie/writing-a-linux-kernel-module-part-2-a-character-device/[f1]
http://derekmolloy.ie/writing-a-linux-kernel-module-part-2-a-character-device/[f1]
https://github.com/payamnaghdy/ICMPdropko[f1]
https://netfilter.org/[f1]
https://focusvirtualization.blogspot.com/2017/09/protocol-stack-69-print-ip-and-port.html[f1]
https://stackoverflow.com/questions/9296835/convert-source-ip-address-from-struct-iphdr-to-string-equivalent-using-linux-ne[f1]
And TA class
# Support
Ghazale Zehtab 
Reach out to me at ghazalze@yahoo.com
