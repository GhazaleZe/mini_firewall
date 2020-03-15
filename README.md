# Packet Dropper LKM

## Note
>This project can be harmful to your machine, you'd better try it on a virtual machine or virtual box
## What does it do?
This loadable kernel module is a simple firewall.
Get a blacklist or whitelist file from a user and drop wanted packets. A test file sends a list to the kernel by "write", the kernel gets the list and understand it's black or white. This module supports different users.

## what does this project contain

  - an "firewall.c" file : a LKM code
  - a "test.c" file : test file for LKM
  - a "Makefile" 
  - a "config.txt" file :blacklist or whitelist of user

## firewall.c
-First I create a device with the name "firewall"
- An important point here is that the name of the function is icmp_drop but don't care name it drop all packets from a blacklisted IP or receive all packets from a whitelist IP.
- This module compares ips[0] whit blacklist and whitelist and then decide what to do.
- It has 2 hooks which are used for white and black
- NF_DROP drop a packet and NF_ACCEPT accept the packet
- In log prints IP and port of destination, an source and it prints that packet is dropped or accepted
- The variable in kernel must be static so that can't be changed by other users
- Pay attention to your warning while compiling, they are important
- Pay attention to function "copy_from_user" which gets data from the user in "mydev_write", I got lots of "KILLED" error because of using other functions.
## test.c
- open users file and send to the kernel 
- Note: after make, run it with Sudo 
> sudo ./test
## Makefile
- compile LKM and test files and make .ko (this file can be loaded to kernel)
## config.txt
- start with blacklist or whitelist and continue whit IPs.
## How to add the module to the kernel and run test
```sh
$ make
$ sudo insmod firewall.ko
$ lsmod 
$ sudo ./test
```
> now go to the log file and monitor mini firewall module(e.g ping from the blacklist)
>By lsmod check module is added or not
>It was told in our TA class you may need to insmod with -f but that was not needed for main.
 ## Remove the module from kernel and clean
 ```sh
$ sudo rmmod firewall.ko
$ make clean
```
## Resources
http://derekmolloy.ie/writing-a-linux-kernel-module-part-2-a-character-device/[f1]
http://derekmolloy.ie/writing-a-linux-kernel-module-part-2-a-character-device/[f1]
https://github.com/payamnaghdy/ICMPdropko[f1]
https://netfilter.org/[f1]
https://focusvirtualization.blogspot.com/2017/09/protocol-stack-69-print-ip-and-port.html[f1]
https://stackoverflow.com/questions/9296835/convert-source-ip-address-from-struct-iphdr-to-string-equivalent-using-linux-ne[f1]
And the TA class
### Support
Ghazale Zehtab 
Reach out to me at ghazalze@yahoo.com :smile:
