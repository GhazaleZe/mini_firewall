#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/string.h>
#include <linux/init.h>           // Macros used to mark up functions e.g. __init __exit
#include <linux/module.h>         // Core header for loading LKMs into the kernel
#include <linux/device.h>         // Header to support the kernel Driver Model
#include <linux/kernel.h>         // Contains types, macros, functions for the kernel
#include <linux/fs.h>             // Header for the Linux file system support
#include <linux/uaccess.h>          // Required for the copy to user function
#include <uapi/linux/tcp.h>
#include <uapi/linux/ip.h>
#define  DEVICE_NAME "firewall"    ///< The device will appear at /dev/ebbchar using this value
#define  CLASS_NAME  "fireclass"        ///< The device class -- this is a character device driver

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ghazale Zehtab");
MODULE_DESCRIPTION("A simple module for droping packet.");
MODULE_VERSION("0.1");

static char  ips[100][256];
static int   i;
static int    majorNumber;                  ///< Stores the device number -- determined automatically
static struct class*  fireclass  = NULL; ///< The device-driver class struct pointer
static struct device* firewall = NULL;
static int k=0;
static int BORW;


static int     mydev_open(struct inode *, struct file *);
static ssize_t mydev_read(struct file *, char *, size_t, loff_t *);
static int     mydev_release(struct inode *, struct file *);

static ssize_t mydev_write(struct file *, const char *, size_t, loff_t *);

static struct file_operations fops =
{
   .open = mydev_open,
   .read = mydev_read,
   .write = mydev_write,
   .release = mydev_release,
};


//**************************************************************************************

unsigned int w_hook(unsigned int hooknum, struct sk_buff *skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int(*okfn)(struct sk_buff *));
unsigned int b_hook(unsigned int hooknum, struct sk_buff *skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int(*okfn)(struct sk_buff *));
//*******************************************************************
static struct nf_hook_ops w_drop __read_mostly = {
        .pf = NFPROTO_IPV4,
        .priority = NF_IP_PRI_FIRST,
        .hooknum =NF_INET_LOCAL_IN,
        .hook = (nf_hookfn *) w_hook
};
//***********************************************************
static struct nf_hook_ops b_drop __read_mostly = {
        .pf = NFPROTO_IPV4,
        .priority = NF_IP_PRI_FIRST,
        .hooknum =NF_INET_LOCAL_IN,
        .hook = (nf_hookfn *) b_hook
};
//********************************************************************************
static int __init icmp_drop_init(void)
{
  printk(KERN_INFO "firewall: Initializing the firewall LKM\n");


  majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
  if (majorNumber<0){
     printk(KERN_ALERT "firewall failed to register a major number\n");
     return majorNumber;
  }
  printk(KERN_INFO "firewall: registered correctly with major number %d\n", majorNumber);

  // Register the device class
  fireclass = class_create(THIS_MODULE, CLASS_NAME);
  if (IS_ERR(fireclass)){                // Check for error and clean up if there is
     unregister_chrdev(majorNumber, DEVICE_NAME);
     printk(KERN_ALERT "Failed to register device class\n");
     return PTR_ERR(fireclass);          // Correct way to return an error on a pointer
  }
  printk(KERN_INFO "firewall: device class registered correctly\n");

  // Register the device driver
  firewall = device_create(fireclass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
  if (IS_ERR(firewall)){               // Clean up if there is an error
     class_destroy(fireclass);           // Repeated code but the alternative is goto statements
     unregister_chrdev(majorNumber, DEVICE_NAME);
     printk(KERN_ALERT "Failed to create the device\n");
     return PTR_ERR(firewall);
  }
  printk(KERN_INFO "firewall: device class created correctly\n"); // Made it! device was initialized




    printk(KERN_INFO "packet droper loaded\n");
       //int ret;
    //ret= nf_register_net_hook(&init_net,&icmp_drop); /*Record in net filtering */
    //if(ret)
        //printk(KERN_INFO "FAILED");
    return  0;

}
//*************************************************************************************************************
static void __exit  icmp_drop_exit(void)
{
	device_destroy(fireclass, MKDEV(majorNumber, 0));     // remove the device
	class_unregister(fireclass);                          // unregister the device class
	class_destroy(fireclass);                             // remove the device class
	unregister_chrdev(majorNumber, DEVICE_NAME);             // unregister the major number
    printk(KERN_INFO "Bye! drop module unloaded\n");
    nf_unregister_net_hook(&init_net,&w_drop); /*UnRecord in net filtering */
    nf_unregister_net_hook(&init_net,&b_drop);
}

//****************************************************************************************
static int mydev_open(struct inode *inodep, struct file *filep){
   i=0;
   printk(KERN_INFO "firewall: Device has been opened \n");
   return 0;
}

//**********************************************************************************************
static ssize_t mydev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){

   	copy_from_user(ips[i], buffer,256);
   	printk(KERN_INFO "ips: %s \n", ips[i]);
   	i++;
   	if(strncmp(ips[0],"wh",2)==0){
   		BORW=0;
   		int rete1 = nf_register_net_hook(&init_net, &w_drop);
       	if(rete1){
         	printk(KERN_ALERT "FAILED\n");
       	}
   		printk(KERN_INFO "white list\n");
   	}
   	else if(strncmp(ips[0],"bl",2)==0){
   		BORW=1;
   		int rete = nf_register_net_hook(&init_net, &b_drop);
        if(rete){
        	printk(KERN_ALERT "FAILED\n");
        }
   		printk(KERN_INFO "block list\n");
   	}
   	else{
   		BORW=1;
   		int rete = nf_register_net_hook(&init_net, &b_drop);
        if(rete){
        	printk(KERN_ALERT "FAILED\n");
        }
   		printk(KERN_INFO "defult is block list\n");
   	}
    return len;
}
//***************************************************************************************
static ssize_t mydev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){

    printk(KERN_INFO "send is not supported");
    return 0;
}

//***************************************************************************************
static int mydev_release(struct inode *inodep, struct file *filep){
   printk(KERN_INFO "firewall: Device successfully closed\n");
   return 0;
}

//*********************************************************************************
unsigned int b_hook(unsigned int hooknum, struct sk_buff *skb,

        const struct net_device *in, const struct net_device *out,

        int(*okfn)(struct sk_buff *))

{		
		struct udphdr *udp_header;
		struct tcphdr *tcp_header;
		unsigned int dest_port, source_port;
		struct sk_buff *sock_buff;
		struct iphdr *ip_header;
        sock_buff = skb;
        ip_header = (struct iphdr *)skb_network_header(sock_buff);
        static char  myipb[256];
        ip_header = (struct iphdr *)skb_network_header(sock_buff);
        if(!sock_buff) { 
        	return NF_DROP;
        }
        snprintf(myipb, 16, "%pI4", &ip_header->saddr);
        if (ip_header->protocol == 17) {      //if protocol is UDP
    		udp_header = (struct udphdr *)(skb_transport_header(skb));
    		source_port = (unsigned int)ntohs(udp_header->source);
    		dest_port = (unsigned int)ntohs(udp_header->dest);
		} 
		else if(ip_header->protocol == 6) {   //if protocol is TCP
    		tcp_header = (struct tcphdr *)(skb_transport_header(skb));
    		source_port = (unsigned int)ntohs(tcp_header->source);
    		dest_port = (unsigned int)ntohs(tcp_header->dest);
		} 
       	
       	else{
			source_port=0;
			dest_port=0;
		}
	    for (k = 1; k < i ; ++k)
	      	{
		        if(strncmp(myipb,ips[k],strlen(myipb))==0){
		        	printk(KERN_INFO "Got packet and dropped it. \n");
					printk(KERN_INFO "src_ip: %pI4 ** source port: %d\n", &ip_header->saddr,source_port);
				    printk(KERN_INFO "dst_ip: %pI4 ** dest_port :%d\n", &ip_header->daddr,dest_port);
		            return NF_DROP;
		        }

		        else if(strncmp(myipb,ips[k],strlen(myipb))!=0) {
			        printk(KERN_INFO "Not in blacklist ,Not dropped. \n");
			       	printk(KERN_INFO "src_ip: %pI4 ** source port: %d\n", &ip_header->saddr,source_port);
				    printk(KERN_INFO "dst_ip: %pI4 ** dest_port :%d\n", &ip_header->daddr,dest_port);
			        return NF_ACCEPT;
			    }
	        }
        
}
//*********************************************************************************
unsigned int w_hook(unsigned int hooknum, struct sk_buff *skb,

        const struct net_device *in, const struct net_device *out,

        int(*okfn)(struct sk_buff *))

{
        struct udphdr *udp_header;
		struct tcphdr *tcp_header;
		unsigned int dest_port, source_port;
		struct sk_buff *sock_buff;
		struct iphdr *ip_header;
        sock_buff = skb;
        ip_header = (struct iphdr *)skb_network_header(sock_buff);
        static char  myip[256];
        ip_header = (struct iphdr *)skb_network_header(sock_buff);
        if(!sock_buff) { 
        	return NF_DROP;
        }
        snprintf(myip, 16, "%pI4", &ip_header->saddr);
        if (ip_header->protocol == 17) {      //if protocol is UDP
    		udp_header = (struct udphdr *)(skb_transport_header(skb));
    		source_port = (unsigned int)ntohs(udp_header->source);
    		dest_port = (unsigned int)ntohs(udp_header->dest);
		} 
		else if(ip_header->protocol == 6) {   //if protocol is TCP
    		tcp_header = (struct tcphdr *)(skb_transport_header(skb));
    		source_port = (unsigned int)ntohs(tcp_header->source);
    		dest_port = (unsigned int)ntohs(tcp_header->dest);
		}
		else{
			source_port=0;
			dest_port=0;
		}  
        for ( k = 0; k < i ; ++k)
        {
	       	if(strncmp(myip,ips[k],strlen(myip))!=0){
	        	printk(KERN_INFO "Got packet not in whitelist so dropped it. \n");
				printk(KERN_INFO "src_ip: %pI4 ** source port: %d\n", &ip_header->saddr,source_port);
			    printk(KERN_INFO "dst_ip: %pI4\n", &ip_header->daddr);
	            return NF_DROP;
	        }

	        else if(strncmp(myip,ips[k],strlen(myip))==0) {
		       	printk(KERN_INFO "in whitelist ,Not dropped. \n");
		       	printk(KERN_INFO "src_ip: %pI4 ** source port: %d\n", &ip_header->saddr,source_port);
			    printk(KERN_INFO "dst_ip: %pI4\n", &ip_header->daddr);
		       	return NF_ACCEPT;
		    }
        
        }
        
}
//*******************************************************************************************************
module_init(icmp_drop_init);
module_exit(icmp_drop_exit);
