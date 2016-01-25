#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/net_namespace.h>

#define NETLINK_USER 31

static void callback(pid_t pid, char *msg);

struct sock *nl_skt = NULL;

static void callback(pid_t pid, char *msg)
{
	struct nlmsghdr *nlmh;
	struct sk_buff *skb_out;
	int msg_size;
	int ret;

	printk(KERN_INFO "Entering: %s\n", __FUNCTION__);
	msg_size = strlen(msg);

	skb_out = nlmsg_new(msg_size, 0);

	if (!skb_out) {
		printk(KERN_INFO "callback: Failed to allocate skb\n");
		return;
	}

	nlmh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
	NETLINK_CB(skb_out).dst_group = 0;
	strncpy(nlmsg_data(nlmh), msg, msg_size);

	msleep(2000);
	ret = nlmsg_unicast(nl_skt, skb_out, pid);

	if (ret < 0)
		printk(KERN_INFO
		       "callback: Error while sending back to user: %p\n",
		       ERR_PTR(ret));

}
