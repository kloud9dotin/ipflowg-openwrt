/*
 ipflowg - IP traffic flow logger
 Copyright (C) 2019 Karthik Ayyar <karthik@houseofkodai.in>
 * gcc -Wall ipflowg.c -lmnl
 */

#include <stdio.h>
#include <sys/fsuid.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <endian.h>
#include <string.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>



#define IPFLOWG_NAME "ipflowg"
#define IPFLOWG_VERSION "0.1"
#define IPFLOWG_COPY "Copyright (c) 2019 Karthik Ayyar <karthik@houseofkodai.in>"
#define IPFLOWG_LICENSE "Licensed under the GNU Lesser General Public License v2.1"

/*
 * 
*/

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC    1000000000L
#endif

typedef struct ipflow {
  uint32_t ip4_src_addr;
  uint32_t ip4_dst_addr;
  uint8_t l4_proto;
  uint16_t port_src;
  uint16_t port_dst;
  uint64_t bytes_src;
  uint64_t bytes_dst;
  uint64_t pkts_src;
  uint64_t pkts_dst;
  uint64_t timestamp_start;
  uint64_t timestamp_stop;
} ipflow_t;

/*
 * note: no validation being done - 
 *   typically the 
 *     mnl_attr_get_type(attr), 
 *     mnl_attr_validate(attr, MNL_TYPE_U64)
 *   are used and MNL-CB_ERROR is returned  
 */
static int mnl_attr_parse_cb_ok(const struct nlattr *attr, void *data) {
	const struct nlattr **tb = data;
	tb[mnl_attr_get_type(attr)] = attr;
	return MNL_CB_OK;
}

#define NL_ATTR_GET(aname,elem,x) \
  if (attrs[aname]) { ipf->elem = mnl_attr_get_u##x(attrs[aname]); }

static int data_cb(const struct nlmsghdr *nlh, void *data) {
  ipflow_t *ipf = data;
	struct nlattr *attrs[CTA_MAX+1];
  const size_t attrs_sz = (CTA_MAX+1) * sizeof(struct nlattr);
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);

  if (IPCTNL_MSG_CT_DELETE != (nlh->nlmsg_type & 0xFF)) {
    return MNL_CB_OK;
  }
	/*switch(nlh->nlmsg_type & 0xFF) {
    case IPCTNL_MSG_CT_NEW:
      if (nlh->nlmsg_flags & (NLM_F_CREATE|NLM_F_EXCL))
        printf("%9s ", "[NEW] ");
      else
        printf("%9s ", "[UPDATE] ");
      break;
    case IPCTNL_MSG_CT_DELETE:
      printf("%9s ", "[DESTROY] ");
      break;
	}*/

  memset(ipf,0,sizeof(ipflow_t));
  memset(attrs,0,attrs_sz);
	mnl_attr_parse(nlh, sizeof(*nfg), mnl_attr_parse_cb_ok, attrs);
  struct nlattr *cta_tuple_orig = attrs[CTA_TUPLE_ORIG];
  struct nlattr *cta_counters_orig = attrs[CTA_COUNTERS_ORIG];
  struct nlattr *cta_counters_reply = attrs[CTA_COUNTERS_REPLY];
  struct nlattr *cta_timestamp = attrs[CTA_TIMESTAMP];

	if (cta_tuple_orig) {
    memset(attrs,0,attrs_sz);
    mnl_attr_parse_nested(cta_tuple_orig, mnl_attr_parse_cb_ok, attrs);
    struct nlattr *cta_tuple_ip = attrs[CTA_TUPLE_IP];
    struct nlattr *cta_tuple_proto = attrs[CTA_TUPLE_PROTO];
    if (cta_tuple_ip) {
      memset(attrs,0,attrs_sz);
      mnl_attr_parse_nested(cta_tuple_ip, mnl_attr_parse_cb_ok, attrs);
      NL_ATTR_GET(CTA_IP_V4_SRC,ip4_src_addr,32);
      NL_ATTR_GET(CTA_IP_V4_DST,ip4_dst_addr,32);
    }
    if (cta_tuple_proto) {
      memset(attrs,0,attrs_sz);
      mnl_attr_parse_nested(cta_tuple_proto, mnl_attr_parse_cb_ok, attrs);
      NL_ATTR_GET(CTA_PROTO_NUM,l4_proto,8);
      NL_ATTR_GET(CTA_PROTO_SRC_PORT,port_src,16);
      NL_ATTR_GET(CTA_PROTO_DST_PORT,port_dst,16);
    }
	}

	if (cta_counters_orig) {
    memset(attrs,0,attrs_sz);
    mnl_attr_parse_nested(cta_counters_orig, mnl_attr_parse_cb_ok, attrs);
    NL_ATTR_GET(CTA_COUNTERS_PACKETS,pkts_src,64);
    NL_ATTR_GET(CTA_COUNTERS_BYTES,bytes_src,64);
	}

	if (cta_counters_reply) {
    memset(attrs,0,attrs_sz);
    mnl_attr_parse_nested(cta_counters_reply, mnl_attr_parse_cb_ok, attrs);
    NL_ATTR_GET(CTA_COUNTERS_PACKETS,pkts_dst,64);
    NL_ATTR_GET(CTA_COUNTERS_BYTES,bytes_dst,64);
	}

	if (cta_timestamp) {
    memset(attrs,0,attrs_sz);
    mnl_attr_parse_nested(cta_timestamp, mnl_attr_parse_cb_ok, attrs);
    NL_ATTR_GET(CTA_TIMESTAMP_START,timestamp_start,64);
    NL_ATTR_GET(CTA_TIMESTAMP_STOP,timestamp_stop,64);
	}

  uint64_t duration = (be64toh(ipf->timestamp_stop)-be64toh(ipf->timestamp_start)) / NSEC_PER_SEC;
  printf("%2u %"PRIu64" %s:%u", 
    ipf->l4_proto,
    duration,
    inet_ntoa(*(struct in_addr *)&(ipf->ip4_src_addr)), ntohs(ipf->port_src)
  );
  printf(" %s:%u %"PRIu64":%"PRIu64" %"PRIu64":%"PRIu64"\n", 
    inet_ntoa(*(struct in_addr *)&(ipf->ip4_dst_addr)), ntohs(ipf->port_dst),
    be64toh(ipf->pkts_src),
    be64toh(ipf->pkts_dst),
    be64toh(ipf->bytes_src),
    be64toh(ipf->bytes_dst)
  );

	return MNL_CB_OK;
}
/*
 * 
*/

char get_sysctl(const char *path) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) { return 0; };
  char c;
  int rc = read(fd, &c, 1);
  close(fd);
  if (rc != 1) { return 0; };
  return c;
}

const char *NF_CONNTRACK_ACCT = "/proc/sys/net/netfilter/nf_conntrack_acct";
const char *NF_CONNTRACK_TIMESTAMP = "/proc/sys/net/netfilter/nf_conntrack_timestamp";

int set_sysctl(char acct, char tstamp) {
  int fd = open(NF_CONNTRACK_ACCT, O_WRONLY);
  if (fd < 0) { return 0; };
  int rc = write(fd, &acct, 1);
  close(fd);
  if (rc != 1) { return 0; };
  fd = open(NF_CONNTRACK_TIMESTAMP, O_WRONLY);
  if (fd < 0) { return 0; };
  rc = write(fd, &tstamp, 1);
  close(fd);
  if (rc != 1) { return 0; };
  return 1;
};

static int usage(int return_code) {
  fprintf(stderr, "IPFLOWG: Netfilter Conntrack IP-Flow-Log " IPFLOWG_VERSION "\n" IPFLOWG_COPY "\n\n");
  fprintf(stderr, "Usage: %s [-a ASCII]\n", IPFLOWG_NAME);
  return return_code;
}

int main(int argc, char *argv[]) {

  if ((argc > 1) && (argv[1][0] == '-') && (argv[1][1] == 'h')) {
    return usage(0);
  }

  setfsuid(getuid());
  setfsgid(getgid());

  char prev_nfct_acct = 0;
  char prev_nfct_timestamp = 0;
  if ((0 == (prev_nfct_acct = get_sysctl(NF_CONNTRACK_ACCT))) || 
      (0 == (prev_nfct_timestamp = get_sysctl(NF_CONNTRACK_TIMESTAMP))) ||
      (!set_sysctl('1', '1'))) {
    fprintf(stderr, "%s: -ERR sysctl net.netfilter.nf_conntrack_acct/timestamp.\n", IPFLOWG_NAME);
    return 1;
  };

	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL) {
		perror("mnl_socket_open");
		exit(EXIT_FAILURE);
	}

	if (mnl_socket_bind(nl, NF_NETLINK_CONNTRACK_NEW |
				NF_NETLINK_CONNTRACK_UPDATE |
				NF_NETLINK_CONNTRACK_DESTROY,
				MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}

  ipflow_t ipf;
  int rc = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (rc > 0) {
		rc = mnl_cb_run(buf, rc, 0, 0, data_cb, &ipf);
		if (rc <= MNL_CB_STOP) break;
		rc = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	};
  if (-1 == rc) {
    perror("mnl_socket_recvfrom");
    exit(EXIT_FAILURE);
  }

  mnl_socket_close(nl);
  set_sysctl(prev_nfct_acct, prev_nfct_timestamp);
  return 0;
}
