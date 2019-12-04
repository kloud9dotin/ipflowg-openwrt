# ipflowg-openwrt
A simple connection tracking userspace tool to display the stats about connections

Steps to be followed:
1) enable nf_conntrack_timeout in kernel config
2) place the ipflowg folder and mypackages folder in root of the openwrt source
3) add src-link mypackages <inser file path to mypackages> in feeds.conf
4) update and install packages

