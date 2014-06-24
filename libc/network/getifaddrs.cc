#include <bsd/porting/netport.h>

#include <bsd/sys/sys/sysctl.h>
#include <bsd/sys/netinet/in.h>
#include <bsd/sys/sys/socket.h>
#include <bsd/sys/net/if_types.h>
#include <bsd/sys/net/route.h>
#include <bsd/sys/net/if.h>
#include <bsd/include/arpa/inet.h>
#include <bsd/sys/net/if_dl.h>
#include <bsd/sys/netinet/in_systm.h>
#include <bsd/sys/netinet/ip.h>
#include <bsd/sys/netinet6/in6.h>
#include <bsd/porting/route.h>
#include <bsd/porting/ifaddrs.h>

#include <bsd/sys/compat/linux/linux.h>
#include <bsd/sys/compat/linux/linux_socket.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <termios.h>
#include <unistd.h>
#if !defined(AF_LINK)
#define	SA_LEN(sa)	sizeof(struct bsd_sockaddr)
#endif

#if !defined(SA_LEN)
#define	SA_LEN(sa)	(sa)->sa_len
#endif

#define	SALIGN	(sizeof(long) - 1)
#define	SA_RLEN(sa)	((sa)->sa_len ? (((sa)->sa_len + SALIGN) & ~SALIGN) : (SALIGN + 1))

#ifndef	ALIGNBYTES
/*
 * On systems with a routing socket, ALIGNBYTES should match the value
 * that the kernel uses when building the messages.
 */
#define	ALIGNBYTES	XXX
#endif
#ifndef	ALIGN
#define	ALIGN(p)	(((u_long)(p) + ALIGNBYTES) &~ ALIGNBYTES)
#endif

#define MAX_SYSCTL_TRY 5

int
getifaddrs(struct ifaddrs **pif)
{
	int icnt = 1;
	int dcnt = 0;
	int ncnt = 0;
	int ntry = 0;
	int mib[6];
	size_t needed;
	char *buf;
	char *next;
	struct ifaddrs *cif = 0;
	char *p, *p0;
	struct rt_msghdr *rtm;
	struct if_msghdrl *ifm;
	struct ifa_msghdrl *ifam;
	struct bsd_sockaddr_dl *dl;
	struct bsd_sockaddr *sa;
	struct ifaddrs *ifa, *ift;
	struct if_data *if_data;
	u_short idx = 0;
	int i;
	size_t len, alen;
	char *data;
	char *names;

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;             /* protocol */
	mib[3] = 0;             /* wildcard address family */
	mib[4] = NET_RT_IFLISTL;/* extra fields for extensible msghdr structs */
	mib[5] = 0;             /* no flags */
	do {
		/*
		 * We'll try to get addresses several times in case that
		 * the number of addresses is unexpectedly increased during
		 * the two sysctl calls.  This should rarely happen, but we'll
		 * try to do our best for applications that assume success of
		 * this library (which should usually be the case).
		 * Portability note: since FreeBSD does not add margin of
		 * memory at the first sysctl, the possibility of failure on
		 * the second sysctl call is a bit higher.
		 */

		if (osv_sysctl(mib, 6, NULL, &needed, NULL, 0) < 0)
			return (-1);
		if ((buf = (char *)malloc(needed)) == NULL)
			return (-1);
		if (osv_sysctl(mib, 6, buf, &needed, NULL, 0) < 0) {
			if (errno != ENOMEM || ++ntry >= MAX_SYSCTL_TRY) {
				free(buf);
				return (-1);
			}
			free(buf);
			buf = NULL;
		} 
	} while (buf == NULL);

	for (next = buf; next < buf + needed; next += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)(void *)next;
		if (rtm->rtm_version != RTM_VERSION)
			continue;
		switch (rtm->rtm_type) {
		case RTM_IFINFO:
			ifm = (struct if_msghdrl *)(void *)rtm;
			if (ifm->ifm_addrs & RTA_IFP) {
				idx = ifm->ifm_index;
				++icnt;
				if_data = IF_MSGHDRL_IFM_DATA(ifm);
				dcnt += if_data->ifi_datalen;
				dl = (struct bsd_sockaddr_dl *)IF_MSGHDRL_RTA(ifm);
				dcnt += SA_RLEN((struct bsd_sockaddr *)(void*)dl) +
				    ALIGNBYTES;
				ncnt += dl->sdl_nlen + 1;
			} else
				idx = 0;
			break;

		case RTM_NEWADDR:
			ifam = (struct ifa_msghdrl *)(void *)rtm;
			if (idx && ifam->ifam_index != idx)
				abort();	/* this cannot happen */

#define	RTA_MASKS	(RTA_NETMASK | RTA_IFA | RTA_BRD)
			if (idx == 0 || (ifam->ifam_addrs & RTA_MASKS) == 0)
				break;
			p = (char *)IFA_MSGHDRL_RTA(ifam);
			++icnt;
			if_data = IFA_MSGHDRL_IFAM_DATA(ifam);
			dcnt += if_data->ifi_datalen + ALIGNBYTES;

			/* Scan to look for length of address */
			alen = 0;
			for (p0 = p, i = 0; i < RTAX_MAX; i++) {
				if ((RTA_MASKS & ifam->ifam_addrs & (1 << i))
				    == 0)
					continue;
				sa = (struct bsd_sockaddr *)(void *)p;
				len = SA_RLEN(sa);
				if (i == RTAX_IFA) {
					alen = len;
					break;
				}
				p += len;
			}
			for (p = p0, i = 0; i < RTAX_MAX; i++) {
				if ((RTA_MASKS & ifam->ifam_addrs & (1 << i))
				    == 0)
					continue;
				sa = (struct bsd_sockaddr *)(void *)p;
				len = SA_RLEN(sa);
				if (i == RTAX_NETMASK && SA_LEN(sa) == 0)
					dcnt += alen;
				else
					dcnt += len;
				p += len;
			}
			break;
		}
	}

	if (icnt + dcnt + ncnt == 1) {
		*pif = NULL;
		free(buf);
		return (0);
	}
	data = (char *)malloc(sizeof(struct ifaddrs) * icnt + dcnt + ncnt);
	if (data == NULL) {
		free(buf);
		return(-1);
	}

	ifa = (struct ifaddrs *)(void *)data;
	data += sizeof(struct ifaddrs) * icnt;
	names = data + dcnt;

	memset(ifa, 0, sizeof(struct ifaddrs) * icnt);
	ift = ifa;

	idx = 0;
	for (next = buf; next < buf + needed; next += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)(void *)next;
		if (rtm->rtm_version != RTM_VERSION)
			continue;
		switch (rtm->rtm_type) {
		case RTM_IFINFO:
			ifm = (struct if_msghdrl *)(void *)rtm;
			if ((ifm->ifm_addrs & RTA_IFP) == 0) {
				idx = 0;
				break;
			}

			idx = ifm->ifm_index;
			dl = (struct bsd_sockaddr_dl *)IF_MSGHDRL_RTA(ifm);

			cif = ift;
			ift->ifa_name = names;
			ift->ifa_flags = (int)ifm->ifm_flags;
			memcpy(names, dl->sdl_data, (size_t)dl->sdl_nlen);
			names[dl->sdl_nlen] = 0;
			names += dl->sdl_nlen + 1;

			ift->ifa_addr = (struct bsd_sockaddr *)(void *)data;
			memcpy(data, dl, (size_t)SA_LEN((struct bsd_sockaddr *)
			    (void *)dl));
			data += SA_RLEN((struct bsd_sockaddr *)(void *)dl);

			if_data = IF_MSGHDRL_IFM_DATA(ifm);
			/* ifm_data needs to be aligned */
			ift->ifa_data = data = (char *)ALIGN(reinterpret_cast<unsigned long>(data));
			memcpy(data, if_data, if_data->ifi_datalen);
			data += if_data->ifi_datalen;

			ift = (ift->ifa_next = ift + 1);
			break;

		case RTM_NEWADDR:
			ifam = (struct ifa_msghdrl *)(void *)rtm;
			if (idx && ifam->ifam_index != idx)
				abort();	/* this cannot happen */

			if (idx == 0 || (ifam->ifam_addrs & RTA_MASKS) == 0)
				break;
			ift->ifa_name = cif->ifa_name;
			ift->ifa_flags = cif->ifa_flags;
			ift->ifa_data = NULL;

			p = (char *)IFA_MSGHDRL_RTA(ifam);
			/* Scan to look for length of address */
			alen = 0;
			for (p0 = p, i = 0; i < RTAX_MAX; i++) {
				if ((RTA_MASKS & ifam->ifam_addrs & (1 << i))
				    == 0)
					continue;
				sa = (struct bsd_sockaddr *)(void *)p;
				len = SA_RLEN(sa);
				if (i == RTAX_IFA) {
					alen = len;
					break;
				}
				p += len;
			}
			for (p = p0, i = 0; i < RTAX_MAX; i++) {
				if ((RTA_MASKS & ifam->ifam_addrs & (1 << i))
				    == 0)
					continue;
				sa = (struct bsd_sockaddr *)(void *)p;
				len = SA_RLEN(sa);
				switch (i) {
				case RTAX_IFA:
					ift->ifa_addr =
					    (struct bsd_sockaddr *)(void *)data;
					memcpy(data, p, len);
					data += len;
					break;

				case RTAX_NETMASK:
					ift->ifa_netmask =
					    (struct bsd_sockaddr *)(void *)data;
					if (SA_LEN(sa) == 0) {
						memset(data, 0, alen);
						data += alen;
						break;
					}
					memcpy(data, p, len);
					data += len;
					break;

				case RTAX_BRD:
					ift->ifa_broadaddr =
					    (struct bsd_sockaddr *)(void *)data;
					memcpy(data, p, len);
					data += len;
					break;
				}
				p += len;
			}

			if_data = IFA_MSGHDRL_IFAM_DATA(ifam);
			/* ifam_data needs to be aligned */
			ift->ifa_data = data = (char *)ALIGN(reinterpret_cast<unsigned long>(data));
			memcpy(data, if_data, if_data->ifi_datalen);
			data += if_data->ifi_datalen;

			ift = (ift->ifa_next = ift + 1);
			break;
		}
	}

	free(buf);

	if (--ift >= ifa) {
		ift->ifa_next = NULL;
		*pif = ifa;
	} else {
		*pif = NULL;
		free(ifa);
	}
	return (0);
}

void 
freeifaddrs(struct ifaddrs *ifp)
{
	free(ifp);
}
