/*
 *Filename: wifi_ext.c
 *Purpose: create a socket of wireless interface mon0. 
 */
#include <arpa/inet.h>

#include <errno.h>
#include <net/ethernet.h>

#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>

#include "wifi_ext.h"
#include "common.h"
#include "radiotap_iter.h"

static const struct radiotap_align_size align_size_000000_00[] = {
    [0] = { .align = 1, .size = 4, },
    [52] = { .align = 1, .size = 4, },
};

static const struct ieee80211_radiotap_namespace vns_array[] = {
    {
        .oui = 0x000000,
        .subns = 0,
        .n_bits = sizeof(align_size_000000_00),
        .align_size = align_size_000000_00,
    },
};

static const struct ieee80211_radiotap_vendor_namespaces vns = {
    .ns = vns_array,
    .n_ns = sizeof(vns_array)/sizeof(vns_array[0]),
};

void* capsulator_thread_main_for_border_port(void* vbpci);

/** binds a raw packets file descriptor fd to the interface specified by name */
void bindll(int fd, char* name) {
    struct ifreq ifr;
    struct sockaddr_ll addr;

    strncpy(ifr.ifr_name, name, IFNAMSIZ);
    ioctl(fd, SIOCGIFINDEX, &ifr);

    memset(&addr, 0, sizeof(addr));
    addr.sll_family = PF_PACKET;
    addr.sll_protocol = 0;
    addr.sll_ifindex = ifr.ifr_ifindex;
    if(bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
        pdie("bind (border port interface)");
}

int make_mon0_sock(void) {
	struct ifreq ifr;
	pthread_t tid;
	int fd, val;
	val = 8*1024;
	border_port* bp;
    bp = realloc(bp, sizeof(border_port));
    char if_name[]="mon0";
    strncpy(bp->intf, if_name, IFNAMSIZ);

	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(fd < 0)
        pdie("border port socket");
    else
        bp->fd = fd;

    /* bind the border port to its interface */
    bindll(fd, bp->intf);

    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val));

    /* put the interface into promiscuous mode so we get packets destined for
       devices on the other side of the tunnel too */
    strncpy(ifr.ifr_name, bp->intf, IFNAMSIZ);
    ioctl(fd, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= IFF_PROMISC;
    ioctl(fd, SIOCSIFFLAGS, &ifr);
    printf("the monitor socket fd is %d\n", fd);

    
    if( pthread_create(&tid, NULL, capsulator_thread_main_for_border_port, bp) != 0 )
        pdie("pthread_create");
    
    return 0;
}



#define BUFSZ (8 * 1024)

void* capsulator_thread_main_for_border_port(void* vbp) {
    border_port* bp;
    char data[BUFSZ];
    int n, rssi, error, chan;
    unsigned long int tsft;
    struct ieee80211_hdr* ieee80211_data;
    int  ieee80211_radiotap_len;
    struct ieee80211_radiotap_header* radiotap;
    pthread_detach(pthread_self());
    bp = (border_port*)vbp;

    struct neighbour *neigh_info = malloc(sizeof(*neigh_info));
    error = new_neighbour(neigh_info);
    if(error) {
        printf("initialize neighbour info fails\n");
    }
    uint8_t fc[2];
    struct EtherAddress dst_mac;
    struct EtherAddress src_mac;
    struct EtherAddress ds_mac;
    struct device_info *di;
    int dir, type, subtype;
    bool station;
    verbose_println("%s BPH: thread for handling incoming border port traffic is now running",
                    bp->intf);

    /* continuously encapsulate and forward ieee80211 frames from the border through the tunnel */
    while(1) {
        /* wait for an ieee80211 frame to arrive */
        verbose_println("%s BPH: waiting for border port traffic",
                        bp->intf);
        /*return the size of raw data*/
        n = read(bp->fd, data, BUFSZ);

        ieee80211_radiotap_len = ieee80211_get_radiotap_len(data);
        radiotap = (struct ieee80211_radiotap_header*)data;

        ieee80211_data = ((char*)data)+ieee80211_radiotap_len;

        //memcpy(fc, ieee80211_data->frame_control, 2);
        //memcpy(dst_mac.data, ieee80211_data->addr1, 6);
        memcpy(src_mac.data, ieee80211_data->addr2, 6);
        //memcpy(ds_mac.data, ieee80211_data->addr3, 6);
        
        //printf("rev:frame_control=%2x-%2x", fc[0], fc[1]);
        //printf("rssi=%d ", rssi);
        //printf("addr1=%02x-%02x-%02x-%02x-%02x-%02x ",addr1[0],addr1[1],addr1[2],addr1[3],addr1[4],addr1[5]);
        //printf("addr2=%02x-%02x-%02x-%02x-%02x-%02x\n",addr2[0],addr2[1],addr2[2],addr2[3],addr2[4],addr2[5]);

        if(n < 0) {
            if(errno != EINTR) {
                verbose_println(
                        "Error: read from border port %s failed\n",
                        bp->intf);
            }
            else
                continue;
        }

        unsigned wifi_header_size = sizeof(struct ieee80211_hdr)+ieee80211_radiotap_len;

        if ((ieee80211_data->frame_control[1] & WIFI_FC1_DIR_MASK) == WIFI_FC1_DIR_DSTODS)
            wifi_header_size += WIFI_ADDR_LEN;

        if (WIFI_QOS_HAS_SEQ(ieee80211_data))
            wifi_header_size += sizeof(uint16_t);

        if (n < wifi_header_size) {
            continue;
        }

        dir = ieee80211_data->frame_control[1] & WIFI_FC1_DIR_MASK;
        type = ieee80211_data->frame_control[0] & WIFI_FC0_TYPE_MASK;
        subtype = ieee80211_data->frame_control[0] & WIFI_FC0_SUBTYPE_MASK;
        station = false;

        switch (dir) {
        case WIFI_FC1_DIR_TODS:
            // TODS bit not set when TA is an access point, but only when TA is a station
            station = true;
            break;
        case WIFI_FC1_DIR_NODS:
            if (type == WIFI_FC0_TYPE_DATA) {
                // NODS never set for data frames unless in ad-hoc mode
                station = true;
                break;
            } else if (type == WIFI_FC0_TYPE_MGT) {
                if (subtype == WIFI_FC0_SUBTYPE_BEACON
                        || subtype == WIFI_FC0_SUBTYPE_PROBE_RESP) {
                    // NODS set for beacon frames and probe response from access points
                    station = false;
                    break;
                } else if (subtype == WIFI_FC0_SUBTYPE_PROBE_REQ
                        || subtype == WIFI_FC0_SUBTYPE_REASSOC_REQ
                        || subtype == WIFI_FC0_SUBTYPE_ASSOC_REQ
                        || subtype == WIFI_FC0_SUBTYPE_AUTH
                        || subtype == WIFI_FC0_SUBTYPE_DISASSOC
                        || subtype == WIFI_FC0_SUBTYPE_DEAUTH) {
                    // NODS set for beacon frames and probe response from access points
                    station = true;
                    break;
                }
            }
            // no idea, ignore packet
            continue;
        case WIFI_FC1_DIR_FROMDS:
            // FROMDS bit not set when TA is an station, but only when TA is an access point
            station = false;
            break;
        case WIFI_FC1_DIR_DSTODS:
            // DSTODS bit never set
            station = false;
            break;
        }

        if (station) {
            di = lookup_neigh_sta(neigh_info, &src_mac);
        } else {
            di = lookup_neigh_ap(neigh_info, &src_mac);
        }

        /*parse the needed information about current frame from radiotap*/
        rssi = RadiotapParser(radiotap, ieee80211_radiotap_len, DBM_ANTSIGNAL);
        chan = RadiotapParser(radiotap, ieee80211_radiotap_len, CHANNEL);
        tsft = RadiotapParser(radiotap, ieee80211_radiotap_len, TSFT);

        /*make new device record when unknown frame comes*/
        if (!di) {
            if (station) {
                error = new_device_info(&neigh_info->neigh_sta_list, &src_mac, rssi, chan, tsft);
                if(error)
                    printf("fail to add new device record\n");
                else {
                    (neigh_info->neigh_sta_num)++;
                    //printf("add new sta record\n");
                }
            }
            else {
                error = new_device_info(&neigh_info->neigh_ap_list, &src_mac, rssi, chan, tsft);
                if(error)
                    printf("add new device record fails\n");
                else {
                    (neigh_info->neigh_ap_num)++;
                    //printf("add new ap record\n");
                }
            }
        }
        else
            update_device_info(di, rssi, chan, tsft);
            

        /*
        if (station) {
            for (DTIter qi = _summary_triggers.begin(); qi != _summary_triggers.end(); qi++) {
                if ((*qi)->_eth == nfo->_eth) {
                    Frame frame = Frame(ta, ceh->tsft, w->i_seq, rssi, ceh->rate, type, subtype, p->length(), dur);
                    (*qi)->_frames.push_back(frame);
                }
            }
        }
        */
    }

    free(bp);
    return NULL;
}

int RadiotapParser(char * buf, int buflen, enum ieee80211_radiotap_type radiotap_type)
{
    int pkt_rate_100kHz = 0, antenna = 0, pwr = 0, rssi = 0, channel = 0;
    uint64_t tsft=0;
    struct ieee80211_radiotap_iterator iterator;
    int ret = ieee80211_radiotap_iterator_init(&iterator, buf, buflen, &vns);

    while (!ret) {

        if (ret)
            continue;

        /* see if this argument is something we can use */

        switch (iterator.this_arg_index) {
        /*
         * You must take care when dereferencing iterator.this_arg
         * for multibyte types... the pointer is not aligned.  Use
         * get_unaligned((type *)iterator.this_arg) to dereference
         * iterator.this_arg for type "type" safely on all arches.
         */
        case IEEE80211_RADIOTAP_TSFT:
            tsft = *iterator.this_arg;
            break;

        case IEEE80211_RADIOTAP_RATE:
            /* radiotap "rate" u8 is in
             * 500kbps units, eg, 0x02=1Mbps
             */
            pkt_rate_100kHz = (*iterator.this_arg) * 5;
            break;

        case IEEE80211_RADIOTAP_CHANNEL:
            channel = *iterator.this_arg;
            break;

        case IEEE80211_RADIOTAP_ANTENNA:
            /* radiotap uses 0 for 1st ant */
            antenna = *iterator.this_arg;
            break;

        case IEEE80211_RADIOTAP_DBM_TX_POWER:
            pwr = *iterator.this_arg;
            break;

        case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
            rssi = *iterator.this_arg;

        default:
            break;
        }

        ret = ieee80211_radiotap_iterator_next(&iterator);

    }  /* while more rt headers */

    //  if (ret != -ENOENT)
    //      return TXRX_DROP;
    switch(radiotap_type) {
        case IEEE80211_RADIOTAP_TSFT:
            return tsft;
        case IEEE80211_RADIOTAP_FLAGS:
            return;
        case IEEE80211_RADIOTAP_RATE:
            return;
        case IEEE80211_RADIOTAP_CHANNEL:
            return channel;
        case IEEE80211_RADIOTAP_FHSS:
            return;
        case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
            return rssi;
        case IEEE80211_RADIOTAP_DBM_ANTNOISE:
            return;
        case IEEE80211_RADIOTAP_LOCK_QUALITY:
            return;
        case IEEE80211_RADIOTAP_TX_ATTENUATION:
            return;
        case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
            return;
        case IEEE80211_RADIOTAP_DBM_TX_POWER:
            return;
        case IEEE80211_RADIOTAP_ANTENNA:
            return;
        case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
            return;
        case IEEE80211_RADIOTAP_DB_ANTNOISE:
            return;
        case IEEE80211_RADIOTAP_RX_FLAGS:
            return;
        case IEEE80211_RADIOTAP_TX_FLAGS:
            return;
        case IEEE80211_RADIOTAP_RTS_RETRIES:
            return;
        case IEEE80211_RADIOTAP_DATA_RETRIES:
            return;
        case IEEE80211_RADIOTAP_MCS:
            return;
        case IEEE80211_RADIOTAP_AMPDU_STATUS:
            return;
    }
}

/*When recevies frame of new device, record its information in device list*/
int new_device_info(struct list *pre, struct EtherAddress *s, int r, int c, unsigned long int t) {
    struct device_info *di = NULL;
    di= (struct device_info*)malloc(sizeof(struct device_info));
    if(di == NULL)
        return 1;
    strncpy(di->mac_addr.data, s->data, 6);
    //strncpy(di->dst, d->data, 6);
    di->rssi = r;
    di->channel = c;
    di->packets = 1;
    di->last_received = t;
    list_push_back(pre, &di->node);
    return 0;
}
int new_local_ap() {}

int new_neighbour(struct neighbour *n) {
    n->neigh_ap_num = 0;
    n->neigh_sta_num = 0;
    list_init(&n->neigh_ap_list);
    list_init(&n->neigh_sta_list);
    return 0;
}

struct device_info *
lookup_neigh_ap(struct neighbour *n, struct EtherAddress *m) {
    struct device_info *di;
    LIST_FOR_EACH(di, struct device_info, node, &n->neigh_ap_list) {
        if(!strncmp(di->mac_addr.data, m->data, 6))
                return di;
    }
    return NULL;
}

struct device_info *
lookup_neigh_sta(struct neighbour *n, struct EtherAddress *m) {
    struct device_info *di;
    LIST_FOR_EACH(di, struct device_info, node, &n->neigh_sta_list) {
        /*strncmp() returns 0 when two compared objects equal*/
        if(!strncmp(di->mac_addr.data, m->data, 6))
                return di;
    }
    return NULL;
}
void update_device_info(struct device_info *di, int r, int c, unsigned long int tsft) {
    di->packets++;
    if(r>0) {
        di->rssi = r;
        di->channel = c;
        di->last_received = tsft;
    }
}