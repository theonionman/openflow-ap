#ifndef WIFI_EXT_H
#define WIFI_EXT_H 1

#ifdef _LINUX_
#include <stdint.h> /* uint*_t */
#include <time.h>
#endif
#include <list.h>
#include "radiotap.h"
#include <net/if.h> /* IFNAMSIZ */
#define WIFI_FC0_VERSION_MASK       0x03
#define WIFI_FC0_VERSION_0      0x00
#define WIFI_FC0_TYPE_MASK      0x0c
#define WIFI_FC0_TYPE_MGT       0x00
#define WIFI_FC0_TYPE_CTL       0x04
#define WIFI_FC0_TYPE_DATA      0x08

#define WIFI_FC0_SUBTYPE_MASK       0xf0
/* for TYPE_MGT */
#define WIFI_FC0_SUBTYPE_ASSOC_REQ  0x00
#define WIFI_FC0_SUBTYPE_ASSOC_RESP 0x10
#define WIFI_FC0_SUBTYPE_REASSOC_REQ    0x20
#define WIFI_FC0_SUBTYPE_REASSOC_RESP   0x30
#define WIFI_FC0_SUBTYPE_PROBE_REQ  0x40
#define WIFI_FC0_SUBTYPE_PROBE_RESP 0x50
#define WIFI_FC0_SUBTYPE_BEACON     0x80
#define WIFI_FC0_SUBTYPE_ATIM       0x90
#define WIFI_FC0_SUBTYPE_DISASSOC   0xa0
#define WIFI_FC0_SUBTYPE_AUTH       0xb0
#define WIFI_FC0_SUBTYPE_DEAUTH     0xc0
#define WIFI_FC0_SUBTYPE_ACTION     0x0d
/* for TYPE_CTL */
#define WIFI_FC0_SUBTYPE_PS_POLL    0xa0
#define WIFI_FC0_SUBTYPE_RTS        0xb0
#define WIFI_FC0_SUBTYPE_CTS        0xc0
#define WIFI_FC0_SUBTYPE_ACK        0xd0
#define WIFI_FC0_SUBTYPE_CF_END     0xe0
#define WIFI_FC0_SUBTYPE_CF_END_ACK 0xf0
/* for TYPE_DATA (bit combination) */
#define WIFI_FC0_SUBTYPE_DATA       0x00
#define WIFI_FC0_SUBTYPE_CF_ACK     0x10
#define WIFI_FC0_SUBTYPE_CF_POLL    0x20
#define WIFI_FC0_SUBTYPE_CF_ACPL    0x30
#define WIFI_FC0_SUBTYPE_NODATA     0x40
#define WIFI_FC0_SUBTYPE_CFACK      0x50
#define WIFI_FC0_SUBTYPE_CFPOLL     0x60
#define WIFI_FC0_SUBTYPE_CF_ACK_CF_ACK  0x70
#define WIFI_FC0_SUBTYPE_QOS               0x80
#define WIFI_FC0_SUBTYPE_QOS_NULL          0xc0

#define WIFI_FC1_DIR_MASK       0x03
#define WIFI_FC1_DIR_NODS       0x00    /* STA->STA */
#define WIFI_FC1_DIR_TODS       0x01    /* STA->AP  */
#define WIFI_FC1_DIR_FROMDS     0x02    /* AP ->STA */
#define WIFI_FC1_DIR_DSTODS     0x03    /* AP ->AP  */

#define WIFI_FC1_MORE_FRAG      0x04
#define WIFI_FC1_RETRY          0x08
#define WIFI_FC1_PWR_MGT        0x10
#define WIFI_FC1_MORE_DATA      0x20
#define WIFI_FC1_WEP            0x40
#define WIFI_FC1_ORDER          0x80

#define WIFI_NWID_LEN           32
#define WIFI_ADDR_LEN           6

#define WIFI_QOS_HAS_SEQ(wh) \
        (((wh)->frame_control[0] & \
          (WIFI_FC0_TYPE_MASK | WIFI_FC0_SUBTYPE_QOS)) == \
          (WIFI_FC0_TYPE_DATA | WIFI_FC0_SUBTYPE_QOS))

#define TSFT     0
#define FLAGS    1
#define RATE     2
#define CHANNEL  3
#define FHSS     4
#define DBM_ANTSIGNAL  5
#define DBM_ANTNOISE   6
#define LOCK_QUALITY  7
#define TX_ATTENUATION  8
#define DB_TX_ATTENUATION  9
#define DBM_TX_POWER   10
#define ANTENNA  11
#define DB_ANTSIGNAL  12
#define DB_ANTNOISE   13
#define RX_FLAGS  14
#define TX_FLAGS  15
#define RTS_RETRIES  16
#define DATA_RETRIES  17

#define MCS  19
#define AMPDU_STATUS  20

struct EtherAddress {
    uint8_t data[WIFI_ADDR_LEN];
};

/*Stores the information of per received wireless frame, which may
 *be from neighbour APs or STAs, or the associated STAs.
 */ 
struct device_info {
    struct list node;
    struct EtherAddress mac_addr;
    //EtherAddress dst;
    int rssi;
    int packets;
    //double _last_rssi;
    //double _last_std;
    //int _last_packets;
    int channel;
    unsigned long int last_received;
};

/*Stores the information of STAs associated with local ap*/
struct local_ap {
    struct EtherAddress bssid;
    uint8_t local_ap_num;
    unsigned int local_sta_num;
    struct list local_sta_list;
};

/*Stores the information of neighbours*/
struct neighbour {
    unsigned int neigh_ap_num;
    unsigned int neigh_sta_num;
    struct list neigh_ap_list;
    struct list neigh_sta_list;
};

struct ieee80211_hdr {
    uint8_t frame_control[2];
    uint16_t duration_id;
    uint8_t  addr1[WIFI_ADDR_LEN];
    uint8_t  addr2[WIFI_ADDR_LEN];
    uint8_t  addr3[WIFI_ADDR_LEN];
    uint16_t seq_ctrl;
    uint8_t  addr4[WIFI_ADDR_LEN];
};

int new_device_info(struct list *, struct EtherAddress *, int, int, unsigned long int);
int new_local_ap(void);
int new_neighbour(struct neighbour *);
struct device_info *lookup_neigh_ap(struct neighbour *, struct EtherAddress *);
struct device_info *lookup_neigh_sta(struct neighbour *, struct EtherAddress *);
void update_device_info(struct device_info *, int, int, unsigned long int);
/**
 * Stores information about a border port from which traffic will be tunneled to
 * and from.
 */
typedef struct border_port {
    /** name of the interface over which packets will be received for tunneling
        and sent after decapsulation */
    char intf[IF_NAMESIZE];

    /** tag associated with this port; only decapsulated packets which were
        tagged with this value will be forwarded to this port */
    //uint32_t tag;

    /** raw packet socket file descriptor attached to this port */
    int fd;

    /** if virtual border port, set to 1, otherwise set to 0 */
    //int vbp;
} border_port;

int RadiotapParser(char *, int, enum ieee80211_radiotap_type);
int make_mon0_sock(void);
#endif