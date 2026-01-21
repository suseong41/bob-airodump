
struct ST_BC_HDR
{
    uint16_t framControl;
    uint16_t duration_id;
    uint8_t da[6];
    uint8_t sa[6];
    uint8_t bssid[6];
    uint16_t seqControl;
} __attribute__((packed));

struct ST_BC_BODY_ESSENTIAL
{
    uint64_t timestamp;
    uint16_t interval;
    uint16_t capability;
    uint8_t elementId;
    uint8_t len;
    uint8_t ssid[];
} __attribute__((packed));

struct BC_BODY_TAG
{
} __attribute__((packed));

ST_BC_HDR parseBeacon(const u_char* packet);