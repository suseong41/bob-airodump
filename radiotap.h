struct ST_RDT_HDR
{
    uint8_t version;
    uint8_t padding;
    uint16_t len;
    uint32_t present;
} __attribute__((packed));

ST_RDT_HDR parseRadiotap(const u_char* packet);

int getPower();