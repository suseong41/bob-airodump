struct ST_802_11
{
    uint16_t fc;
    uint16_t d_id;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t sc;
} __attribute__((packed));

bool chkBeacon();