struct ST_802_11
{
    uint16_t framControl;
    uint16_t duration_id;
    uint8_t da[6];
    uint8_t sa[6];
    uint8_t bssid[6];
    uint16_t seqControl;
} __attribute__((packed));

ST_802_11 parse802_11(const u_char* packet);
bool chkBeacon(ST_802_11 target);
std::string getBssid(ST_802_11 bch);