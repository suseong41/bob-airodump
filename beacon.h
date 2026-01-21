struct ST_BC
{
    uint64_t timestamp;
    uint16_t interval;
    uint16_t capacity;
} __attribute__((packed));

ST_BC parseBeacon(const u_char* packet);
std::string getEssid(const u_char* packet, const int beaconLen);