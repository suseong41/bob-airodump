#pragma once
#pragma pack(push,1)
struct ST_RDT
{
    uint8_t version;
    uint8_t padding;
    uint16_t len;
    uint32_t present;
} __attribute__((packed));

ST_RDT capRdt(const u_char* packet);
int presentCount(const u_char* packet);