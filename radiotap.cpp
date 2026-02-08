#include <stdio.h>
#include <pcap.h>
#include "radiotap.h"

// https://www.radiotap.org
ST_RDT capRdt(const u_char* packet)
{
    ST_RDT *pHdr = (ST_RDT*)packet;
    //printf("len = %d -> ", pHdr->len);
    return *pHdr;
}

static bool hasNextPresent(uint32_t present)
{
    if ((present & 0x80000000) != 0)
    {
        return true;
    }
    return false;
}

int presentCount(const u_char* packet)
{
    int count = 0;
    uint32_t* presentPtr = (uint32_t*)(packet+4);
    while (true)
    {
        uint32_t present = *presentPtr;
        count ++;
        if(hasNextPresent(present))
        {
            presentPtr++;
        }
        else break;
    }
    return count;
}

bool hasFcs(const u_char* packet, ST_RDT *rdt, int presentCount)
{
    uint32_t present = rdt->present;
    const u_char* data = (packet+4+4*presentCount);
    int alignment = 0;
    if ((present & 0x00000001) != 0)
    {
        if ((presentCount%2) == 0) alignment = 4;
        //uint64_t mactime = (uint64_t)*(data+alignment); // 8바이트단위 아니면 정렬 필요.
        if ((present & 0x00000002) != 0)
        {
            uint8_t flags = *(data+8+alignment);
            if ((flags & 0x10) != 0) return true;
        }
    }
    else
    {
        if ((present & 0x00000002) != 0)
        {
            uint8_t flags = *data;
            if ((flags & 0x10) != 0) return true;
        }
    }

    return false;
}