#include <stdio.h>
#include <string>
#include <map>
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

// http://www.ktword.co.kr/test/view/view.php?no=5088
static int channelFromMhz(uint16_t freq)
{ // 14번 빼고는 5간격 인듯?
    if (freq == 2412) return 1;
    if (freq == 2417) return 2;
    if (freq == 2422) return 3;
    if (freq == 2427) return 4;
    if (freq == 2432) return 5;
    if (freq == 2437) return 6;
    if (freq == 2442) return 7;
    if (freq == 2447) return 8;
    if (freq == 2452) return 9;
    if (freq == 2457) return 10;
    if (freq == 2462) return 11;
    if (freq == 2467) return 12;
    if (freq == 2472) return 13;
    if (freq == 2484) return 14;
    return 0;
}

// PWR은 present에서 { 5 Antenna Signal } 부분을 파싱해야 함.
// 그에따라 앞에 여부를 다 확인해야함.
std::map<std::string, int> getRdtInfo(const u_char* packet, ST_RDT *rdt, int presentCount)
{
    std::map<std::string, int> info;
    uint32_t present = rdt->present;
    int offset = 4 + 4*presentCount;

    if ((present & (1<<0)) != 0) // 0. TSFT
    {
        while ( (offset % 8) != 0 ) offset++;
        offset += 8;
    }
    if ((present & (1<<1)) != 0) // 1. FLAGS
    {
        offset += 1;
    }
    if ((present & (1<<2)) != 0) // 2. Rate
    {
        offset += 1;
    }
    if ((present & (1<<3)) != 0) // 3. Channel
    {
        while ( (offset % 2) != 0 ) offset++;
        uint16_t freq = *(uint16_t*)(packet + offset);
        info["CH"] = channelFromMhz(freq); // 0 is None
        offset += 4;
    }
    if ((present & (1<<4)) != 0) // 4. FHSS
    {
        while ( (offset % 2) != 0 ) offset++;
        offset += 2;
    }
    if ((present & (1<<5)) != 0) // 5. Antenna Signal
    {
        info["PWR"] = (int8_t)packet[offset]; // 999 is None
    }

    return info;
}