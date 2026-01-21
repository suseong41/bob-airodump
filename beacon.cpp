#include <stdio.h>
#include <string>
#include <pcap.h>
#include "beacon.h"

//http://www.ktword.co.kr/test/view/view.php?m_temp1=4906&id=758
ST_BC parseBeacon(const u_char* packet)
{
    ST_BC *pHdr = (ST_BC*)packet;
    return *pHdr;
}

std::string getEssid(const u_char* packet, const int beaconLen)
{
    const u_char* index = packet;
    const u_char* end = index + beaconLen;
    while(index < end)
    {
        uint8_t tagId = index[0];
        uint8_t tagLen = index[1];
        const u_char* data = index + 2;
        if (tagId == 0)
        {   
            if (tagLen == 0) return "<length: 0>";
            // <length: n> 찍히던거는 00으로 설정된거 길이인듯..?
            if (data[0] == 0 | data[1] == 0) return "<length: " + std::to_string(tagLen) + ">";
            return std::string((char*)data, tagLen);
        }
        index += (2 + tagLen);
    }
    
    return ""; 
}