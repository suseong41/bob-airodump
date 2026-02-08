#include <stdio.h>
#include <string>
#include <pcap.h>
#include "mac.h"
#include "wireless.h"

// http://www.ktword.co.kr/test/view/view.php?m_temp1=3352&id=761
// http://www.ktword.co.kr/test/view/view.php?no=2319
// addr4는 무선 브리지라 비콘이랑 관련없는듯함

ST_WL capWl(const u_char* packet)
{
    ST_WL *pHdr = (ST_WL*)packet;
    return *pHdr;
}

//http://www.ktword.co.kr/test/view/view.php?m_temp1=4906&id=758
ST_BC_COMMON capBc(const u_char* packet)
{
    ST_BC_COMMON *pHdr = (ST_BC_COMMON*)packet;
    return *pHdr;
}

bool chkBeacon(ST_WL target)
{    
    // wifi 00, type 00(관리), subtypes 1000(비콘) [리틀엔디안]
    if ((target.framControl & 0x00FF) == 0x80) return true;
    return false;
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