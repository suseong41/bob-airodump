#include <stdio.h>
#include <string>
#include <pcap.h>
#include "802_11.h"

// http://www.ktword.co.kr/test/view/view.php?m_temp1=3352&id=761
// http://www.ktword.co.kr/test/view/view.php?no=2319
// addr4는 무선 브리지라 비콘이랑 관련없는듯함

ST_802_11 parse802_11(const u_char* packet)
{
    ST_802_11 *pHdr = (ST_802_11*)packet; 
    return *pHdr;
}

bool chkBeacon(ST_802_11 target)
{    
    // wifi 00, type 00(관리), subtypes 1000(비콘) [리틀엔디안]
    if ((target.framControl & 0x00FF) == 0x80) return true;
    return false;
}

std::string getBssid(ST_802_11 bch)
{
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
        bch.bssid[0], bch.bssid[1], bch.bssid[2], bch.bssid[3], bch.bssid[4], bch.bssid[5]);
    return std::string(buf);
}