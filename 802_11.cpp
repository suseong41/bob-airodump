#include <stdio.h>
#include <pcap.h>
#include "802_11.h"

// http://www.ktword.co.kr/test/view/view.php?m_temp1=3352&id=761
// addr4는 무선 브리지라 비콘이랑 관련없는듯함

ST_802_11 parse802_11(const u_char* packet)
{
    ST_802_11 *pHdr = (ST_802_11*)packet; 
    return *pHdr;
}