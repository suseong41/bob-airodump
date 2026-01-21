#include <stdio.h>
#include <pcap.h>
#include "beacon.h"

// http://www.ktword.co.kr/test/view/view.php?no=2319
ST_BC_HDR parseBeacon(const u_char* packet)
{
    ST_BC_HDR *pHdr = (ST_BC_HDR*)packet; 
    return *pHdr;
}

