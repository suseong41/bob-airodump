#include <stdio.h>
#include <pcap.h>
#include "radiotap.h"

// https://www.radiotap.org
ST_RDT_HDR parseRadiotap(const u_char* packet)
{
    ST_RDT_HDR *pHdr = (ST_RDT_HDR*)packet; 
    //printf("len = %d -> ", pHdr->len);
    return *pHdr;
}

int getPower()
{
    return 0;
}