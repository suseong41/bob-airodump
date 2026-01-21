#include <stdio.h>
#include <string>
#include <vector>
#include <map>
#include <stdbool.h>
#include <pcap.h>
#include <iostream>
#include <unistd.h>

#include "radiotap.h"
#include "beacon.h"

struct ST_PRINT
{   
    std::string BSSID;
    //std::string PWR;
    std::string BEACONS;
    std::string DATA;
    //std::string s;
    //std::string CH;
    //std::string MB;
    std::string ENC;
    //std::string CIPHER;
    //std::string AUTH;
    std::string ESSID;
};

std::map<ST_PRINT, std::string> printDump()
{
    std::map<ST_PRINT, std::string> print;
    return print;
}

void usage()
{
    printf("syntax: airodump <interface>\n");
    printf("sample: airodump mon0");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void clean()
{   
    std::cout << "\033[H\033[2J\033[3J";
}
// BSSID, BEACONS, 
int main(int argc, char* argv[])
{
    if(!parse(&param, argc, argv)) { return -1; }
    
    //clean();
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }
    
    while(true)
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) 
        {
            printf("Timeout... (No packets)\n"); continue;
        }
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        //printf("%u bytes captured\n", header->caplen);
        ST_RDT_HDR rdt = parseRadiotap(packet);
        ST_BC_HDR bc = parseBeacon(packet+rdt.len);
        //uint64_t subtypes = *(packet+headerLen);
        //uint64_t ssidLen = *(packet+headerLen+37);
        //uint64_t ssid = *(packet+headerLen+38);
        /*
        if (subtypes == 0x80)
        {
            //clean();
            //printf("radiotap len = %d, type = %x\n", headerLen, subtypes);
            //printf("Beacon Frame Captured\n");
            printf("bssid: ");
            for (int i=0; i<6; i++)
            {
                if (i == 5)
                {
                    printf("%02x\n", *(packet+headerLen+16+i));
                } else 
                {
                    printf("%02x:", *(packet+headerLen+16+i));
                }
            }
            //printf("ssid len = %x", ssidLen);
            //printf("%d\n", ssid);
            //std::cout << std::flush;
            //sleep(0.5);
        }
        */
        
    }
    
    pcap_close(pcap);
    
    
    printf("%-17s %3s %-7s %s %s %2s %3s %4s %6s %4s %5s\n", 
        "BSSID", "PWR", "BEACONS", "DATA", "/s", "CH", "MB", "ENC", "CIPHER", "AUTH", "ESSID");
    
    // 한 채널만 사용하면 잘 안보인다.. 왜 그럴까?
    // 일단.. sudo iwconfig mon0 channel 1 ~ 5로 먼저 하자..
    // channel hopping을 한다면.. 어떤 채널인지 상단에 나와야 할듯..

    // 라디오탭 중 길이 읽기
    // 길이만큼 점프, 해당 부분에서 0x0008이 나오는지 확인1
    return 0;
}