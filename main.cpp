#include <stdio.h>
#include <string>
#include <vector>
#include <map>
#include <pcap.h>
#include <iostream>
#include <unistd.h>

#include "mac.h"
#include "radiotap.h"
#include "wireless.h"

struct ST_PRINT
{   
    std::string BSSID;
    std::string PWR;
    std::string BEACONS;
    std::string DATA;
    //std::string s;
    std::string CH;
    //std::string MB;
    std::string ENC;
    //std::string CIPHER;
    //std::string AUTH;
    std::string ESSID;
};

static std::string prtMac(ST_MAC mac)
{
    std::string prt = "";
    char buf[4];
    for (int i=0; i<sizeof(mac); i++)
    {
        sprintf(buf, "%02X", mac.mac[i]);
        prt += buf;

        if ( i != 5) prt += ":";
    }

    return prt;
}
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
        ST_RDT rdt = capRdt(packet);
        ST_WL wl = capWl(packet+rdt.len);
        uint64_t wirelessLen = sizeof(wl);
        if (!chkBeacon(wl)) continue;
        //printf("beacon frame cpatured\n");
        ST_PRINT prt;
        prt.BSSID = prtMac(wl.bssid);
        ST_BC_COMMON bc_commoon = capBc(packet+wirelessLen);
        uint64_t bcLen = sizeof(bc_commoon);
        //printf("tag loc: %d\n", rdt.len+wirelessLen+bcLen);
        const u_char* tagStart = (packet+rdt.len+wirelessLen+bcLen);
        prt.ESSID = getEssid(tagStart, (header->caplen)-rdt.len-wirelessLen-bcLen);
        std::map<std::string, int> info = getRdtInfo(packet, &rdt, presentCount(packet));
        if (info["PWR"] != 999) prt.PWR = std::to_string(info["PWR"]);
        if (info["CH"] != 0) prt.CH = std::to_string(info["CH"]);

        printf("BSSID: %s  PWR: %s  CH: %s   ESSID: %s\n", prt.BSSID.c_str(),prt.PWR.c_str(),prt.CH.c_str(), prt.ESSID.c_str());
        //uint64_t subtypes = *(packet+headerLen);
        //uint64_t ssidLen = *(packet+headerLen+37);
        //uint64_t ssid = *(packet+headerLen+38);
        /*
        if (subtypes == 0x80)
        {
            //clean();
            //printf("radiotap len = %d, type = %x\n", headerLen, subtypes);
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