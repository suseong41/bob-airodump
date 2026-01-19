#include <stdio.h>
#include <string.h>

int main()
{
    printf("hello world\n");
    printf("%-17s %3s %-7s %s %s %2s %3s %4s %6s %4s %5s\n", 
        "BSSID", "PWR", "BEACONS", "DATA", "/s", "CH", "MB", "ENC", "CIPHER", "AUTH", "ESSID");
    return 0;
}