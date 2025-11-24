#include <stdio.h>
#include <pcap.h>

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t **alldevsp;
    pcap_findalldevs(alldevsp, errbuf);
	if (alldevsp == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	printf("Device: %s\n", (*alldevsp)->name);

    pcap_t *handle;

    handle = pcap_open_live((*alldevsp)->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", (*alldevsp)->name, errbuf);
        return(2);
    } else {
        printf("Device %s opened successfully\n", (*alldevsp)->name);
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", (*alldevsp)->name);
        return(2);
    }
    else 
    {
        printf("Device %s supports Ethernet headers\n", (*alldevsp)->name);
    }
	return(0);
}