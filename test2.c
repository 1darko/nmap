#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

// Calcul checksum
unsigned short checksum(unsigned short *ptr, int nbytes) {
    long sum;
    unsigned short oddbyte;
    unsigned short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *) ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}

int main() {
    pcap_if_t **alldevsp;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_findalldevs(alldevsp, errbuf);                // Interface réseau
    char *dst_ip = "192.168.1.10";      // IP cible
    int dst_port = 80;                  // Port cible


    // === 1. Ouvrir capture PCAP ===
    pcap_t *handle = pcap_open_live((*alldevsp)->name, 65535, 0, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Erreur pcap_open_live: %s\n", errbuf);
        return 1;
    }

    // Filtre capture : TCP depuis la cible vers nous
    char filter_exp[256];
    sprintf(filter_exp, "tcp and src host %s", dst_ip);

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Erreur pcap_compile\n");
        return 1;
    }
    pcap_setfilter(handle, &fp);

    // === 2. Socket brut pour envoyer le paquet ===
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    // Dire que l'on fournit l'entête IP
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    // === 3. Construire le paquet IP+TCP ===
    char packet[4096];
    memset(packet, 0, sizeof(packet));

    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    // IP header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = htons(443);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = inet_addr("8.8.8.8");    // TON IP source (à adapter)
    iph->daddr = inet_addr(dst_ip);

    iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));

    // TCP header
    tcph->source = htons(44444);   // ton port source aléatoire
    tcph->dest = htons(dst_port);
    tcph->seq = htonl(1);
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->syn = 0;
    tcph->ack = 1;                 // FLAG ACK !!!
    tcph->window = htons(1024);

    // Pseudo-header pour checksum TCP
    struct pseudo_header {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t length;
    } psh;

    psh.src = iph->saddr;
    psh.dst = iph->daddr;
    psh.zero = 0;
    psh.proto = IPPROTO_TCP;
    psh.length = htons(sizeof(struct tcphdr));

    char pseudo_packet[4096];
    memcpy(pseudo_packet, &psh, sizeof(psh));
    memcpy(pseudo_packet + sizeof(psh), tcph, sizeof(struct tcphdr));

    tcph->check = checksum((unsigned short *)pseudo_packet,
                           sizeof(psh) + sizeof(struct tcphdr));

    // === 4. Envoyer le paquet ===
    struct sockaddr_in dst;
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = iph->daddr;

    if (sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr),
               0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        perror("sendto");
        return 1;
    }

    printf("Paquet ACK envoyé. En attente de réponse...\n");

    // === 5. Lire une réponse avec PCAP ===
    struct pcap_pkthdr *header;
    const u_char *data;
    int res = pcap_next_ex(handle, &header, &data);

    if (res > 0) {
        const struct iphdr *rip = (struct iphdr *)(data + 14); // Ethernet offset
        const struct tcphdr *rtcp = (struct tcphdr *)(data + 14 + rip->ihl * 4);

        if (rtcp->rst) {
            printf("Réponse RST reçue → port NON FILTRÉ\n");
        } else {
            printf("Autre réponse reçue (flags=%d)\n", rtcp->rst);
        }
    } else {
        printf("Aucune réponse → port FILTRÉ\n");
    }

    pcap_close(handle);
    close(sock);

    return 0;
}
