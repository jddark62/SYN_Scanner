
#include "main.h"

unsigned short checkSum(unsigned short*, int);
const char* dottedDecimal(const struct in_addr*);

__attribute__((unused)) char* hostnameToIp(char*);
void ipToHost(const char*, char*);
void* receiveAck(void*);
void initPacket(unsigned char*, int, char*);
void strToInt(int*, char*, int);
void localIp(char*);
void exitFailure(char*, ...);
void initDatagram(char*, const char*, struct iphdr*, struct tcphdr*);
void parseTarget(char*, struct in_addr*, int64_t*);
int parseCidr(const char*, struct in_addr*, struct in_addr*);

//to do a proper checksum
struct pseudoHeader { //Needed for checksum calculation
    unsigned int sourceAddress;
    unsigned int destAddress;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;

    struct tcphdr tcp;
};

struct in_addr destinationIP;
unsigned openHosts = 0;

int main(int argc, char* argv[])
{
    double scanDuration;
    struct timespec begin, finish;
    clock_gettime(CLOCK_MONOTONIC, &begin);

    if (argc != 3) {
        printf("Please use this format:\n");
        printf("%s <IP/CIDR> <port-1, port-2, ....>\n", argv[0]);
        printf("Cases:\n");
        printf("\t%s 10.1.82.13 80,443,8080\n", argv[0]);
        printf("\t%s 10.1.82.13 80\n", argv[0]);

        return 1;
    }

    printf("Stealth Scanning [%s]:[%s]\n", argv[1], argv[2]);

    //storing original port list
    char* list = malloc(strlen(argv[2]) + 1);
    strcpy(list, argv[2]);

    int64_t numberOfHosts;
    struct in_addr target_in_addr;
    parseTarget(argv[1], &target_in_addr, &numberOfHosts); //Parse the selected target hosts

    //fetching local IP of the machine for IP header in Datagram
    char sourceIp[INET6_ADDRSTRLEN];
    localIp(sourceIp);

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP); //This is the main socket to send the SYN packet
    if (sockfd < 0)
        exitFailure("Error creating socket. Error number: %d. Error message: %s\n", errno, strerror(errno));

    //ID_HDRINCL to not use kernel's ip header
    int oneVal = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &oneVal, sizeof(oneVal)) < 0)
        exitFailure("Error in setting IP_HDRINCL. Error number: %d. Error message: %s\n", errno, strerror(errno));

    int host_count;
    for (host_count = 0; host_count < numberOfHosts; host_count++) {
        destinationIP.s_addr = inet_addr(dottedDecimal(&target_in_addr)); //Current iteration's target host address
        if (destinationIP.s_addr == -1)
            exitFailure("Invalid address\n");

        // IP_Header--TCP_Header--Data
        char DATAGRAM[4096];
        //a.Initializing TCP/IP Packet
        //Creating IP Header
        struct iphdr* ipHeader = (struct iphdr*)DATAGRAM;
        //Initialize TCP Header
        struct tcphdr* tcpHeader = (struct tcphdr*)(DATAGRAM + sizeof(struct ip));

        initDatagram(DATAGRAM, sourceIp, ipHeader, tcpHeader);

        pthread_t snifferThread;
        //Listens for one SYN-ACK packet from any port
        if (pthread_create(&snifferThread, NULL, receiveAck, NULL) != 0)
            exitFailure("Error in creation of sniffer thread. Error number: %d. Error message: %s\n", errno,
                        strerror(errno));

        strcpy(list, argv[2]);
        char* packetHeader = strtok(list, ",");
        //Iterating through all selected ports, sending SYN packets at once
        while (packetHeader != NULL)
        {
            struct sockaddr_in dest;
            struct pseudoHeader psh;

            dest.sin_family = AF_INET;
            dest.sin_addr.s_addr = destinationIP.s_addr;

            int port;
            strToInt(&port, packetHeader, 10);
            //Updating TCP Header with new port information
            tcpHeader->dest = htons(port);
            tcpHeader->check = 0;

            psh.sourceAddress = inet_addr(sourceIp);
            psh.destAddress = dest.sin_addr.s_addr;
            psh.placeholder = 0;
            psh.protocol = IPPROTO_TCP;
            psh.tcp_length = htons(sizeof(struct tcphdr));

            memcpy(&psh.tcp, tcpHeader, sizeof(struct tcphdr));
            //Calculating Checksum for TCP Header
            tcpHeader->check = checkSum((unsigned short *) &psh, sizeof(struct pseudoHeader));

            if (sendto(sockfd, DATAGRAM, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr*)&dest, sizeof(dest)) < 0)
                exitFailure("Error sending syn packet. Error number: %d. Error message: %s\n", errno, strerror(errno));

            packetHeader = strtok(NULL, ",");
        }
        //Waits for sniffer thread to reply, host is closed if there isn't a reply
        pthread_join(snifferThread, NULL);
        target_in_addr.s_addr = htonl(ntohl(target_in_addr.s_addr) + 1);
    }

    close(sockfd);

    clock_gettime(CLOCK_MONOTONIC, &finish);
    scanDuration = (double)(finish.tv_sec - begin.tv_sec);
    //conversion to seconds
    scanDuration += (double)(finish.tv_nsec - begin.tv_nsec) / 1000000000.0;

    int durationInHours = (int)scanDuration / 3600;
    int durationInMins = (int)(scanDuration / 60) % 60;
    double durationInSeconds = fmod(scanDuration, 60);

    printf("\nNumber of Active Hosts: %d\n", openHosts);
    printf("Stealth Scan Duration\t:%d hour(s) %d min(s) %.05lf sec(s)\n", durationInHours, durationInMins, durationInSeconds);

    return 0;
}

//Initializing datagram packet
void initDatagram(char* datagram, const char* source_ip, struct iphdr* ipheader, struct tcphdr* tcpheader)
{
    memset(datagram, 0, 4096);

    //Filling IP header
    ipheader->ihl = 5;
    ipheader->version = 4;
    ipheader->tos = 0;
    ipheader->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
    ipheader->id = htons(46156); //packet ID
    ipheader->frag_off = htons(16384);
    ipheader->ttl = 64;
    ipheader->protocol = IPPROTO_TCP;
    //Before calculating checksum, it is set to 0
    ipheader->check = 0;
    //Spoof the source ip address
    ipheader->saddr = inet_addr(source_ip);
    ipheader->daddr = destinationIP.s_addr;
    ipheader->check = checkSum((unsigned short*)datagram, ipheader->tot_len >> 1);

    //Filling TCP Header
    tcpheader->source = htons(46156);
    tcpheader->dest = htons(80);
    tcpheader->seq = htonl(1105024978); //Sequence number (32-bit)
    tcpheader->ack_seq = 0; //Acknowledgement Number (32-bit)
    tcpheader->doff = sizeof(struct tcphdr) / 4; //Data offset (size of tcp header - 4-byte units)
    tcpheader->fin = 0; //Finish flag "fin"
    tcpheader->syn = 1;
    tcpheader->rst = 0;
    tcpheader->psh = 0;
    tcpheader->ack = 0;
    tcpheader->urg = 0;
    tcpheader->window = htons(14600); // Receive window size (read from filesystem)
    tcpheader->check = 0; //Kernel's IP stack fills in correct checksum during transmission, if it is set to zero
    tcpheader->urg_ptr = 0;
}

/**
  Parse target IP into usable format
  Fill target_in_addr with first target IP and num_hosts with number of hosts
 */
void parseTarget(char* target, struct in_addr* target_in_addr, int64_t* num_hosts)
{
    struct in_addr parsed_in_addr, mask_in_addr, wildcard_in_addr, network_in_addr, broadcast_in_addr, min_in_addr, max_in_addr;

    int bits = parseCidr(target, &parsed_in_addr, &mask_in_addr);
    if (bits == -1)
        exitFailure("Invalid network address: %s\nValid example: 166.104.0.0/16\n", target);

    wildcard_in_addr = mask_in_addr;
    wildcard_in_addr.s_addr = ~wildcard_in_addr.s_addr;

    network_in_addr = parsed_in_addr;
    network_in_addr.s_addr &= mask_in_addr.s_addr;

    broadcast_in_addr = parsed_in_addr;
    broadcast_in_addr.s_addr |= wildcard_in_addr.s_addr;

    min_in_addr = network_in_addr;
    max_in_addr = broadcast_in_addr;

    if (network_in_addr.s_addr != broadcast_in_addr.s_addr) {
        min_in_addr.s_addr = htonl(ntohl(min_in_addr.s_addr) + 1);
        max_in_addr.s_addr = htonl(ntohl(max_in_addr.s_addr) - 1);
    }

    *target_in_addr = min_in_addr;
    *num_hosts = (int64_t)ntohl(broadcast_in_addr.s_addr) - ntohl(network_in_addr.s_addr) + 1;

    printf("%" PRId64 " host(s): ", *num_hosts);
    printf("%s -> ", dottedDecimal(&min_in_addr));
    printf("%s\n\n", dottedDecimal(&max_in_addr));
    fflush(stdout);
}

/**
  Convert string s to integer
 */
void strToInt(int* out, char* s, int base)
{
    if (s[0] == '\0' || isspace((unsigned char)s[0]))
        return;

    char* end;
    errno = 0;
    long l = strtol(s, &end, base);

    if (l > INT_MAX || (errno == ERANGE && l == LONG_MAX))
        return;
    if (l < INT_MIN || (errno == ERANGE && l == LONG_MIN))
        return;
    if (*end != '\0')
        return;

    *out = (int) l;
}

/**
  Parse CIDR notation address.
  Return the number of bits in the netmask if the string is valid.
  Return -1 if the string is invalid.
 */
int parseCidr(const char* cidr, struct in_addr* addr, struct in_addr* mask)
{
    int bits = inet_net_pton(AF_INET, cidr, addr, sizeof addr);

    mask->s_addr = htonl(~(bits == 32 ? 0 : ~0U >> bits));
    return bits;
}

/**
  Format the IPv4 address in dotted quad notation, using a static buffer.
 */
const char* dottedDecimal(const struct in_addr* addr)
{
    static char buf[INET_ADDRSTRLEN];

    return inet_ntop(AF_INET, addr, buf, sizeof buf);
}

/**
  Exit the program with EXIT_FAILURE code
 */
void exitFailure(char* fmt, ...)
{
    va_list ap;
    char buff[4096];

    va_start(ap, fmt);
    vsprintf(buff, fmt, ap);

    fflush(stdout);
    fputs(buff, stderr);
    fflush(stderr);

    exit(EXIT_FAILURE);
}

/**
  Method to sniff incoming packets and look for Ack replies
*/
int start_sniffer()
{
    int sock_raw;

    socklen_t saddr_size, data_size;
    struct sockaddr_in saddr;

    unsigned char* buffer = (unsigned char*)malloc(65536);

    //Create a raw socket that shall sniff
    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock_raw < 0) {
        printf("Socket Error\n");
        fflush(stdout);
        return 1;
    }

    saddr_size = sizeof(saddr);

    //Receive a packet
    data_size = recvfrom(sock_raw, buffer, 65536, 0, (struct sockaddr*)&saddr, &saddr_size);

    if (data_size < 0) {
        printf("Recvfrom error, failed to get packets\n");
        fflush(stdout);
        return 1;
    }

    initPacket(buffer, data_size, inet_ntoa(saddr.sin_addr));
    close(sock_raw);

    return 0;
}

/**
  Method to sniff incoming packets and look for Ack replies
*/
void* receiveAck(void* ptr)
{
    start_sniffer();

    return NULL;
}

/**
  Method to process incoming packets and look for Ack replies
*/
void initPacket(unsigned char* buffer, int size, char* source_ip)
{
    struct iphdr* ipheader = (struct iphdr*)buffer;
    struct sockaddr_in source, dest;
    unsigned short iphdrlen;

    if (ipheader->protocol == 6) {
        struct iphdr* iph = (struct iphdr*)buffer;
        iphdrlen = iph->ihl * 4;

        struct tcphdr* tcph = (struct tcphdr*)(buffer + iphdrlen);

        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = iph->saddr;

        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = iph->daddr;

        if (tcph->syn == 1 && tcph->ack == 1 && source.sin_addr.s_addr == destinationIP.s_addr) {
            char source_host[NI_MAXHOST];
            ipToHost(source_ip, source_host);
            printf("%s\t%s\n", source_ip, source_host);
            fflush(stdout);

            ++openHosts;
        }
    }
}

/**
 Checksums - IP and TCP
 */
unsigned short checkSum(unsigned short* ptr, int n_bytes)
{
    register long sum;
    register short answer;
    unsigned short odd_byte;

    sum = 0;
    while (n_bytes > 1) {
        sum += *ptr++;
        n_bytes -= 2;
    }

    if (n_bytes == 1) {
        odd_byte = 0;
        *((u_char*)&odd_byte) = *(u_char*)ptr;
        sum += odd_byte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;

    return answer;
}

/**
  Get ip from domain name
 */
char* hostnameToIp(char* hostname)
{
    struct hostent* he;
    struct in_addr** addr_list;

    if ((he = gethostbyname(hostname)) == NULL)
        exitFailure("gethostbyname");

    addr_list = (struct in_addr**)he->h_addr_list;

    int a;
    for (a = 0; addr_list[a] != NULL; a++)
        return inet_ntoa(*addr_list[a]); //Return the first one;

    return NULL;
}

/**
 Get source IP of the system running this program
 */
void localIp(char* buffer)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    const char* kGoogleDnsIp = "8.8.8.8";
    int dns_port = 53;

    struct sockaddr_in serv;

    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
    serv.sin_port = htons(dns_port);

    if (connect(sock, (const struct sockaddr*)&serv, sizeof(serv)) != 0)
        exitFailure("Failed to get local IP\n");

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);

    if (getsockname(sock, (struct sockaddr*)&name, &namelen) != 0)
        exitFailure("Failed to get local IP");

    inet_ntop(AF_INET, &name.sin_addr, buffer, INET6_ADDRSTRLEN);

    close(sock);
}

/**
 Get hostname of an IP address
 */
void ipToHost(const char* ip, char* buffer)
{
    struct sockaddr_in dest;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(ip);
    dest.sin_port = 0;

    if (getnameinfo((struct sockaddr*)&dest, sizeof(dest), buffer, NI_MAXHOST, NULL, 0, NI_NAMEREQD) != 0)
        strcpy(buffer, "Hostname cannot be fetched/determined.");
}