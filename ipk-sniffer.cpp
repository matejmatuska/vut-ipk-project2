#include <iostream>
#include <iomanip>
#include <string>

#include <ctime>
#include <cctype>
#include <cstring>

#include <pcap/pcap.h>

#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

using namespace std;

// IPv6 header length
#define IP6_HDR_LEN 40;

/**
 * Structure for program arguments
 */
struct args {
    char *interface;
    size_t num_packets;
    int port;
    // filters
    int tcp;
    int udp;
    int icmp;
    int arp;
};

/**
 * Macros for option parsing
 */
#define IF_OPTION(short, long) \
    if (strcmp((short), argv[i]) == 0 || strcmp((long), argv[i]) == 0)

#define IF_L_OPTION(long) \
    if (strcmp((long), argv[i]) == 0)

#define IF_S_OPTION(short) \
    if (strcmp((short), argv[i]) == 0)

#define REQUIRE_ARGUMENT()                                            \
    do {                                                              \
        if (!arg) {                                                   \
            cerr << "Option" << argv[i] << "requires an argument.\n"; \
            return 0;                                                 \
        }                                                             \
        i++;                                                          \
    } while (0);

/**
 * Parses program arguments into args.
 * If an error is encountered, erorr message is printed to stderr and 0 is returned
 * 
 * @param args structure for arguments
 * @param argc argument count, usually from main()
 * @param argv arguments, usually from main()
 * @return 1 on success, 0 on error
 */
bool parse_args(struct args *args, int argc, char *argv[])
{
    if (argc == 1)
        return true;

    if (argc == 2) {
        if (strcmp("-i", argv[1]) == 0) {
            return true;
        } else {
            cerr << "Invalid argument: " << argv[1] << ".\n";
            return false;
        }
    }

    for (int i = 1; i < argc; i++) {
        char *arg = i + 1 < argc ? argv[i + 1] : nullptr;

        IF_OPTION("-i", "--interface") {
            REQUIRE_ARGUMENT();
            args->interface = arg;

        } else IF_S_OPTION("-p") {
            REQUIRE_ARGUMENT();
            char *rest;
            args->port = strtol(arg, &rest, 10);
            if (*rest != '\0' || args->port < 0) {
                cerr << "Port must me a positive integer." << endl;
                return false;
            }
        } else IF_OPTION("-t", "--tcp") {
            args->tcp = 1;
        } else IF_OPTION("-u", "--udp") {
            args->udp = 1;
        } else IF_L_OPTION("--arp") {
            args->arp = 1;
        } else IF_L_OPTION("--icmp") {
            args->icmp = 1;
        } else IF_S_OPTION("-n"){
            REQUIRE_ARGUMENT();
            char *rest;
            args->num_packets = strtoul(arg, &rest, 10);
            if (*rest != '\0' || args->num_packets <= 0) {
                cerr << "Argument for -n must be a positive integer." << endl;
                return false;
            }
        } else {
            cerr << "Invalid arguments: " << argv[i] << ".\n";
            return false;
        }
    }
    return true;
}

/**
 * Prints active network devices to stdout
 * @pararm errbuff buffer for pcap error messages, see libpcap docs
 * @return nonzero value on success, 0 if an error occured
 */
int print_active_devices(char *errbuff)
{
    pcap_if_t *devices;
    if (pcap_findalldevs(&devices, errbuff) == PCAP_ERROR) {
        cerr << errbuff << endl;
        return 1;
    }
    if (devices == NULL) {
        cout << "There are no active devices." << endl;
        return 0;
    }

    pcap_if_t *device = devices;
    while (device) {
        if (device->flags & PCAP_IF_RUNNING) // TODO are active RUNNING or UP?
            // TODO print "any"?
            cout << device->name << endl;
        device = device->next;
    }
    pcap_freealldevs(devices);
    return 0;
}

/**
 * Builds filter for pcap_compile() from program arguments
 * @param args program arguments
 * @return filter for pcap_compile
 */
std::string build_filter(struct args *args)
{
    std::string filter;
    int first = 1;
    if (args->tcp) {
        filter += "tcp";
        first = 0;
    }
    if (args->udp) {
        if (!first)
            filter += " or ";
        filter += "udp";
        first = 0;
    }
    if (args->arp) {
        if (!first)
            filter += " or ";
        filter += "arp";
        first = 0;
    }
    if (args->icmp) {
        if (!first)
            filter += " or ";
        filter += "icmp";
        first = 0;
    }

    // TODO no port if no filter
    if (args->port >= 0) {
        // TODO shouldn't the filters be in parentheses
        if (filter.empty())
            filter += "port " + std::to_string(args->port);
        else
            filter += " and port " + std::to_string(args->port);
    }

    return filter;
}

/**
 * Prints raw packet to stdout in the following format:
 *
 * offset_of_printed_bytes: bytes_hex bytes_ascii
 *
 * @param size packet size
 * @param pkt raw packet
 */
void print_raw_pkt(size_t size, const u_char *pkt)
{
    auto cf = cout.flags();

    cout << hex; // hex is set until reset
    for (size_t offset = 0; offset < size; offset += 16) {
        cout << "0x" << setw(4) << setfill('0') << offset << ":  ";

        // print bytes in hex
        for (size_t i = 0; i < 16; i++) {
            int c = offset + i < size ? pkt[offset + i] : 0;
            cout << setw(2) << setfill('0') << c << " ";

            if (i == 7)
                cout << " ";
        }
        // print bytes in ascii
        for (size_t i = 0; i < 16; i++) {
            int c = offset + i < size ? pkt[offset + i] : 0;
            char p = isprint(c) ? c : '.';
            cout << p;

            if (i == 7)
                cout << " ";
        }
        cout << endl;
    }
    cout.flags(cf); // reset flags
}

/**
 * Prints source and destination ports from TCP header
 * @param header TCP header
 */
void process_tcp(const struct tcphdr *header)
{
    cout << "src port: " << ntohs(header->th_sport) << endl;
    cout << "dst port: " << ntohs(header->th_dport) << endl;
}

/**
 * Prints source and destination ports from UDP header
 * @param header UDP header
 */
void process_udp(const struct udphdr *header)
{
    cout << "src port: " << ntohs(header->uh_sport) << endl;
    cout << "dst port: " << ntohs(header->uh_dport) << endl;
}

/**
 * Prints information from IPv4 packet
 * @param raw_ip raw IPv4 header
 */
void process_ip(const u_char *raw_ip)
{
    const struct ip *hdr = reinterpret_cast<const struct ip*>(raw_ip);
    cout << "src IP: " << inet_ntoa(hdr->ip_src) << endl;
    cout << "dst IP: " << inet_ntoa(hdr->ip_dst) << endl;

    switch (hdr->ip_p) {
        case IPPROTO_TCP:
            {
                const u_char *raw_tcp = raw_ip + hdr->ip_hl * 4;
                process_tcp(reinterpret_cast<const struct tcphdr*>(raw_tcp));
            }
            break;
        case IPPROTO_UDP:
            {
                const u_char *raw_udp = raw_ip + hdr->ip_hl * 4;
                process_udp(reinterpret_cast<const struct udphdr*>(raw_udp));
            }
            break;
        case IPPROTO_ICMP:
            // TODO maybe add soem data
            break;
        default:
            cerr << "Unhandled IP protocol: " << hdr->ip_p << endl;
    }
}

/**
 * @param addr MAC address as array of bytes 
 * @param addr_len number of bytes in addr
 *
 * @return MAC address in standardized format as string
 */
string mac_as_string(const uint8_t *addr, int addr_len)
{
    ostringstream stream;
    stream << hex;
    int i = 0;
    while (i < addr_len - 1) {
        stream << setw(2) << setfill('0') << (int) addr[i] << ':';
        i++;
    }
    stream << setw(2) << setfill('0') << (int) addr[i];
    return stream.str();
}

/**
 * Prints information from IPv6 packet
 *
 * @param raw_ip raw IPv6 header
 */
void process_ip6(const u_char *raw_ip)
{
    const struct ip6_hdr *hdr = reinterpret_cast<const struct ip6_hdr*>(raw_ip);

    char buff[256];
    const char *src_addr = inet_ntop(AF_INET6, &hdr->ip6_src, buff, 256);
    const char *dst_addr = inet_ntop(AF_INET6, &hdr->ip6_dst, buff, 256);
    cout << "src IP: " << src_addr << endl;
    cout << "dst IP: " << dst_addr << endl;

    switch (hdr->ip6_nxt) {
        case IPPROTO_TCP:
            {
                const u_char *raw_tcp = raw_ip + IP6_HDR_LEN;
                process_tcp(reinterpret_cast<const struct tcphdr*>(raw_tcp));
            }
            break;
        case IPPROTO_UDP:
            {
                const u_char *raw_udp = raw_ip + IP6_HDR_LEN;
                process_udp(reinterpret_cast<const struct udphdr*>(raw_udp));
            }
            break;
        case IPPROTO_ICMPV6:
            break;
        default:
            cerr << "Unhandled IP protocol: " << hdr->ip6_nxt << endl;
    }
}

/**
 * Returns a string with timestamp ts in RFC 3339 format
 *
 * @param ts timestamp
 * @return string with formatted timestamp
 */
string format_timestamp(struct timeval *ts)
{
    ostringstream ts_str;
    struct tm *time = localtime(&(ts->tv_sec));
    char datetime[32];
    char offset[16];
    strftime(datetime, sizeof(datetime) - 1, "%FT%T.", time);

    // format the offset
    size_t j = strftime(offset, sizeof(offset) - 1, "%z", time); // get offset
    if (strcmp(offset, "+0000") == 0) {
        offset[0] = 'Z';
        offset[1] = '\0';
    } else {
        // insert ':' into the offset
        for (int i = 0; i < 3; i++) {
            offset[j] = offset[j - 1];
            j--;
        }
        offset[j + 1] = ':';
    }
    ts_str << "timestamp: " << datetime;
    ts_str << fixed << setprecision(3) << ts->tv_usec / 1000 << offset;
    return ts_str.str();
}

/**
 * Processes and prints packets data from raw packet.
 *
 * @param pkt_header pcap packet header
 * @param raw_pkt raw packet
 */
void process_packet(struct pcap_pkthdr *pkt_hdr, const u_char *raw_pkt)
{
    cout << format_timestamp(&pkt_hdr->ts) << endl;

    struct ether_header *ehdr = (struct ether_header*) raw_pkt;
    // TODO byte order?
    string src_addr = mac_as_string(ehdr->ether_shost, ETHER_ADDR_LEN);
    string dst_addr = mac_as_string(ehdr->ether_dhost, ETHER_ADDR_LEN);
    cout << "src MAC: " << src_addr << endl;
    cout << "dst MAC: " << dst_addr << endl;

    cout << "frame length: " << pkt_hdr->len << " bytes" << endl;

    if (ntohs(ehdr->ether_type) == ETHERTYPE_IP) {
        const u_char *raw_ip = raw_pkt + ETHER_HDR_LEN;
        process_ip(raw_ip);
    } else if (ntohs(ehdr->ether_type) == ETHERTYPE_IPV6) {
        const u_char *raw_ip = raw_pkt + ETHER_HDR_LEN;
        process_ip6(raw_ip);
    }
    print_raw_pkt(pkt_hdr->caplen, raw_pkt);
    cout << endl;
}

int main(int argc, char *argv[])
{
    struct args args;
    memset(&args, 0, sizeof(struct args)); // initialize everything to 0
    // defaults
    args.port = -1;
    args.num_packets = 1; 
    if (!parse_args(&args, argc, argv)) {
        // err printed in parse_args()
        return 1;
    }

    char errbuff[PCAP_ERRBUF_SIZE];
    if (pcap_init(PCAP_CHAR_ENC_LOCAL, errbuff) == -1) {
        cerr << "Failed initializing pcap: " << errbuff << endl;
        return 1;
    }

    if (!args.interface) {
        print_active_devices(errbuff);
        return 0;
    }

    pcap_t *handle = pcap_create(args.interface, errbuff);
    if (handle == NULL) {
        cerr << "Failed creating interface handle: " << errbuff << endl;
        return 1;
    }

    pcap_set_promisc(handle, 1); // set interface card to promiscious mode
    pcap_set_immediate_mode(handle, 1); // receive buckets without buffering

    int result = pcap_activate(handle);
    if (result < 0) {
        cerr << "Err activating capture: ";
        switch (result) {
            case PCAP_ERROR_PERM_DENIED:
                cerr << "Permission denied.";
                break;
        }
        cerr << endl;
        pcap_close(handle); // we sould close, see docs
        return 1;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        cerr << "Only LINKTYPE_ETHERNET is supported." << endl;
        pcap_close(handle);
        return 1;
    }

    string program = build_filter(&args);
    bpf_program filter;
    if (pcap_compile(handle, &filter, program.c_str(), 1, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR) {
        pcap_perror(handle, "Failed compiling filter: ");
        pcap_close(handle);
        return 1;
    }
    if (pcap_setfilter(handle, &filter) == PCAP_ERROR) {
        pcap_perror(handle, "Failed setting filter: ");
        pcap_close(handle);
        return 1;
    }
    pcap_freecode(&filter);

    struct pcap_pkthdr *pkt_header = NULL;
    const u_char *pkt_data = NULL;
    for (size_t i = 0; i < args.num_packets; i++) {
        int res = pcap_next_ex(handle, &pkt_header, &pkt_data);
        if (!res) {
            if (res == PCAP_ERROR) {
                pcap_perror(handle, "Failed reading packet: ");
                pcap_close(handle);
                return 1;
            }
            if (res == 0) {
                cerr << "Buffer timeout" << endl;
                continue;
            }
            cerr << "Failed reading packet" << endl;
            return 1;
        }
        process_packet(pkt_header, pkt_data);
    }

    pcap_close(handle);
    return 0;
}
