#include "arper.h"

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <asm/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <arpa/inet.h>  //htons etc
#include <errno.h>
#include <iomanip>
#include <sstream>
#include <sys/types.h>
#include <ifaddrs.h>
#include <unordered_set>

struct arp_header {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_len;
    uint8_t protocol_len;
    uint16_t opcode;
    uint8_t sender_mac[arper_consts::MAC_LENGTH];
    uint8_t sender_ip[arper_consts::IPV4_LENGTH];
    uint8_t target_mac[arper_consts::MAC_LENGTH];
    uint8_t target_ip[arper_consts::IPV4_LENGTH];
};

ARPer::ARPer():
    _arp_fd(-1), _ifname("")
{}

/*
 *
 * Sample code that sends an ARP who-has request on
 * interface <ifname> to IPv4 address <ip>.
 * Returns 0 on success.
 */
int ARPer::probe(ARP_res_t &res)
{
    uint32_t dst = inet_addr(res.ip.c_str());
    if (dst == 0 || dst == 0xffffffff) {
        std::cerr << "Invalid source IP\n" << std::endl;
        return -EINVAL;
    }

    if (this->_send_arp(dst)) {
        std::cerr << "Failed to send_arp" << std::endl;
        return -EBADF; /// todo: correct err type
    }

    while(this->_read_arp(res)) {
    }

    return 0;
}

std::vector<std::string> ARPer::get_ifaces()
{
    static const std::unordered_set<std::string> forbidden_ifaces {
        std::string("lo")
    };
    std::vector<std::string> res;
    struct ifaddrs *addrs, *iter;

    getifaddrs(&addrs);
    iter = addrs;

    while (iter)
    {
        if (iter->ifa_addr && iter->ifa_addr->sa_family == PF_INET) {
            const std::string iface(iter->ifa_name);
            if (forbidden_ifaces.find(iface) == forbidden_ifaces.end())
                res.push_back(iface);
        }
        iter = iter->ifa_next;
    }

    freeifaddrs(addrs);
    return res;
}

int ARPer::set_ifname(const std::string &new_ifname)
{
    if (new_ifname.size() > (IFNAMSIZ - 1)) {
        std::cerr << "Too long interface name, MAX="
                  << IFNAMSIZ - 1 << std::endl;
        return -EINVAL;
    }

    this->_ifname = new_ifname;

    if (this->_get_if_info()) {
        std::cerr << "get_if_info failed, interface"
                  << this->_ifname.c_str()
                  << " not found or no IP set?"
                  << std::endl;
        return -EBADF;
    }

    if (this->_set_arp_fd()) {
        std::cerr << "Failed to bind_arp()" << std::endl;
        return -EBADF; /// todo: correct err type
    }

    return 0;
}

/*
 * Reads a single ARP reply from fd.
 * Return 0 on success.
 */
int ARPer::_read_arp(ARP_res_t &res)
{
    uint8_t buf[arper_consts::BUF_SIZE];
    ssize_t length = recvfrom(this->_get_arp_fd(),
                              buf, arper_consts::BUF_SIZE,
                              0, nullptr, nullptr);
    if (length == -1) {
        std::cerr << "recvfrom failed" << std::endl;
        return -EBADF;
    }
    struct ethhdr *rcv_resp = reinterpret_cast<struct ethhdr*>(buf);
    uint8_t *mem_offset = buf + arper_consts::ETH2_HEADER_LEN;
    struct arp_header *arp_resp = reinterpret_cast<struct arp_header*>(mem_offset);

    if (ntohs(rcv_resp->h_proto) != arper_consts::PROTO_ARP) {
        std::cerr << "got not ARP packet" << std::endl;
        return -EPROTOTYPE;
    }
    if (ntohs(arp_resp->opcode) != arper_consts::ARP_REPLY) {
        std::cerr << "got not ARP reply" << std::endl;
        return -EPROTO;
    }
    std::cerr << "got arp reply with len of " << length << std::endl;
    struct in_addr sender_a;
    memset(&sender_a, 0, sizeof(struct in_addr));
    memcpy(&sender_a.s_addr, arp_resp->sender_ip, sizeof(uint32_t));

    std::cerr << "Sender IP: " << inet_ntoa(sender_a) << std::endl;
    for (size_t i = 0; i < arper_consts::MAC_LENGTH; ++i) {
        const int mac_byte = static_cast<int>(arp_resp->sender_mac[i]);
        std::stringstream mac_stream;
        mac_stream << std::setfill('0') << std::setw(2) <<
                      std::uppercase << std::hex << mac_byte;
        res.mac += mac_stream.str();
//        if (i != arper_consts::MAC_LENGTH - 1)
//            res.mac += ":";
    }

    printf("Sender MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
          arp_resp->sender_mac[0],
          arp_resp->sender_mac[1],
          arp_resp->sender_mac[2],
          arp_resp->sender_mac[3],
          arp_resp->sender_mac[4],
          arp_resp->sender_mac[5]);

    return 0;
}

/*
 * Sends an ARP who-has request to dst_ip
 * on interface ifindex, using source mac src_mac and source ip src_ip.
 */
int ARPer::_send_arp(uint32_t dst_ip) const
{
    uint8_t buf[arper_consts::BUF_SIZE] = {0};
    struct sockaddr_ll socket_address = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_ARP),
        .sll_ifindex = this->_get_ifindex(),
        .sll_hatype = htons(ARPHRD_ETHER),
        .sll_pkttype = static_cast<uint8_t>(PACKET_BROADCAST),
        .sll_halen = arper_consts::MAC_LENGTH,
        .sll_addr = {},
    };
    uint8_t *mem_offset = socket_address.sll_addr + arper_consts::MAC_LENGTH;
    *reinterpret_cast<uint16_t*> (mem_offset) = 0U;
    struct ethhdr *send_req = reinterpret_cast<struct ethhdr*>(buf);
    struct arp_header *arp_req = reinterpret_cast<struct arp_header*>
            (buf + arper_consts::ETH2_HEADER_LEN);

    //Broadcast
    memset(send_req->h_dest, 0xff, arper_consts::MAC_LENGTH);
    //Target MAC zero
    memset(arp_req->target_mac, 0x00, arper_consts::MAC_LENGTH);
    //Set source mac to our MAC address
    memcpy(send_req->h_source, this->_ifmac, arper_consts::MAC_LENGTH);
    memcpy(arp_req->sender_mac, this->_ifmac, arper_consts::MAC_LENGTH);
    memcpy(socket_address.sll_addr, this->_ifmac, arper_consts::MAC_LENGTH);

    /* Setting protocol of the packet */
    send_req->h_proto = htons(ETH_P_ARP);

    /* Creating ARP request */
    arp_req->hardware_type = htons(arper_consts::HW_TYPE);
    arp_req->protocol_type = htons(ETH_P_IP);
    arp_req->hardware_len = arper_consts::MAC_LENGTH;
    arp_req->protocol_len = arper_consts::IPV4_LENGTH;
    arp_req->opcode = htons(arper_consts::ARP_REQUEST);

    uint32_t src_ip = this->_ifip; /// > todo: add getter for _ifip
    memcpy(arp_req->sender_ip, &src_ip, sizeof(uint32_t));
    memcpy(arp_req->target_ip, &dst_ip, sizeof(uint32_t));

    struct sockaddr *recv_addr = reinterpret_cast<struct sockaddr*> (&socket_address);
    size_t addr_size = sizeof(socket_address);
    std::cerr << "sending arp request" << std::endl;
    ssize_t ret = sendto(this->_get_arp_fd(), buf, 42, 0, recv_addr, addr_size);
    if (ret == -1) {
        std::cerr << "send_arp failed" << std::endl;
        return -EBADF;
    }

    return 0;
}

/*
 * Creates a raw socket that listens for ARP traffic on specific ifindex.
 * Writes out the socket's FD.
 * Return 0 on success.
 */
int ARPer::_set_arp_fd()
{
    struct sockaddr_ll sll{};
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = this->_get_ifindex();

    // Submit request for a raw socket descriptor.
    this->_arp_fd= socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (this->_arp_fd < 1) {
        std::cerr << "c _set_arp_fd failed to init arp socket " << std::endl;
        return -EBADF;
    }
    std::cerr << "successfully socket # "
              << this->_get_arp_fd()
              << " created" << std::endl;

    struct sockaddr* sock_name = reinterpret_cast<struct sockaddr*>(&sll);
    if (bind(this->_get_arp_fd(), sock_name, sizeof(struct sockaddr_ll)) < 0) {
        std::cerr << "_set_arp_fd failed to bind arp socket " << std::endl;
        ARPer::_close_if_need(this->_arp_fd);
        return -EBADF;
    }

    std::cerr << "successfully binded to interface #"
              << this->_get_ifindex()
              << std::endl;

    return 0;
}

/*
 * Gets interface information by name:
 * IPv4
 * MAC
 * ifindex
 */
int ARPer::_get_if_info()
{
    struct ifreq ifr;
    int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sd <= 0) {
        perror("socket()");
        ARPer::_close_if_need(sd);
        return -1;
    }

    strcpy(ifr.ifr_name, this->_ifname.c_str());
    //Get interface index using name
    if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
        perror("SIOCGIFINDEX");
        ARPer::_close_if_need(sd);
        return -1;
    }

    this->_ifindex = ifr.ifr_ifindex;
    std::cerr << "interface index is " <<  this->_get_ifindex() << std::endl;

    //Get MAC address of the interface
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("SIOCGIFHWADDR");
        ARPer::_close_if_need(sd);
        return -1;
    }

    //Copy mac address to output
    memcpy(this->_ifmac, ifr.ifr_hwaddr.sa_data, arper_consts::MAC_LENGTH);

    if (this->_set_if_ip4(sd)) {
        ARPer::_close_if_need(sd);
        return -1;
    }

    std::cerr << "get_if_info: ok, cleaning temporary socket" << std::endl;
    ARPer::_close_if_need(sd);
    return 0;
}

ARPer::~ARPer()
{
    ARPer::_close_if_need(this->_arp_fd);
}

/*
 * Writes interface IPv4 address as network byte order to ip.
 * Returns 0 on success.
 */
int ARPer::_set_if_ip4(int fd)
{
    struct ifreq ifr{};

    strcpy(ifr.ifr_name, this->_ifname.c_str());
    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        perror("SIOCGIFADDR");
        return -ENXIO;
    }

    struct sockaddr &addr = ifr.ifr_addr;
    if (addr.sa_family != AF_INET) {
        std::cerr << "not AF_INET" << std::endl;
        return -EPROTOTYPE;
    }

    struct sockaddr_in *i = reinterpret_cast<struct sockaddr_in*>(&addr);
    this->_ifip = i->sin_addr.s_addr;

    return 0;
}

int32_t ARPer::_get_ifindex() const
{
    return this->_ifindex;
}

int32_t ARPer::_get_arp_fd() const
{
    return this->_arp_fd;
}

std::string ARPer::get_ifname() const
{
    return _ifname;
}

void ARPer::_close_if_need(int sd)
{
    if (sd >= 0)
        close(sd);
}
