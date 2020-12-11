#pragma once
#include <iostream>
#include <string>
#include <vector>

struct ARP_res_t {
    ARP_res_t(): ip(""), mac(""){
        this->ip.reserve(32);
        this->mac.reserve(32);
    }
    std::string ip;
    std::string mac;
    ~ARP_res_t(){};
};

namespace arper_consts {
    static constexpr uint16_t PROTO_ARP = 0x0806; // arper_consts::ARP_REQUEST
    static constexpr uint16_t ARP_REQUEST = 0x01;
    static constexpr uint16_t ARP_REPLY = 0x02;
    static constexpr uint16_t HW_TYPE = 1U;
    static constexpr size_t ETH2_HEADER_LEN =14U;
    static constexpr size_t MAC_LENGTH = 6U;
    static constexpr size_t IPV4_LENGTH = 4U;
    static constexpr size_t BUF_SIZE = 64U;

}

class ARPer
{
public:
    ARPer();
    ~ARPer();
    std::vector<std::string> get_ifaces();
    int probe(ARP_res_t &res);
    std::string get_ifname() const;
    int set_ifname(const std::string &new_ifname);

private:
    int _read_arp(ARP_res_t &res);
    int _send_arp(uint32_t dst_ip) const;
    int _set_if_ip4(int fd);
    int _get_if_info();

    int32_t _get_ifindex() const;
    int32_t _get_arp_fd() const;
    int _set_arp_fd();
    static void _close_if_need(int sd);

    int32_t _ifindex;
    uint8_t _ifmac[arper_consts::MAC_LENGTH];
    uint32_t _ifip;
    int32_t _arp_fd;
    std::string _ifname;
};
