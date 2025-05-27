//
// Created by brian on 2025 Jan 31.
//
#ifdef WIN32
#include <pcap.h>
#else
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#endif
#include <ntv/flow_key.hh>
#include <sstream>

#include <ntv/missing.hh>
#include <ntv/raw_packet.hh>
#include <ntv/vlan_header.hh>

#include <xlog/api.hh>
#define fake

fake RawPacket::RawPacket(pcap_pkthdr const* pkthdr, u_char const* packet)
    : info_hdr{ *pkthdr } // make a copy of the packet data
{
  byte_arr.reserve(pkthdr->caplen);
  byte_arr.assign(packet, packet + pkthdr->caplen);
}
auto RawPacket::ArriveTime() const -> int64_t {
  std::chrono::seconds const sec{ info_hdr.ts.tv_sec };
  std::chrono::microseconds const usec{ info_hdr.ts.tv_usec };
  auto const duration{ sec + usec };
  // 返回时间戳
  return duration.count();
}
auto RawPacket::ByteCount() const -> std::int64_t {
  return std::int64_t(byte_arr.size());
}

auto RawPacket::Data() const -> u_char const* { return byte_arr.data(); }
auto RawPacket::Beg() const -> ustring_t::const_iterator {
  return byte_arr.begin();
}
auto RawPacket::End() const -> ustring_t::const_iterator {
  return byte_arr.end();
}

std::optional<FlowKey> RawPacket::GetFlowKey() const {
  u_char const* packet_data{ byte_arr.data() };
  auto const* eth_hdr{ reinterpret_cast<ether_header const*>(packet_data) };
  u_char const* ip_header_start{ packet_data + sizeof(ether_header) };

  if (ntohs(eth_hdr->ether_type) == ETHERTYPE_VLAN) {
    ip_header_start += sizeof(vlan_header);
  }

  if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IPV6) return std::nullopt;

  auto const* ip_hdr = reinterpret_cast<ip const*>(ip_header_start);
  if (ip_hdr->ip_p != IPPROTO_TCP && ip_hdr->ip_p != IPPROTO_UDP)
    return std::nullopt;

  uint32_t ip1{ ntohl(ip_hdr->ip_src.s_addr) };
  uint32_t ip2{ ntohl(ip_hdr->ip_dst.s_addr) };
  uint16_t port1, port2;

  if (ip_hdr->ip_p == IPPROTO_TCP) {
    auto const* tcp_hdr =
      reinterpret_cast<tcphdr const*>(ip_header_start + (ip_hdr->ip_hl << 2));
    port1 = ntohs(tcp_hdr->th_sport);
    port2 = ntohs(tcp_hdr->th_dport);
  } else {
    auto const* udp_hdr =
      reinterpret_cast<udphdr const*>(ip_header_start + (ip_hdr->ip_hl << 2));
    port1 = ntohs(udp_hdr->uh_sport);
    port2 = ntohs(udp_hdr->uh_dport);
  }

  // 规范化：小的IP+port在前
  if (ip1 > ip2 || (ip1 == ip2 && port1 > port2)) {
    std::swap(ip1, ip2);
    std::swap(port1, port2);
  }

  return FlowKey{ ip1, ip2, port1, port2, ip_hdr->ip_p };
}

std::vector<int> RawPacket::ByteSeq() const {
  std::vector<int> intdata;
  std::ranges::transform(byte_arr, std::back_inserter(intdata),
                         [](u_char byte) { return static_cast<int>(byte); });
  return intdata;
}

void to_json(nlohmann::json& j, const RawPacket& pkt) {
  j = nlohmann::json{ { "timestamp", pkt.ArriveTime() },
                      { "size", pkt.ByteCount() },
                      { "sequence", pkt.ByteSeq() } };
}

void to_json(nlohmann::json& j, const std::shared_ptr<RawPacket>& pkt_ptr) {
  if (pkt_ptr) {
    j = *pkt_ptr; // 递归调用 RawPacket 的 to_json
  } else {
    j = nullptr;
  }
}
std::string ipv4_to_string(uint32_t ip_addr_net_order) {
  in_addr addr{};
  addr.s_addr = htonl(ip_addr_net_order); // 保证网络字节序
  char str[INET_ADDRSTRLEN];
  if (!inet_ntop(AF_INET, &addr, str, INET_ADDRSTRLEN)) {
    throw std::runtime_error("inet_ntop failed");
  }
  return std::string{ str };
}

// peer
bool operator<(Peer const& lhs, Peer const& rhs) {
  if (lhs.ip < rhs.ip) return true;
  if (rhs.ip < lhs.ip) return false;
  return lhs.port < rhs.port;
}
bool operator>(Peer const& lhs, Peer const& rhs) { return rhs < lhs; }
std::ostream& operator<<(std::ostream& os, Peer const& obj) {
  return os << obj.ip << "_" << obj.port;
}
