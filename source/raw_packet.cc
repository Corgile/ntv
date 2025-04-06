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
  u_char const* packet_data = byte_arr.data();
  auto const* eth_hdr = reinterpret_cast<ether_header const*>(packet_data);
  u_char const* ip_header_start = packet_data + sizeof(ether_header);

  if (ntohs(eth_hdr->ether_type) == ETHERTYPE_VLAN) {
    ip_header_start += sizeof(vlan_header);
  }

  if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IPV6) return std::nullopt;

  auto const* ip_hdr = reinterpret_cast<ip const*>(ip_header_start);
  if (ip_hdr->ip_p != IPPROTO_TCP && ip_hdr->ip_p != IPPROTO_UDP)
    return std::nullopt;

  uint32_t ip1 = ntohl(ip_hdr->ip_src.s_addr);
  uint32_t ip2 = ntohl(ip_hdr->ip_dst.s_addr);
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


std::optional<AlignedPacket> RawPacket::ToAligned() const {
  u_char const* packet_data = byte_arr.data();
  auto const* eth_hdr = reinterpret_cast<ether_header const*>(packet_data);
  u_char const* ip_header_start = packet_data + sizeof(ether_header);

  if (ntohs(eth_hdr->ether_type) == ETHERTYPE_VLAN) {
    ip_header_start += sizeof(vlan_header);
  }

  if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IPV6) return std::nullopt;

  auto const* ip_hdr = reinterpret_cast<ip const*>(ip_header_start);
  if (ip_hdr->ip_p != IPPROTO_TCP && ip_hdr->ip_p != IPPROTO_UDP)
    return std::nullopt;

  std::array<u_char, 192> aligned{};
  size_t offset = 0;

  // === IP HEADER ===
  size_t ip_len = ip_hdr->ip_hl * 4;
  size_t copy_len = (std::min)(ip_len, size_t(60));
  std::memcpy(aligned.data() + offset, ip_header_start, copy_len);
  offset += 60;  // 固定偏移，无论实际 IP 长度是多少都填满

  uint32_t ip1 = ntohl(ip_hdr->ip_src.s_addr);
  uint32_t ip2 = ntohl(ip_hdr->ip_dst.s_addr);
  uint16_t port1 = 0, port2 = 0;

  // === TCP / UDP HEADER ===
  if (ip_hdr->ip_p == IPPROTO_TCP) {
    auto const* tcp_hdr = reinterpret_cast<tcphdr const*>(ip_header_start + ip_len);
    auto pkt_end = packet_data + byte_arr.size();
    auto tcp_ptr = reinterpret_cast<u_char const*>(tcp_hdr);
    size_t avail = pkt_end > tcp_ptr ? pkt_end - tcp_ptr : 0;
    size_t tcp_copy = (std::min)(size_t(60), avail);
    std::memcpy(aligned.data() + offset, tcp_ptr, tcp_copy);
    offset += 60;

    port1 = ntohs(tcp_hdr->th_sport);
    port2 = ntohs(tcp_hdr->th_dport);

    // 补充 UDP 头部全 0
    std::memset(aligned.data() + offset, 0, 8);
    offset += 8;
  } else {
    // UDP 情况下填空 TCP 头
    offset += 60;

    auto const* udp_hdr = reinterpret_cast<udphdr const*>(ip_header_start + ip_len);
    std::memcpy(aligned.data() + offset, udp_hdr, 8);
    port1 = ntohs(udp_hdr->uh_sport);
    port2 = ntohs(udp_hdr->uh_dport);
    offset += 8;
  }

  // === PAYLOAD 64 ===
  size_t header_size = ip_header_start - packet_data + ip_len;
  if (header_size < byte_arr.size()) {
    size_t payload_len = (std::min)(size_t(64), byte_arr.size() - header_size);
    std::memcpy(aligned.data() + offset, packet_data + header_size, payload_len);
  }
  // offset += 128; // 不需要加，结构已预定义满 256

  // === 规范化 KEY ===
  if (ip1 > ip2 || (ip1 == ip2 && port1 > port2)) {
    std::swap(ip1, ip2);
    std::swap(port1, port2);
  }

  return AlignedPacket{
    .bytes = aligned,
    .key = FlowKey{ ip1, ip2, port1, port2, ip_hdr->ip_p }
  };
}
