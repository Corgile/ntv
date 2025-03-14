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
auto RawPacket::GetKey() const -> std::string {
  // 指针指向数据包的开始
  u_char const* packet_data{ byte_arr.data() };
  // 判断以太网帧类型（检查VLAN）
  auto const eth_hdr{ reinterpret_cast<ether_header const*>(packet_data) };
  u_char const* ip_header_start{ packet_data + sizeof(struct ether_header) };
  // VLAN 标签处理：以太网帧长度超过14字节说明有VLAN标签
  if (ntohs(eth_hdr->ether_type) == ETHERTYPE_VLAN) { // VLAN Tag is present
    ip_header_start += sizeof(vlan_header);           // 跳过4字节VLAN标签
    XLOG_TRACE << "VLAN";
  }
  if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IPV6) { return {}; }
  // 解析IP头
  auto const ip_hdr{ reinterpret_cast<struct ip const*>(ip_header_start) };
  if (ip_hdr->ip_p not_eq IPPROTO_TCP and ip_hdr->ip_p not_eq IPPROTO_UDP) {
    return {}; // 非TCP/UDP协议，无法生成五元组
  }
  Peer peer1, peer2;
  // 解析TCP/UDP头
  peer1.ip = inet_ntoa(ip_hdr->ip_src);
  peer2.ip = inet_ntoa(ip_hdr->ip_dst);

  if (ip_hdr->ip_p == IPPROTO_TCP) {
    auto const tcp_hdr{ reinterpret_cast<struct tcphdr const*>(
      ip_header_start + (ip_hdr->ip_hl << 2)) };
    peer1.port = ntohs(tcp_hdr->th_sport);
    peer2.port = ntohs(tcp_hdr->th_dport);
  } else if (ip_hdr->ip_p == IPPROTO_UDP) {
    auto const udp_hdr{ reinterpret_cast<struct udphdr const*>(
      ip_header_start + (ip_hdr->ip_hl << 2)) };
    peer1.port = ntohs(udp_hdr->uh_sport);
    peer2.port = ntohs(udp_hdr->uh_dport);
  } else {
    if (ip_hdr->ip_p == IPPROTO_ICMP or ip_hdr->ip_p == IPPROTO_ICMPV6) {
      XLOG_DEBUG << "ICMP, Skipped";
    }
    throw std::logic_error{ "期望是TCP/UDP协议，但经过解析却不是" };
  }
  // 规范化 IP 和端口顺序，确保无论 A->B 还是 B->A 都是相同的会话
  if (peer1 > peer2) { std::swap(peer1, peer2); }
  // 生成五元组key
  std::stringstream key;
  key << peer1 << "-" << peer2 << "-" << int(ip_hdr->ip_p);
  return key.str();
}
auto RawPacket::Data() const -> u_char const* { return byte_arr.data(); }
auto RawPacket::Beg() const -> ustring_t::const_iterator {
  return byte_arr.begin();
}
auto RawPacket::End() const -> ustring_t::const_iterator {
  return byte_arr.end();
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
