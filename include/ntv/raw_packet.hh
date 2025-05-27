//
// Created by brian on 11/28/23.
//

#ifndef RAW_PACKET_INFO_HPP
#define RAW_PACKET_INFO_HPP

#include <memory>
#include <string>

#ifdef WIN32
#include <ntv/missing.hh>
#else
#include <netinet/in.h>
#include <netinet/ip.h>
#endif

#include <pcap/pcap.h>

#include <moodycamel/concurrent_queue.hh>
#include <ntv/flow_key.hh>
#include <ntv/usings.hh>

struct RawPacket {
  RawPacket() = default;
  pcap_pkthdr info_hdr{};
  ustring_t byte_arr{};
  /**
   * raw packet 构造函数
   * @param pkthdr meta data
   * @param packet packet data
   * @note 会将meta信息和packet所有的字节复制一份。
   */
  RawPacket(pcap_pkthdr const* pkthdr, u_char const* packet);

  RawPacket(RawPacket const& other)                = delete;
  RawPacket(RawPacket&& other) noexcept            = delete;
  RawPacket& operator=(RawPacket const& other)     = delete;
  RawPacket& operator=(RawPacket&& other) noexcept = delete;

  [[nodiscard]] auto ArriveTime() const -> std::int64_t;
  [[nodiscard]] auto ByteCount() const -> std::int64_t;
  /// 字节数据的开始地址
  /// @return const_iterator
  [[nodiscard]] auto Data() const -> u_char const*;
  /// 字节数据的开始地址
  /// @return const_iterator
  [[nodiscard]] auto Beg() const -> ustring_t::const_iterator;
  /// 字节数据的末尾
  /// @return const_iterator
  [[nodiscard]] auto End() const -> ustring_t::const_iterator;
  [[nodiscard]] std::optional<FlowKey> GetFlowKey() const;
  [[nodiscard]] std::vector<int> ByteSeq() const;
};
void to_json(nlohmann::json& j, const RawPacket& pkt);
void to_json(nlohmann::json& j, const std::shared_ptr<RawPacket>& pkt_ptr);
std::string ipv4_to_string(uint32_t ip_addr_net_order);
struct Peer {
  std::string ip{};
  std::uint16_t port{};
  friend bool operator<(Peer const& lhs, Peer const& rhs);
  friend bool operator>(Peer const& lhs, Peer const& rhs);
  friend std::ostream& operator<<(std::ostream& os, Peer const& obj);
};

#endif // RAW_PACKET_INFO_HPP
