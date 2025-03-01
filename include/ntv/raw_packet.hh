//
// Created by brian on 11/28/23.
//

#ifndef RAW_PACKET_INFO_HPP
#define RAW_PACKET_INFO_HPP

#include <memory>
#include <string>

#ifdef WIN32
#include <winsock.h>
#else
#include <netinet/in.h>
#include <netinet/ip.h>
#endif

#include <pcap/pcap.h>

#include <moodycamel/concurrent_queue.hh>
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
  /**
   * 根据 byte_arr 解析出五元组作为key
   * @return \p std::string
   */
  [[nodiscard]] auto GetKey() const -> std::string;
  [[nodiscard]] auto Data() const -> u_char const*;
  [[nodiscard]] auto Beg() const -> ustring_t::const_iterator;
  [[nodiscard]] auto End() const -> ustring_t::const_iterator;
};

struct Peer {
  std::string ip{};
  std::uint16_t port{};
  friend bool operator<(Peer const& lhs, Peer const& rhs);
  friend bool operator>(Peer const& lhs, Peer const& rhs);
  friend std::ostream& operator<<(std::ostream& os, Peer const& obj);
};

#endif // RAW_PACKET_INFO_HPP
