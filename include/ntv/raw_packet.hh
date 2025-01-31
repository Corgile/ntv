//
// Created by brian on 11/28/23.
//

#ifndef HOUND_RAW_PACKET_INFO_HPP
#define HOUND_RAW_PACKET_INFO_HPP

#include <list>
#include <memory>
#include <string>
#include <string_view>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <pcap/pcap.h>

#include <moodycamel/concurrent_queue.hh>

struct RawPacket;
using raw_packet_t   = std::shared_ptr<RawPacket>;
using packet_queue_t = moodycamel::ConcurrentQueue<raw_packet_t>;
using packet_list_t  = std::list<raw_packet_t>;
using ustring_t      = std::basic_string<u_char>;
using ustring_view   = std::basic_string_view<u_char>;

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

  /**
   * 根据 byte_arr 解析出五元组作为key
   * @return \p std::string
   */
  std::string GetKey();

  [[nodiscard]] auto ArriveTime() const
    -> int64_t {
    std::chrono::seconds const sec{ info_hdr.ts.tv_sec };
    std::chrono::microseconds const usec{ info_hdr.ts.tv_usec };
    auto duration = sec + usec;
    // 返回时间戳
    return duration.count();
  }
};

struct Peer {
  std::string ip{};
  uint16_t port{};
  friend bool operator<(Peer const& lhs, Peer const& rhs);
  friend bool operator>(Peer const& lhs, Peer const& rhs);
  friend std::ostream& operator<<(std::ostream& os, Peer const& obj);
};

#endif // HOUND_RAW_PACKET_INFO_HPP
