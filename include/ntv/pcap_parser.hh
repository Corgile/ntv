//
// Created by brian on 2025 Jan 31.
//

#ifndef PCAP_PARSER_HH
#define PCAP_PARSER_HH

#include <atomic>
#include <condition_variable>
#include <filesystem>
#include <map>
#include <thread>
#include <vector>

#include <pcap/pcap.h>

#include <ntv/raw_packet.hh>

namespace fs = std::filesystem;

class PcapParser {
public:
  PcapParser();
  ~PcapParser();
  void ParseFile(fs::path const& pcap_file);

private:
  static void DeadHandler(u_char*, pcap_pkthdr const*, u_char const*);
  /**
   * 将数据包重新组装成会话
   */
  void Reassemble();

  pcap_t* mHandle{ nullptr };
  std::atomic_bool mStop{ false };

  packet_queue_t mPacketQueue;
  std::vector<std::thread> mProcessThreads;
  std::mutex mMutex;
  std::condition_variable mCV;
  std::map<std::string, packet_list_t> mFlowMap;
  using flow_node_t = std::map<std::string, packet_list_t>::node_type;
  moodycamel::ConcurrentQueue<flow_node_t> mSession;
  std::map<std::string, int64_t> mLastSeen;
};

#endif // PCAP_PARSER_HH
