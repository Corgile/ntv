#pragma once

#include <string>
#include <list>
#include <map>
#include <queue>
#include <filesystem>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <moodycamel/concurrent_queue.hh>
#include <ntv/raw_packet.hh>

class PcapParser {
public:
  PcapParser();
  ~PcapParser();

  void ParseFile(std::filesystem::path const& pcap_file);
  static void DeadHandler(u_char* user_data, const pcap_pkthdr* pkthdr, const u_char* packet);

private:
  using raw_packet_t = std::shared_ptr<RawPacket>;
  using packet_list_t = std::list<raw_packet_t>;
  using flow_node_t = std::map<std::string, packet_list_t>::node_type;

  void Reassemble(std::stop_token const& stop);
  void Scan(std::stop_token const& stop);
  void DumpFlow(std::stop_token const& stop);
  void AsyncWriter(std::stop_token const& stop);

  void WriteSessionAsync(flow_node_t&& node);
  void WriteSession(flow_node_t& node);

  // 数据结构
  moodycamel::ConcurrentQueue<raw_packet_t> mPacketQueue;
  moodycamel::ConcurrentQueue<flow_node_t> mSession;
  std::map<std::string, packet_list_t> mFlowMap;
  std::map<std::string, uint64_t> mLastSeen;

  // 异步写队列
  std::queue<flow_node_t> mWriteQueue;
  std::mutex mWriteMutex;
  std::condition_variable_any mWriteCV;

  // 多线程
  std::vector<std::jthread> mAssembleThreads;
  std::jthread mScanner;
  std::jthread mDumper;
  std::jthread mWriter;

  std::mutex mMutex;
  std::condition_variable_any mScanCV;

  std::filesystem::path mInputFile, mParentDir, mOutputDir;
  pcap_t* mHandle = nullptr;
};
