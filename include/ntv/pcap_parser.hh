#pragma once

#include <array>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <list>
#include <memory>
#include <mutex>
#include <unordered_map>

#include <moodycamel/concurrent_queue.hh>
#include <ntv/flow_key.hh>
#include <ntv/raw_packet.hh>
#include <ntv/usings.hh>

class PcapParser {
public:
  PcapParser();
  ~PcapParser();
  void ParseFile(std::filesystem::path const& pcap_file);

  static void DeadHandler(u_char* user_data, const pcap_pkthdr* pkthdr,
                          const u_char* packet);

private:
  struct FlowShard {
    moodycamel::ConcurrentQueue<raw_packet_t> packetQueue;
    std::unordered_map<FlowKey, packet_list_t> flowMap;
    std::unordered_map<FlowKey, uint64_t> lastSeen;
    std::jthread thread;
  };

  static constexpr int SHARD_COUNT = 16;
  std::array<FlowShard, SHARD_COUNT> mShards;

  moodycamel::ConcurrentQueue<flow_node_t> mWriteQueue;
  std::vector<std::jthread> mWriterThreads;
  static constexpr int WRITER_THREAD_COUNT = 4;

  std::filesystem::path mInputFile, mParentDir, mOutputDir;
  pcap_t* mHandle = nullptr;

private:
  static uint64_t GetTimestampUs();
  void RunShard(int shardId, const std::stop_token& stop);
  void RunWriter(const std::stop_token& stop);
  void static WriteSession(const flow_node_t& node);
};
