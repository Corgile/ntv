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
#include <ntv/usings.hh>
#include <ntv/visualizer.hh>

namespace fs = std::filesystem;

class PcapParser {
public:
  PcapParser();
  ~PcapParser();
  void ParseFile(fs::path const& pcap_file);

private:
  static void DeadHandler(u_char*, pcap_pkthdr const*, u_char const*);
  void Scan();
  void DumpFlow();
  void Reassemble();
  void WritePcap(flow_node_t const& flow, std::string_view filename);

  pcap_t* mHandle{ nullptr };
  std::atomic_bool mStopAssemble{ false };
  std::atomic_bool mStopScan{ false };
  std::atomic_bool mStopDump{ false };

  fs::path mInputFile;
  fs::path mParentDir;
  Visualizer mVisualizer;

  packet_queue_t mPacketQueue;
  std::thread mScanner;
  std::thread mDumper;
  std::vector<std::thread> mAssembleThreads;
  std::mutex mMutex;
  std::condition_variable mScanCV;
  std::map<std::string, packet_list_t> mFlowMap;
  moodycamel::ConcurrentQueue<flow_node_t> mSession;
  std::map<std::string, int64_t> mLastSeen;
};

#endif // PCAP_PARSER_HH
