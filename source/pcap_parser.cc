//
// Created by brian on 2025 Jan 31.
//

#include <iostream>
#include <ntv/globals.hh>
#include <ntv/pcap_parser.hh>

PcapParser::PcapParser() {
  for (int i = 0; i < 5; ++i) {
    mProcessThreads.emplace_back([&] { Reassemble(); });
  }
  mProcessThreads.emplace_back([&] {
    while (not mStop) {
      std::unique_lock guard{ mMutex };
      mCV.wait_for(guard, 10s, [&] { return not mFlowMap.empty(); });
      for (auto const& [key, list] : mFlowMap) {
        bool const changed{ list.back()->ArriveTime() != mLastSeen.at(key) };
        if (changed and not mStop) { continue; }
        mSession.enqueue(mFlowMap.extract(key));
        mLastSeen.extract(key);
      }
    }
  });
}

void PcapParser::ParseFile(fs::path const& pcap_file) {
  using open_offline = pcap_t* (*)(const char*, u_int, char*);
  open_offline const open_func{ pcap_open_offline_with_tstamp_precision };
  std::array<char, PCAP_ERRBUF_SIZE> err_buff{};
  // PCAP_TSTAMP_PRECISION_MICRO, PCAP_TSTAMP_PRECISION_NANO
  mHandle = open_func(pcap_file.c_str(), 0, err_buff.data());
  pcap_set_promisc(mHandle, 1);
  pcap_set_buffer_size(mHandle, 25 << 21); // 50MB

  constexpr bpf_u_int32 net{ 0 };
  bpf_program fp{};
  using namespace global;
  if (pcap_compile(mHandle, &fp, opt.filter.c_str(), 0, net) == -1) {
    exit(EXIT_FAILURE);
  }
  if (pcap_setfilter(mHandle, &fp) == -1) { exit(EXIT_FAILURE); }
  pcap_freecode(&fp);
  pcap_loop(mHandle, 0, DeadHandler, reinterpret_cast<u_char*>(this));
  pcap_close(mHandle);
}

void PcapParser::DeadHandler(u_char* user_data, pcap_pkthdr const* pkthdr,
                             u_char const* packet) {
  auto const this_{ reinterpret_cast<PcapParser*>(user_data) };
  auto pkt{ std::make_shared<RawPacket>(pkthdr, packet) };
  this_->mPacketQueue.enqueue(std::move(pkt));
}

/**
 * 将数据包重新组装成会话
 */
void PcapParser::Reassemble() {
  while (not mStop) {
    raw_packet_t newer{};
    while (mPacketQueue.try_dequeue(newer)) {
      auto const key{ newer->GetKey() };
      if (key.empty()) { continue; }
      std::scoped_lock guard{ mMutex };
      if (not mFlowMap.contains(key)) {
        mLastSeen[key] = newer->ArriveTime();
        mFlowMap.insert({ key, { std::move(newer) } });
        continue;
      }
      mFlowMap.at(key).emplace_back(std::move(newer));
    }
    std::this_thread::sleep_for(500ms);
  }
}

PcapParser::~PcapParser() {
  mStop = true;
  mCV.notify_one();
  for (auto& t : mProcessThreads) { t.join(); }
  std::cout << "Last Seen: " << mLastSeen.size() << "\n";
  std::cout << "Flow Map: " << mFlowMap.size() << "\n";
  std::cout << "mSession: " << mSession.size_approx() << "\n";
  std::cout << "Packet Queue: " << mPacketQueue.size_approx() << "\n";
}
