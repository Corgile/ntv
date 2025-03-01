//
// Created by brian on 2025 Jan 31.
//

#include <ntv/globals.hh>
#include <ntv/pcap_parser.hh>
#include <pcap/pcap.h>
#include <xlog/api.hh>

#ifdef _MSC_VER
#define LambdaRetType
#else
#define LambdaRetType ->void
#endif

PcapParser::PcapParser() {
  mAssembleThreads.emplace_back([&] LambdaRetType { Reassemble(); });
  mAssembleThreads.emplace_back([&] LambdaRetType { Reassemble(); });
  mAssembleThreads.emplace_back([&] LambdaRetType { Reassemble(); });
  mAssembleThreads.emplace_back([&] LambdaRetType { Reassemble(); });
  mScanner = std::thread{ [&] LambdaRetType { Scan(); } };
  mDumper  = std::thread{ [&] LambdaRetType { DumpFlow(); } };
}

void PcapParser::ParseFile(fs::path const& pcap_file) {
  mInputFile = pcap_file.stem();
  mParentDir = pcap_file.parent_path();
#ifdef WIN32
  using open_offline = pcap_t* (*)(char const*, char*);
  open_offline const open_func{ pcap_open_offline };
#else
  using open_offline = pcap_t* (*)(char const*, u_int, char*);
  open_offline const open_func{ pcap_open_offline_with_tstamp_precision };
#endif

  std::array<char, PCAP_ERRBUF_SIZE> err_buff{};
  // PCAP_TSTAMP_PRECISION_MICRO, PCAP_TSTAMP_PRECISION_NANO
  mHandle = open_func(pcap_file.string().c_str(), err_buff.data());
  if (mHandle == nullptr) {
    XLOG_ERROR << err_buff;
    exit(EXIT_FAILURE);
  }
  pcap_set_promisc(mHandle, 1);
  pcap_set_buffer_size(mHandle, 25 << 22); // 100MB

  constexpr bpf_u_int32 net{ 0 };
  bpf_program fp{};
  using namespace global;
  if (pcap_compile(mHandle, &fp, opt.filter.c_str(), 0, net) == -1) {
    XLOG_ERROR << "编译 filter 失败: " << std::string{ pcap_geterr(mHandle) };
    exit(EXIT_FAILURE);
  }
  if (pcap_setfilter(mHandle, &fp) == -1) {
    XLOG_ERROR << "设置 filter 失败: " << std::string{ pcap_geterr(mHandle) };
    exit(EXIT_FAILURE);
  }
  pcap_freecode(&fp);
  pcap_loop(mHandle, 0, DeadHandler, reinterpret_cast<u_char*>(this));
  XLOG_INFO << "pcap_loop 解析完成";
  pcap_close(mHandle);
}

void PcapParser::DeadHandler(u_char* user_data, pcap_pkthdr const* pkthdr,
                             u_char const* packet) {
  auto const this_{ reinterpret_cast<PcapParser*>(user_data) };
  this_->mPacketQueue.enqueue(std::make_shared<RawPacket>(pkthdr, packet));
}

/**
 * 将数据包重新组装成会话
 */
void PcapParser::Reassemble() {
  while (not mStopAssemble) {
    raw_packet_t newer{};
    while (mPacketQueue.try_dequeue(newer)) {
      auto const key{ newer->GetKey() };
      if (key.empty()) { continue; }
      std::scoped_lock guard{ mMutex };
      if (not mFlowMap.contains(key)) { mFlowMap.insert({ key, {} }); }
      mLastSeen[key] = newer->ArriveTime();
      mFlowMap.at(key).emplace_back(newer);
    }
    std::this_thread::sleep_for(10ms);
  }
}

void PcapParser::Scan() {
  while (not mStopScan) {
    std::unique_lock guard{ mMutex };
    mScanCV.wait_for(guard, 10s,
                     [&] { return not mFlowMap.empty() or mStopScan; });
    for (auto const& [key, list] : mFlowMap) {
      // TODO 用std::chrono来计算 timeout
      bool const changed{ list.back()->ArriveTime() not_eq mLastSeen.at(key) };
      if (changed and not mStopScan) { continue; } // 会话未完成
      mSession.enqueue(mFlowMap.extract(key));
      mLastSeen.extract(key);
      mFlowMap.erase(key);
    }
  }
  std::scoped_lock guard{ mMutex };
  for (auto it{ mFlowMap.begin() }; it not_eq mFlowMap.end();) {
    mSession.enqueue(mFlowMap.extract(it));
    it = mFlowMap.erase(it);
  }
  mLastSeen.clear();
}

void PcapParser::DumpFlow() {
  while (not mStopDump) {
    flow_node_t node{};
    while (mSession.try_dequeue(node)) { WriteSession(node); }
    std::this_thread::sleep_for(10ms);
  }
}

void PcapParser::WriteSession(flow_node_t const& flow) const {
  // DLT_EN10MB表示以太网帧类型
  pcap_t* handle{ pcap_open_dead(DLT_EN10MB, 65535) };
  if (handle == nullptr) {
    XLOG_ERROR << "Error opening PCAP handle: " << pcap_geterr(handle);
    return;
  }
  fs::path const dir{ mParentDir / mInputFile };
  if (not fs::exists(dir)) { fs::create_directory(dir); }
  fs::path file{ dir / flow.key() };
  file.append(".pcap");
  pcap_dumper_t* dumper{ pcap_dump_open(handle, file.string().c_str()) };
  if (dumper == nullptr) {
    XLOG_ERROR << "Error opening PCAP dumper: " << pcap_geterr(handle);
    pcap_close(handle);
    return;
  }
  for (auto const& packet : flow.mapped()) {
    pcap_pkthdr header{ packet->info_hdr };
    pcap_dump(reinterpret_cast<u_char*>(dumper), &header, packet->Data());
  }
  // 关闭PCAP文件
  pcap_dump_close(dumper);
  pcap_close(handle);
}

PcapParser::~PcapParser() {
  XLOG_INFO << "进入析构函数";
  XLOG_INFO << "等待 mPacketQueue 队列处理";
  while (mPacketQueue.size_approx()) {
    std::this_thread::sleep_for(10ms); // 等待队列处理
  }
  mStopAssemble = true;
  for (auto& t : mAssembleThreads) {
    if (t.joinable()) { t.join(); }
  }
  mScanCV.notify_all(); // scanner,该醒了

  XLOG_INFO << "等待 mFlowMap 处理";
  while (not mFlowMap.empty()) {
    std::this_thread::sleep_for(10ms); // 等待Scan线程处理
  }
  mStopScan = true;
  if (mScanner.joinable()) { mScanner.join(); }

  XLOG_INFO << "等待 mSession 队列处理";
  while (mSession.size_approx()) {
    std::this_thread::sleep_for(10ms); // 等待队列处理
  }
  mStopDump = true;
  if (mDumper.joinable()) { mDumper.join(); }

  XLOG_INFO << "Last Seen: " << mLastSeen.size();
  XLOG_INFO << "Packet Queue: " << mPacketQueue.size_approx();
  XLOG_INFO << "Flow Map: " << mFlowMap.size();
  XLOG_INFO << "mSession: " << mSession.size_approx();
}
