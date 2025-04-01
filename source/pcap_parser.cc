#include <ntv/globals.hh>
#include <ntv/mtf.hh>
#include <ntv/pcap_parser.hh>
#include <opencv2/opencv.hpp>
#include <pcap/pcap.h>
#include <xlog/api.hh>

using namespace std::chrono_literals;
namespace fs = std::filesystem;

PcapParser::PcapParser() {
  for (int i = 0; i < 4; ++i) {
    mAssembleThreads.emplace_back(
      [this](std::stop_token st) { Reassemble(st); });
  }
  mScanner = std::jthread([this](std::stop_token const& st) { Scan(st); });
  mDumper  = std::jthread([this](std::stop_token const& st) { DumpFlow(st); });
  mWriter =
    std::jthread([this](std::stop_token const& st) { AsyncWriter(st); });
}

PcapParser::~PcapParser() {
  XLOG_INFO << "进入析构函数";

  // 等 packet queue 清空
  while (mPacketQueue.size_approx() > 0) { std::this_thread::sleep_for(10ms); }
  XLOG_INFO << "mPacketQueue Empty";

  // join 自动完成（jthread 析构时自动停止+join）

  // 等待 mSession 清空
  while (mSession.size_approx() > 0) { std::this_thread::sleep_for(10ms); }

  // 等写队列清空
  while (true) {
    std::scoped_lock lock{ mWriteMutex };
    if (mWriteQueue.empty()) break;
    std::this_thread::sleep_for(10ms);
  }

  mWriteCV.notify_all();

  XLOG_INFO << "Last Seen: " << mLastSeen.size();
  XLOG_INFO << "Packet Queue: " << mPacketQueue.size_approx();
  XLOG_INFO << "Flow Map: " << mFlowMap.size();
  XLOG_INFO << "mSession: " << mSession.size_approx();
  XLOG_INFO << __FUNCSIG__ << " Done";
}

void PcapParser::ParseFile(fs::path const& pcap_file) {
  mInputFile = pcap_file;
  mParentDir = pcap_file.parent_path();
  mOutputDir = mInputFile.stem();
  mInputFile = mInputFile.stem(); // TODO 优化
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

void PcapParser::Reassemble(std::stop_token const& stop) {
  XLOG_INFO << "Reassemble thread started";
  while (!stop.stop_requested()) {
    raw_packet_t newer{};
    while (mPacketQueue.try_dequeue(newer)) {
      auto key = newer->GetKey();
      if (key.empty()) continue;
      std::scoped_lock lock{ mMutex };
      mLastSeen[key] = newer->ArriveTime();
      mFlowMap[key].emplace_back(std::move(newer));
      mScanCV.notify_all();
    }
    std::this_thread::sleep_for(10ms);
  }
  XLOG_INFO << "Reassemble exiting";
}

void PcapParser::Scan(std::stop_token const& stop) {
  XLOG_INFO << "Scan thread started";
  while (!stop.stop_requested()) {
    std::unique_lock lock{ mMutex };
    mScanCV.wait_for(
      lock, 10s, [&] { return !mFlowMap.empty() || stop.stop_requested(); });

    for (auto it = mFlowMap.begin(); it != mFlowMap.end();) {
      if (it->second.empty()) {
        ++it;
        continue;
      }

      bool changed = it->second.back()->ArriveTime() != mLastSeen[it->first];
      if (changed) {
        ++it;
        continue;
      }

      mLastSeen.erase(it->first);
      mSession.enqueue(mFlowMap.extract(it++));
    }
  }

  std::scoped_lock lock{ mMutex };
  for (auto it = mFlowMap.begin(); it != mFlowMap.end();) {
    mSession.enqueue(mFlowMap.extract(it++));
  }
  mLastSeen.clear();
  XLOG_INFO << "Scan exiting";
}

void PcapParser::DumpFlow(std::stop_token const& stop) {
  XLOG_INFO << "DumpFlow thread started";
  while (!stop.stop_requested()) {
    flow_node_t node{};
    while (mSession.try_dequeue(node)) {
      WriteSessionAsync(std::move(node));
      // WriteSession(std::move(node));
    }
    std::this_thread::sleep_for(10ms);
  }
  XLOG_INFO << "DumpFlow exiting";
}

void PcapParser::AsyncWriter(std::stop_token const& stop) {
  XLOG_INFO << "AsyncWriter thread started";

  while (true) {
    flow_node_t node;

    {
      std::unique_lock lock{ mWriteMutex };
      mWriteCV.wait(
        lock, [&] { return !mWriteQueue.empty() || stop.stop_requested(); });

      if (mWriteQueue.empty()) {
        if (stop.stop_requested()) break;
        continue;
      }

      node = std::move(mWriteQueue.front());
      mWriteQueue.pop();
    }

    WriteSession(node);
  }

  XLOG_INFO << "AsyncWriter exiting";
}

void PcapParser::WriteSessionAsync(flow_node_t&& node) {
  {
    std::scoped_lock lock{ mWriteMutex };
    mWriteQueue.push(std::move(node));
  }
  mWriteCV.notify_one(); // ✅ 只唤醒一个就行
}

void PcapParser::WriteSession(flow_node_t& flow) {
  fs::path save_path = fs::path{ global::opt.outdir } / flow.key();
  save_path.replace_extension(".png");

  try {
    cv::Mat mat;
    if (global::opt.outfmt == "tile") {
      GrayScale gray(flow.mapped());
      mat = gray.Matrix();
    } else if (global::opt.outfmt == "mtf") {
      MTF mtf(flow.mapped());
      mat = mtf.getMatrix();
    } else {
      XLOG_ERROR << "未知输出格式: " << global::opt.outfmt;
      return;
    }

    if (!cv::imwrite(save_path.string(), mat)) {
      XLOG_ERROR << "保存失败: " << save_path;
    }
  } catch (std::exception const& e) {
    XLOG_ERROR << "WriteSession 异常: " << e.what();
  }
}

void PcapParser::DeadHandler(u_char* user_data, const pcap_pkthdr* pkthdr,
                             const u_char* packet) {
  auto* parser = reinterpret_cast<PcapParser*>(user_data);
  parser->mPacketQueue.enqueue(std::make_shared<RawPacket>(pkthdr, packet));
}
