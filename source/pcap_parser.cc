#include <ntv/globals.hh>
#include <ntv/mtf.hh>
#include <ntv/pcap_parser.hh>
#include <opencv2/opencv.hpp>
#include <pcap/pcap.h>
#include <xlog/api.hh>

using namespace std::chrono_literals;
namespace fs = std::filesystem;

// === 构造函数 ===
PcapParser::PcapParser() {
  for (int i = 0; i < SHARD_COUNT; ++i) {
    mShards[i].thread =
      std::jthread([this, i](std::stop_token st) { RunShard(i, st); });
  }

  // mWriterThread = std::jthread([this](std::stop_token st) { RunWriter(st); });
  for (int i = 0; i < WRITER_THREAD_COUNT; ++i) {
    mWriterThreads.emplace_back([this](std::stop_token st) { RunWriter(st); });
  }
}

// === 析构函数 ===
PcapParser::~PcapParser() {
  XLOG_INFO << "析构函数开始";

  // 等待写队列清空
  while (true) {
    std::scoped_lock lock(mWriteMutex);
    if (mWriteQueue.empty()) break;
    std::this_thread::sleep_for(10ms);
  }

  mWriteCV.notify_all();
  XLOG_INFO << "析构函数结束";
}

// === 解析主流程 ===
void PcapParser::ParseFile(fs::path const& pcap_file) {
  mInputFile = pcap_file;
  mParentDir = pcap_file.parent_path();
  mOutputDir = mInputFile.stem();
  mInputFile = mInputFile.stem();

  std::array<char, PCAP_ERRBUF_SIZE> err_buff{};
  mHandle = pcap_open_offline(pcap_file.string().c_str(), err_buff.data());
  if (mHandle == nullptr) {
    XLOG_ERROR << err_buff;
    exit(EXIT_FAILURE);
  }

  constexpr bpf_u_int32 net = 0;
  bpf_program fp{};
  if (pcap_compile(mHandle, &fp, global::opt.filter.c_str(), 0, net) == -1) {
    XLOG_ERROR << "编译filter失败: " << pcap_geterr(mHandle);
    exit(EXIT_FAILURE);
  }

  if (pcap_setfilter(mHandle, &fp) == -1) {
    XLOG_ERROR << "设置filter失败: " << pcap_geterr(mHandle);
    exit(EXIT_FAILURE);
  }

  pcap_freecode(&fp);
  pcap_loop(mHandle, 0, DeadHandler, reinterpret_cast<u_char*>(this));
  pcap_close(mHandle);
  XLOG_INFO << "pcap_loop 解析完成";
}

// === 将packet分发给shard ===
void PcapParser::DeadHandler(u_char* user_data, const pcap_pkthdr* pkthdr,
                             const u_char* packet) {
  auto* self   = reinterpret_cast<PcapParser*>(user_data);
  auto raw     = std::make_shared<RawPacket>(pkthdr, packet);
  auto opt_key = raw->GetFlowKey();
  if (!opt_key.has_value()) return;

  size_t shard_id = std::hash<FlowKey>{}(opt_key.value()) % SHARD_COUNT;
  self->mShards[shard_id].packetQueue.enqueue(std::move(raw));
}

// === Shard工作线程 ===
void PcapParser::RunShard(int shardId, std::stop_token stop) {
  auto& shard = mShards[shardId];
  XLOG_INFO << "Shard[" << shardId << "] 启动";

  while (!stop.stop_requested()) {
    raw_packet_t pkt;
    while (shard.packetQueue.try_dequeue(pkt)) {
      auto key_opt = pkt->GetFlowKey();
      if (!key_opt.has_value()) continue;
      auto key = key_opt.value();
      shard.flowMap[key].emplace_back(pkt);
      shard.lastSeen[key] = pkt->ArriveTime();
    }

    uint64_t now = GetTimestampUs();
    for (auto it = shard.flowMap.begin(); it != shard.flowMap.end();) {
      auto& key = it->first;
      if (now - shard.lastSeen[key] > 10'000'000) {
        EnqueueToWrite({ std::move(key), std::move(it->second) });
        shard.lastSeen.erase(key);
        it = shard.flowMap.erase(it);
      } else {
        ++it;
      }
    }

    std::this_thread::sleep_for(1ms);
  }

  // flush所有剩余流
  for (auto& [key, list] : shard.flowMap) {
    EnqueueToWrite({ std::move(key), std::move(list) });
  }
  XLOG_INFO << "Shard[" << shardId << "] 退出";
}

// === 写线程 ===
void PcapParser::RunWriter(std::stop_token stop) {
  XLOG_INFO << "写线程启动";

  while (!stop.stop_requested()) {
    flow_node_t node;
    {
      std::unique_lock lock(mWriteMutex);
      mWriteCV.wait(
        lock, [&] { return !mWriteQueue.empty() || stop.stop_requested(); });

      if (mWriteQueue.empty()) continue;

      node = std::move(mWriteQueue.front());
      mWriteQueue.pop();
    }

    WriteSession(node);
  }

  XLOG_INFO << "写线程退出";
}

void PcapParser::EnqueueToWrite(flow_node_t&& node) {
  {
    std::scoped_lock lock(mWriteMutex);
    mWriteQueue.push(std::move(node));
  }
  mWriteCV.notify_one();
}

// === 写出PNG逻辑 ===
void PcapParser::WriteSession(flow_node_t& node) {
  fs::path save_path = fs::path{ global::opt.outdir } /
    (std::to_string(node.first.ip1) + "-" + std::to_string(node.first.ip2) +
     "-" + std::to_string(node.first.port1) + "-" +
     std::to_string(node.first.port2) + "-" +
     std::to_string(node.first.protocol) + ".png");

  cv::Mat mat;
  if (global::opt.outfmt == "tile") {
    GrayScale gray(node.second);
    mat = gray.Matrix();
  } else if (global::opt.outfmt == "mtf") {
    MTF mtf(node.second);
    mat = mtf.getMatrix();
  }

  if (!cv::imwrite(save_path.string(), mat)) {
    XLOG_ERROR << "保存失败: " << save_path;
  }
}

// === 当前时间（微秒）===
uint64_t PcapParser::GetTimestampUs() {
  return std::chrono::duration_cast<std::chrono::microseconds>(
           std::chrono::steady_clock::now().time_since_epoch())
    .count();
}
