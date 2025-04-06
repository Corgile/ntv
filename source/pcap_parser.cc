#include <ntv/gaf.hh>
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
      std::jthread{ [this, i](const std::stop_token& st) { RunShard(i, st); } };
  }

  for (int i = 0; i < WRITER_THREAD_COUNT; ++i) {
    mWriterThreads.emplace_back(
      [this](const std::stop_token& st) { RunWriter(st); });
  }
}

// === 析构函数 ===
PcapParser::~PcapParser() {
  XLOG_INFO << "析构函数开始, 等待写队列处理: " << mWriteQueue.size_approx();

  for (int i = 0; i < mWriterThreads.size(); ++i) {
    XLOG_DEBUG << "Join前 mWriterThreads[" << i
               << "] joinable: " << mWriterThreads[i].joinable();
  }

  while (mWriteQueue.size_approx()) { std::this_thread::sleep_for(1000ms); }

  XLOG_INFO << "析构函数结束, 写队列已清空";
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
  auto raw{ std::make_shared<RawPacket>(pkthdr, packet) };
  auto const self{ reinterpret_cast<PcapParser*>(user_data) };
  auto const opt_key{ raw->GetFlowKey() };
  if (not opt_key.has_value()) return;

  size_t const shard_id{ std::hash<FlowKey>{}(opt_key.value()) % SHARD_COUNT };
  self->mShards[shard_id].packetQueue.enqueue(std::move(raw));
}

// === Shard工作线程 ===
void PcapParser::RunShard(const int shardId, const std::stop_token& stop) {
  auto& shard{ mShards[shardId] };
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

    uint64_t const now{ GetTimestampUs() };
    for (auto it = shard.flowMap.begin(); it != shard.flowMap.end();) {
      auto& [key, list]{ *it };
      if (now - shard.lastSeen[key] <= 10'000'000) {
        ++it;
        continue;
      }
      mWriteQueue.enqueue({ key, std::move(list) });
      shard.lastSeen.erase(key);
      it = shard.flowMap.erase(it);
    }
    std::this_thread::sleep_for(10ms);
  }

  for (auto& [key, list] : shard.flowMap) {
    mWriteQueue.enqueue({ key, std::move(list) });
  }
  XLOG_INFO << "Shard[" << shardId
            << "] 退出, Flush count: " << shard.flowMap.size();
}

void PcapParser::RunWriter(const std::stop_token& stop) {
  XLOG_INFO << "写线程[" << std::this_thread::get_id() << "]启动";
  flow_node_t node;
  while (not stop.stop_requested()) {
    if (mWriteQueue.try_dequeue(node)) {
      WriteSession(node);
      continue;
    }
    if (stop.stop_requested()) { break; }
    std::this_thread::sleep_for(10ms); // 🔕 idle 等待，防止空转烧CPU
  }

  XLOG_INFO << "写线程[" << std::this_thread::get_id() << "]退出";
}

// === 写出PNG逻辑 ===
void PcapParser::WriteSession(const flow_node_t& node) {
  fs::path const save_path = fs::path{ global::opt.outdir } /
    (std::to_string(node.first.ip1) + "-" + std::to_string(node.first.ip2) +
     "-" + std::to_string(node.first.port1) + "-" +
     std::to_string(node.first.port2) + "-" +
     std::to_string(node.first.protocol) + ".png");

  cv::Mat mat;
  if (global::opt.outfmt == "tile") {
    const Tile gray{ node.second };
    mat = gray.Matrix();
  } else if (global::opt.outfmt == "mtf") {
    const MTF mtf{ node.second };
    mat = mtf.Matrix();
  } else if (global::opt.outfmt == "gaf") {
    const GAF gaf{ node.second };
    mat = gaf.getMatrix();
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
