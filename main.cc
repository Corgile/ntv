#include <ntv/globals.hh>
#include <ntv/pcap_parser.hh>
#include <ntv/helpers.hh>
#include <xlog/api.hh>

#include <wintoastlib.h>

namespace fs = std::filesystem;

int main(int const argc, char* argv[]) {
  xlog::setLogLevelTo(xlog::Level::INFO);
  xlog::toggleAsyncLogging(TOGGLE_OFF);
  xlog::toggleConsoleLogging(TOGGLE_ON);
  if (argc < 3) {
    XLOG_WARN << "Usage: " << fs::path{ argv[0] }.stem().string()
              << "<output-format:tile|mtf|pcap> <outdir> <pcapfile>";
    exit(EXIT_FAILURE);
  }
  global::opt.outfmt = argv[1];
  global::opt.outdir = argv[2];
  fs::path const pcap_file{ argv[3] };
  XLOG_INFO << "开始: " << pcap_file.filename().string();
  XLOG_INFO << "输出: " << global::opt.outfmt;
  {
    PcapParser parser{};
    parser.ParseFile(pcap_file);
  }
  XLOG_INFO << "完成";
  ShowNotification(
    L"NTV", L"转换完成", L"转换又完成",
    L"D:/User/WorkSpace/projects/ntv/resource/img_2025-02-27_15-10-20.png",
    L"");
  return 0;
}
