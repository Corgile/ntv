#include <ntv/globals.hh>
#include <ntv/pcap_parser.hh>
#include <xlog/api.hh>
namespace fs = std::filesystem;

int main(int const argc, char* argv[]) {
  xlog::setLogLevelTo(xlog::Level::INFO);
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
  xlog::toggleAsyncLogging(TOGGLE_OFF);
  xlog::toggleConsoleLogging(TOGGLE_ON);
  PcapParser parser{};
  parser.ParseFile(pcap_file);
  return 0;
}
