#include <ntv/globals.hh>
#include <ntv/pcap_parser.hh>
#include <xlog/api.hh>
namespace fs = std::filesystem;

int main(int const argc, char* argv[]) {
  xlog::toggleAsyncLogging(TOGGLE_OFF);
  xlog::toggleConsoleLogging(TOGGLE_ON);
  xlog::setLogLevelTo(xlog::Level::INFO);
  // C:\Users\corgi\workspace\project\PcapPlusPlus-master\Tests\ExamplesTest\pcap_examples\http-packets.pcap
  if (argc < 1) {
    XLOG_WARN << "Usage: " << fs::path{ argv[0] }.stem().string()
              << "/path/to/config.ini";
    exit(EXIT_FAILURE);
  }
  // global::opt.outfmt = argv[1];
  // global::opt.outdir = argv[2];
  // fs::path const pcap_file{ argv[3] };
  fs::path const pcap_file{
    R"(C:\Users\corgi\workspace\project\PcapPlusPlus-master\Examples\Tutorials\Tutorial-PcapFiles\input.pcap)"
  };
  XLOG_INFO << "开始: " << pcap_file.filename().string();
  XLOG_INFO << "输出: " << global::opt.outfmt;
  PcapParser parser{};
  parser.ParseFile(pcap_file);
  return 0;
}
