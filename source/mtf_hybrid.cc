//
// Created by corgi on 2025 四月 02.
//

#include <ntv/mtf_hybrid.hh>
#include <opencv2/opencv.hpp>
#include <cmath>

MTFHybrid::MTFHybrid(const packet_list_t& packets) {
  auto global_seq = extractAllTransitions(packets);
  cv::Mat global_mtf = computeMTF(global_seq);  // 16×16

  auto tiles = extractLocalMTFs(packets, 15);   // up to 15 packet tiles
  cv::Mat tile_mtf = tileMTFs(tiles, 4, 16);     // 64×64

  // 填入左上角 16×16
  global_mtf.copyTo(tile_mtf(cv::Rect(0, 0, 16, 16)));

  tile_mtf.convertTo(matrix_, CV_8UC1, 255.0);
}

cv::Mat MTFHybrid::getMatrix() const {
  return matrix_;
}

std::vector<int> MTFHybrid::extractAllTransitions(const packet_list_t& packets) {
  std::vector<int> transitions;
  for (const auto& pkt : packets) {
    if (!pkt) continue;
    const u_char* data = pkt->Data();
    size_t len = pkt->ByteCount();
    std::vector<bool> bits;

    for (size_t i = 0; i < len; ++i) {
      uchar byte = data[i];
      for (int j = 7; j >= 0; --j)
        bits.push_back((byte >> j) & 1);
    }

    for (size_t i = 0; i < bits.size(); i += 4) {
      int val = 0;
      for (size_t j = i; j < std::min(i + 4, bits.size()); ++j) {
        val = (val << 1) | bits[j];
      }
      transitions.push_back(val);
    }
  }
  return transitions;
}

cv::Mat MTFHybrid::computeMTF(const std::vector<int>& transitions) {
  cv::Mat mat = cv::Mat::zeros(16, 16, CV_32FC1);
  if (transitions.size() < 2) return mat;

  for (size_t k = 0; k < transitions.size() - 1; ++k) {
    int i = transitions[k] & 0xF;
    int j = transitions[k + 1] & 0xF;
    mat.at<float>(i, j) += 1.0f;
  }

  for (int row = 0; row < 16; ++row) {
    float sum = cv::sum(mat.row(row))[0];
    if (sum > 0) mat.row(row) /= sum;
  }
  return mat;
}

std::vector<cv::Mat> MTFHybrid::extractLocalMTFs(const packet_list_t& packets, int count) {
  std::vector<cv::Mat> mats;
  int actual = std::min((int)packets.size(), count);
  for(auto packet : packets){
    auto t = extractAllTransitions({packet});
    mats.push_back(computeMTF(t));
  }
  for (int i = 0; i < actual; ++i) {

  }
  return mats;
}

cv::Mat MTFHybrid::tileMTFs(const std::vector<cv::Mat>& images, int cols, int dim) {
  cv::Mat tiled(cols * dim, cols * dim, CV_32FC1, cv::Scalar(0));
  for (int idx = 0; idx < images.size(); ++idx) {
    int row = idx / cols;
    int col = idx % cols;
    images[idx].copyTo(tiled(cv::Rect(col * dim, row * dim, dim, dim)));
  }
  return tiled;
}
