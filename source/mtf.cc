//
// Created by corgi on 2025 Mar 14.
//

#include <utility>

#include "ntv/mtf.hh"

MTF::MTF(const packet_list_t& packets, int cols) {
  std::vector<cv::Mat> matrices;
  for (const auto& packet : packets) {
    auto transitions = processPacket(packet);
    matrices.push_back(computeTransitionMatrix(transitions));
  }
  const cv::Mat tiled_float{ tileImages(matrices, cols, 16) };
  tiled_float.convertTo(matrix_, CV_8UC1, 255.0);
}
cv::Mat MTF::Matrix() const { return matrix_; }

std::vector<int> MTF::processPacket(const raw_packet_t& packet) {
  const u_char* data = packet->Data();
  size_t length      = packet->ByteCount();
  std::vector<bool> bits;

  // 将每个字节拆解为8个二进制位
  for (size_t i = 0; i < length; ++i) {
    uchar byte = data[i];
    for (int j = 7; j >= 0; --j) { bits.push_back((byte >> j) & 1); }
  }

  // 每4位一组转换为0-15的整数
  std::vector<int> transitions;
  for (size_t i = 0; i < bits.size(); i += 4) {
    int val = 0;
    for (size_t j = i; j < std::min(i + 4, bits.size()); ++j) {
      val = (val << 1) | bits[j];
    }
    transitions.push_back(val);
  }

  return transitions;
}

cv::Mat MTF::computeTransitionMatrix(const std::vector<int>& transitions) {
  cv::Mat mat{ cv::Mat::zeros(16, 16, CV_8UC1) };
  if (transitions.size() < 2) return mat;
  for (size_t k = 0; k < transitions.size() - 1; ++k) {
    int i = transitions[k] & 0xF;
    int j = transitions[k + 1] & 0xF;
    mat.at<float>(i, j) += 1.0f;
  }
  for (int row = 0; row < 16; ++row) {
    double sum{ cv::sum(mat.row(row))[0] };
    if (sum > 0) mat.row(row) /= sum;
  }

  return mat;
}

cv::Mat MTF::tileImages(const std::vector<cv::Mat>& images, const int cols,
                        const int dim) {
  cv::Mat tiled(cols * dim, cols * dim, CV_8UC1, cv::Scalar{ 0 });
  for (int idx = 0; idx < std::min((int)images.size(), cols * cols); ++idx) {
    const int row{ idx / cols };
    const int col{ idx % cols };
    images[idx].copyTo(tiled(cv::Rect{ col * dim, row * dim, dim, dim }));
  }
  return tiled;
}

cv::Mat Tile::Matrix() const {
  cv::Mat img(m_width, m_width, CV_8UC1);
  size_t filled = 0;

  for (auto& pkt : m_packets) {
    if (!pkt) continue;
    auto const byte_alighed{ pkt->ToAligned() };

    size_t len{ std::min(byte_alighed->Size(), img.total() - filled) };
    if (len == 0) break;
    std::memcpy(img.data + filled, byte_alighed->Data(), len);
    filled += len;
  }
  if (filled < img.total()) {
    std::memset(img.data + filled, 0, img.total() - filled);
  }
  return img;
}

Tile::Tile(packet_list_t packets, int width)
    : m_packets{ std::move(packets) }
    , m_width(width) {}
