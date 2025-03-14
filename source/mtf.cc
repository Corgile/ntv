//
// Created by corgi on 2025 Mar 14.
//

#include "ntv/mtf.hh"

MTF::MTF(const packet_list_t& packets, int cols) {
  std::vector<cv::Mat> matrices;
  for (const auto& packet : packets) {
    auto transitions = processPacket(packet);
    matrices.push_back(computeTransitionMatrix(transitions));
  }

  // 生成 cols×cols 的网格，不足补零，超出截断
  cv::Mat tiled_float = tileImages(matrices, cols, 16);

  // 转换为8位灰度图（0-255）
  tiled_float.convertTo(matrix_, CV_8UC1, 255.0);
}
cv::Mat MTF::getMatrix() const { return matrix_; }

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
  cv::Mat mat = cv::Mat::zeros(16, 16, CV_32FC1);
  if (transitions.size() < 2) return mat;

  // 统计状态转移次数
  for (size_t k = 0; k < transitions.size() - 1; ++k) {
    int i = transitions[k] & 0xF; // 确保值在0-15
    int j = transitions[k + 1] & 0xF;
    mat.at<float>(i, j) += 1.0f;
  }

  // 归一化为概率
  for (int row = 0; row < 16; ++row) {
    float sum = cv::sum(mat.row(row))[0];
    if (sum > 0) mat.row(row) /= sum;
  }

  return mat;
}
cv::Mat MTF::tileImages(const std::vector<cv::Mat>& images, const int cols,
                        const int dim) {
  int total = cols * cols; // 总处理图像数（可能补零或截断）
  std::vector<cv::Mat> rows;

  for (int i = 0; i < cols; ++i) { // 每行
    std::vector<cv::Mat> row_images;
    for (int j = 0; j < cols; ++j) { // 每列
      int index = i * cols + j;
      cv::Mat img;
      if (index < images.size() && index < total) {
        img = images[index];
      } else {
        img = cv::Mat::zeros(dim, dim, CV_32FC1);
      }
      row_images.push_back(img);
    }

    // 水平拼接一行
    cv::Mat row_mat;
    cv::hconcat(row_images, row_mat);
    rows.push_back(row_mat);
  }

  // 垂直拼接所有行
  cv::Mat tiled;
  cv::vconcat(rows, tiled);
  return tiled; // 尺寸为 (cols×dim) x (cols×dim)
}
