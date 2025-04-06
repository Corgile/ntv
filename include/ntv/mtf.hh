//
// Created by corgi on 2025 Mar 14.
//

#ifndef MTF_HH
#define MTF_HH
#include <cstdint>
#include <memory>
#include <vector>

#include <ntv/raw_packet.hh>
#include <ntv/usings.hh>

#include <opencv2/opencv.hpp>

class MTF {
public:
  explicit MTF(const packet_list_t& packets, int cols = 4);

  [[nodiscard]] cv::Mat Matrix() const;

private:
  cv::Mat matrix_;
  // 将数据包转换为0-15的整数序列
  static std::vector<int> processPacket(const raw_packet_t& packet);
  // 生成转移概率矩阵
  static cv::Mat computeTransitionMatrix(const std::vector<int>& transitions);
  // 平铺矩阵生成图像
  static cv::Mat tileImages(const std::vector<cv::Mat>& images, int cols,
                            int dim);
};

class Tile {
public:
  /**
   *
   * @param packets
   * @param width
   */
  explicit Tile(packet_list_t packets, int width = 64);

  /**
   * Matrix函数
   * 将 m_packets 中的所有数据包 raw bytes 依次拼接，
   * 每个字节的值（0~255）直接作为灰度像素值。
   * 拼接成的长条数据调整为 m_width x m_width 的矩阵：
   * - 如果数据不足，末尾补 0；
   * - 如果数据过多，则截断多余部分。
   * 返回的 cv::Mat 可被 cv::imwrite 保存为 PNG 图片。
   */
  [[nodiscard]] cv::Mat Matrix() const;

private:
  packet_list_t m_packets;
  int m_width;
};

#endif // MTF_HH
