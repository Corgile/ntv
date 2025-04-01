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

  cv::Mat getMatrix() const;

private:
  cv::Mat matrix_;
  // 将数据包转换为0-15的整数序列
  static std::vector<int> processPacket(const raw_packet_t& packet);
  // 生成转移概率矩阵
  static cv::Mat computeTransitionMatrix(const std::vector<int>& transitions);
  // 平铺矩阵生成图像
  static cv::Mat tileImages(const std::vector<cv::Mat>& images, int cols,
                            int dim);

  static cv::Mat markovTile() {
    /**
    * def markov_tile(matrices, n_clusters):
    """
    对 packet_list（每个元素为一个16x16的转移矩阵）进行时序建模，
    返回一个 Markov Transition Field (MTF) 矩阵，形状为 (n, n)，
    其中 n 为数据包数。具体步骤：

    1. 将每个转移矩阵展平为一个256维向量；
    2. 利用KMeans将所有数据包映射到 n_clusters 个离散状态中；
    3. 统计相邻数据包之间的状态转移次数，构造全局转移矩阵；
    4. 对全局转移矩阵按行归一化，得到状态转移概率；
    5. 构造MTF矩阵：对于任意 (i, j)，赋值为从状态 state[i] 到 state[j]
    的转移概率。
    """
    num_packets = len(matrices)
    flattened = np.array([p.flatten() for p in matrices])

    # 使用KMeans聚类，将每个数据包映射到一个离散状态
    kmeans = KMeans(n_clusters=n_clusters, random_state=0).fit(flattened)
    state_labels = kmeans.labels_

    # 构造全局状态转移矩阵（大小为 n_clusters x n_clusters）
    global_M = np.zeros((n_clusters, n_clusters))
    for i in range(num_packets - 1):
        cur_state = state_labels[i]
        next_state = state_labels[i + 1]
        global_M[cur_state, next_state] += 1

    # 对全局转移矩阵每一行归一化
    for i in range(n_clusters):
        row_sum = np.sum(global_M[i])
        if row_sum > 0:
            global_M[i] = global_M[i] / row_sum

    # 构造 Markov Transition Field (MTF) 矩阵
    # MTF(i, j) = P(从 state_labels[i] 转移到 state_labels[j])
    mtf = np.zeros((num_packets, num_packets))
    for i in range(num_packets):
        for j in range(num_packets):
            mtf[i, j] = global_M[state_labels[i], state_labels[j]]
    return mtf
     */
  }
};

class GrayScale {
public:
  /**
   *
   * @param packets
   * @param width
   */
  explicit GrayScale(packet_list_t packets, int width = 64);

  /**
   * Matrix函数
   * 将 m_packets 中的所有数据包 raw bytes 依次拼接，
   * 每个字节的值（0~255）直接作为灰度像素值。
   * 拼接成的长条数据调整为 m_width x m_width 的矩阵：
   * - 如果数据不足，末尾补 0；
   * - 如果数据过多，则截断多余部分。
   * 返回的 cv::Mat 可被 cv::imwrite 保存为 PNG 图片。
   */
  cv::Mat Matrix() const;

private:
  packet_list_t m_packets;
  int m_width;
};

#endif // MTF_HH
