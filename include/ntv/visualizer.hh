//
// Created by brian on 2025 Feb 01.
//

#ifndef VISUALIZER_HH
#define VISUALIZER_HH

#include <fftw3.h>
#include <ntv/raw_packet.hh>
#include <opencv2/opencv.hpp>

enum struct Method {
  TimeDomain,
  FrequencyDomain,
  RecurrencePlots,
  GramianAngularField,
  MarkovTransitionField,
};

class Visualizer {
public:
  Visualizer()  = default;
  ~Visualizer() = default;

  void Plot(flow_node_t const& flow, Method const method) {}

private:
  // 时域方法：直接绘制数据包字节流
  static cv::Mat TimeDomain(const packet_list_t& session, int width,
                            int height) {
    cv::Mat img   = cv::Mat::zeros(height, width, CV_8UC3);
    int packetPos = 0;

    for (const auto& packet : session) {
      for (int i = 0; i < packet->ByteCount() && packetPos < width * height;
           ++i) {
        int row         = packetPos / width;
        int col         = packetPos % width;
        uchar intensity = packet->byte_arr[i]; // 使用字节作为强度值
        img.at<cv::Vec3b>(row, col) =
          cv::Vec3b(intensity, intensity, intensity);
        packetPos++;
      }
      if (packetPos >= width * height) break;
    }

    return img;
  }

  // 频域方法：对字节流进行快速傅里叶变换（FFT）
  static cv::Mat FrequencyDomain(const packet_list_t& session, int width,
                                 int height) {
    cv::Mat img   = cv::Mat::zeros(height, width, CV_8UC3);
    int packetPos = 0;

    for (const auto& packet : session) {
      std::vector<double> realData(packet->Beg(),
                                   packet->End()); // 将字节流数据转换为实数序列
      int N = realData.size();

      // 使用FFTW进行傅里叶变换
      fftw_complex* in  = (fftw_complex*)fftw_malloc(sizeof(fftw_complex) * N);
      fftw_complex* out = (fftw_complex*)fftw_malloc(sizeof(fftw_complex) * N);
      fftw_plan p = fftw_plan_dft_1d(N, in, out, FFTW_FORWARD, FFTW_ESTIMATE);

      // 填充输入数据
      for (int i = 0; i < N; ++i) {
        in[i][0] = realData[i]; // 实部
        in[i][1] = 0.0;         // 虚部
      }

      fftw_execute(p); // 执行傅里叶变换

      // 提取频域幅度并归一化
      double maxFreq = 0.0;
      std::vector<double> magnitudes(N);
      for (int i = 0; i < N; ++i) {
        magnitudes[i] =
          sqrt(out[i][0] * out[i][0] + out[i][1] * out[i][1]); // 计算幅度
        maxFreq = std::max(maxFreq, magnitudes[i]);
      }

      // 将频域幅度映射到图像像素
      for (int i = 0; i < N && packetPos < width * height; ++i) {
        int row = packetPos / width;
        int col = packetPos % width;
        uchar intensity =
          static_cast<uchar>(magnitudes[i] / maxFreq * 255); // 归一化
        img.at<cv::Vec3b>(row, col) =
          cv::Vec3b(intensity, intensity, intensity);
        packetPos++;
      }

      fftw_destroy_plan(p);
      fftw_free(in);
      fftw_free(out);

      if (packetPos >= width * height) break;
    }

    return img;
  }

  // 递归图法 (VisualRP)
  static cv::Mat RP(const packet_list_t& session, int width, int height) {
    cv::Mat img   = cv::Mat::zeros(height, width, CV_8UC3);
    int packetPos = 0;

    // 将字节流展平为一维数组
    std::vector<uchar> data;
    for (const auto& packet : session) {
      data.insert(data.end(), packet->Beg(), packet->End());
    }

    int N = data.size();
    // 计算每对时刻的欧氏距离（相似度）
    for (int i = 0; i < N && packetPos < width * height; ++i) {
      for (int j = 0; j < N && packetPos < width * height; ++j) {
        double distance = std::abs(data[i] - data[j]); // 计算欧氏距离
        uchar intensity =
          static_cast<uchar>(std::min(distance, 255.0)); // 归一化
        int row = packetPos / width;
        int col = packetPos % width;
        img.at<cv::Vec3b>(row, col) =
          cv::Vec3b(intensity, intensity, intensity);
        packetPos++;
      }
      if (packetPos >= width * height) break;
    }

    return img;
  }

  // 格拉姆角场 (VisualGAF)
  static cv::Mat GAF(const packet_list_t& session, int width, int height) {
    cv::Mat img   = cv::Mat::zeros(height, width, CV_8UC3);
    int packetPos = 0;

    // 将字节流展平为一维数组
    std::vector<uchar> data;
    for (const auto& packet : session) {
      data.insert(data.end(), packet->Beg(), packet->End());
    }

    int N          = data.size();
    double min_val = *std::min_element(data.begin(), data.end());
    double max_val = *std::max_element(data.begin(), data.end());

    // 将字节流标准化到[0, 1]区间
    for (auto& byte : data) {
      byte = static_cast<uchar>((byte - min_val) / (max_val - min_val) * 255);
    }

    // 转化为极坐标并计算GAF
    for (int i = 0; i < N && packetPos < width * height; ++i) {
      double angle  = M_PI * (data[i] / 255.0); // 将字节值映射到[0, π]区间
      double cosine = cos(angle);
      double sine   = sin(angle);

      // 构造GAF矩阵
      for (int j = 0; j < N && packetPos < width * height; ++j) {
        double angle2    = M_PI * (data[j] / 255.0);
        double cosine2   = cos(angle2);
        double sine2     = sin(angle2);
        double gaf_value = cosine * cosine2 + sine * sine2;

        uchar intensity = static_cast<uchar>((gaf_value + 1) * 127.5); // 归一化
        int row         = packetPos / width;
        int col         = packetPos % width;
        img.at<cv::Vec3b>(row, col) =
          cv::Vec3b(intensity, intensity, intensity);
        packetPos++;
      }
    }

    return img;
  }

  // 马尔可夫转移场 (VisualMFT)
  static cv::Mat MTF(const packet_list_t& session, int width, int height) {
    cv::Mat img = cv::Mat::zeros(height, width, CV_8UC3);

    // 将字节流展平为一维数组
    std::vector<uchar> data;
    for (const auto& packet : session) {
      data.insert(data.end(), packet->Beg(), packet->End());
    }

    int N = data.size();
    std::map<int, int> state_counts;

    // 离散化并统计状态转移频率
    for (int i = 0; i < N - 1; ++i) {
      int state1 = data[i];
      int state2 = data[i + 1];
      state_counts[state1 * 256 + state2]++; // 记录从state1到state2的转移频率
    }

    // 转移矩阵归一化
    double max_val = 0;
    for (const auto& pair : state_counts) {
      max_val = std::max(max_val, (double)pair.second);
    }

    // 映射转移矩阵到图像
    for (const auto& pair : state_counts) {
      int row = pair.first / 256; // 计算行
      int col = pair.first % 256; // 计算列

      // 确保行列索引不超出图像尺寸
      if (row < height && col < width) {
        double intensity            = pair.second / max_val * 255.0;
        img.at<cv::Vec3b>(row, col) = cv::Vec3b(static_cast<uchar>(intensity),
                                                static_cast<uchar>(intensity),
                                                static_cast<uchar>(intensity));
      }
    }

    return img;
  }
};

#endif // VISUALIZER_HH
