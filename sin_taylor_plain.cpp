#include <iostream>
#include <vector>
#include <cmath>
#include <iomanip>

int main() {
    // ====== 파라미터 ======
    const int64_t s = 100;         // 스케일링 상수
    const int64_t denom = 120;     // 정수화 분모
    const double x_input = 0.5236; // 30도(라디안)

    // ====== 입력값 ======
    int64_t x_scaled = static_cast<int64_t>(std::round(s * x_input));

    // ====== 테일러 계수 (정수화) ======
    const double c1 = 1.0;
    const double c3 = -1.0/6.0;
    const double c5 = 1.0/120.0;
    int64_t ic1 = static_cast<int64_t>(std::round(c1 * denom * std::pow(s,4)));
    int64_t ic3 = static_cast<int64_t>(std::round(c3 * denom * std::pow(s,2)));
    int64_t ic5 = static_cast<int64_t>(std::round(c5 * denom));

    // ====== 항별 연산 ======
    int64_t x3 = x_scaled * x_scaled * x_scaled;
    int64_t x5 = x3 * x_scaled * x_scaled;
    int64_t term1 = ic1 * x_scaled;
    int64_t term2 = ic3 * x3;
    int64_t term3 = ic5 * x5;
    int64_t y_scaled = term1 + term2 + term3;

    // ====== 역스케일링 ======
    double y_recovered = static_cast<double>(y_scaled) / (denom * std::pow(s,5));

    // ====== 실제값 및 오차 ======
    double y_true = std::sin(x_input);
    double error = std::abs(y_true - y_recovered);

    // ====== 결과 출력 ======
    std::cout << "[x, 근사값, 실제값, 오차]" << std::endl;
    std::cout << "x=" << x_input
              << ", 근사=" << y_recovered
              << ", 실제=" << y_true
              << ", 오차=" << error << std::endl;
    return 0;
} 