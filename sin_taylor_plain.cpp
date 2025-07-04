#include <iostream>
#include <vector>
#include <cmath>
#include <iomanip>

int main() {
    // ====== 파라미터 ======
    const int64_t s = 50;         // 스케일링 상수
    const int64_t denom = 6;     // 정수화 분모

    std::cout << std::fixed << std::setprecision(6);
    std::cout << "각도(도)\tx_input(rad)\t근사값\t실제값\t오차" << std::endl;

    for (int deg = -90; deg <= 90; deg += 10) {
        double x_input = deg * M_PI / 180.0;
        int64_t x_scaled = static_cast<int64_t>(std::round(s * x_input));

        // ====== 테일러 계수 (정수화) ======
        const double c1 = 1.0;
        const double c3 = -1.0/6.0;
        int64_t ic1 = static_cast<int64_t>(std::round(c1 * denom * std::pow(s,2)));
        int64_t ic3 = static_cast<int64_t>(std::round(c3 * denom * std::pow(s,0)));

        // ====== 항별 연산 ======
        int64_t x3 = x_scaled * x_scaled * x_scaled;
        int64_t term1 = ic1 * x_scaled;
        int64_t term2 = ic3 * x3;
        int64_t y_scaled = term1 + term2;

        // ====== 역스케일링 ======
        double y_recovered = static_cast<double>(y_scaled) / (denom * std::pow(s,3));

        // ====== 실제값 및 오차 ======
        double y_true = std::sin(x_input);
        double error = std::abs(y_true - y_recovered);

        // ====== 결과 출력 ======
        std::cout << deg << "\t" << x_input << "\t" << y_recovered << "\t" << y_true << "\t" << error << std::endl;
    }
    return 0;
} 