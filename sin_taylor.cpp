#include <openfhe/pke/openfhe.h>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <vector>
#include <cmath>
#include <random>

using namespace lbcrypto;

// ====== 파라미터 ======
const double T = 0.01;         // 샘플링 간격
const double t_end = 0.2;      // 총 시간 (테스트용 짧게)
const int N = static_cast<int>(t_end / T) + 1;
const int64_t s = 100;         // 스케일링 상수
const int64_t denom = 120;     // 정수화 분모
const double x_min = -M_PI/2;  // 경계 최소
const double x_max =  M_PI/2;  // 경계 최대
const double k_repulse = 0.5;  // 경계 반발력
const double step_std = 0.05;  // 랜덤 스텝 표준편차

// 테일러 계수 (정수화)
const double c1 = 1.0;
const double c3 = -1.0/6.0;
const double c5 = 1.0/120.0;
const int64_t ic1 = static_cast<int64_t>(std::round(c1 * denom * std::pow(s,4)));
const int64_t ic3 = static_cast<int64_t>(std::round(c3 * denom * std::pow(s,2)));
const int64_t ic5 = static_cast<int64_t>(std::round(c5 * denom));

// 역스케일링 상수
const double inv_scale = 1.0 / (denom * std::pow(s,5));

int main() {
    // ====== 암호화 파라미터 설정 ======
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetPlaintextModulus(1099512004609);  // 충분히 큰 소수 (NTT-friendly)
    parameters.SetMultiplicativeDepth(5);   // x^5까지
    parameters.SetSecurityLevel(SecurityLevel::HEStd_NotSet);
    parameters.SetRingDim(8192);

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    // ====== 입력값 시퀀스 생성 (경계 랜덤 워크) ======
    std::vector<double> x(N);
    x[0] = 0.0;
    std::default_random_engine rng(std::random_device{}());
    std::normal_distribution<double> dist(0.0, step_std);
    for (int k = 1; k < N; ++k) {
        double step = dist(rng);
        if (x[k-1] > x_max) step -= k_repulse * (x[k-1] - x_max);
        else if (x[k-1] < x_min) step += k_repulse * (x_min - x[k-1]);
        x[k] = x[k-1] + step;
    }

    // ====== 정수 스케일링 ======
    std::vector<int64_t> x_scaled(N);
    for (int k = 0; k < N; ++k) x_scaled[k] = static_cast<int64_t>(std::round(s * x[k]));

    // ====== 결과 저장용 ======
    std::vector<double> y_true(N), y_approx(N), error(N);

    // ====== 시간 측정 시작 ======
    auto taylor_start = std::chrono::high_resolution_clock::now();

    // ====== 반복 ======
    for (int k = 0; k < N; ++k) {
        // 1. x_scaled 암호화
        auto p_x = cc->MakePackedPlaintext({x_scaled[k]});
        auto ct_x = cc->Encrypt(keyPair.publicKey, p_x);

        // 2. 암호공간에서 x^3, x^5 계산
        auto ct_x2 = cc->EvalMult(ct_x, ct_x);           // x^2
        auto ct_x3 = cc->EvalMult(ct_x2, ct_x);          // x^3
        auto ct_x5 = cc->EvalMult(ct_x3, ct_x2);         // x^5

        // 3. 각 항 상수곱
        auto term1 = cc->EvalMult(ct_x, cc->MakePackedPlaintext({ic1}));    // ic1 * x
        auto term2 = cc->EvalMult(ct_x3, cc->MakePackedPlaintext({ic3}));   // ic3 * x^3
        auto term3 = cc->EvalMult(ct_x5, cc->MakePackedPlaintext({ic5}));   // ic5 * x^5

        // 4. 합산
        auto ct_y = cc->EvalAdd(term1, term2);
        ct_y = cc->EvalAdd(ct_y, term3);

        // 5. 복호화 및 역스케일링
        Plaintext p_y;
        cc->Decrypt(keyPair.secretKey, ct_y, &p_y);
        int64_t y_scaled = p_y->GetPackedValue()[0];
        y_approx[k] = y_scaled * inv_scale;
        y_true[k] = std::sin(x[k]);
        error[k] = std::abs(y_true[k] - y_approx[k]);
    }

    // ====== 시간 측정 끝 ======
    auto taylor_end = std::chrono::high_resolution_clock::now();
    auto taylor_ms = std::chrono::duration_cast<std::chrono::milliseconds>(taylor_end - taylor_start).count();

    // ====== 결과 출력 ======
    std::cout << "[k, x, 근사값, 실제값, 오차]" << std::endl;
    for (int k = 0; k < N; ++k) {
        std::cout << std::setw(3) << k << ": x=" << std::setw(10) << x[k]
                  << ", 근사=" << std::setw(12) << y_approx[k]
                  << ", 실제=" << std::setw(12) << y_true[k]
                  << ", 오차=" << std::setw(12) << error[k] << std::endl;
    }

    std::cout << "\n[테일러 근사 전체 소요 시간]" << std::endl;
    std::cout << "총 " << taylor_ms << " ms (" << (double)taylor_ms/N << " ms/1회)" << std::endl;
    return 0;
} 