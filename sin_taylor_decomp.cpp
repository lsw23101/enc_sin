#include <openfhe/pke/openfhe.h>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <vector>
#include <cmath>

using namespace lbcrypto;

int main() {
    // ====== 파라미터 ======
    const int64_t denom = 120;     // 테일러 계수 정수화 분모
    const std::vector<int64_t> x_digits = {5, 2, 3, 6}; // 0.5236 → [5,2,3,6]
    const std::vector<double> digit_scale = {1e-1, 1e-2, 1e-3, 1e-4}; // 자리수 보정
    const size_t num_digits = x_digits.size();

    // ====== 테일러 계수 (정수화) ======
    const double c1 = 1.0;
    const double c3 = -1.0/6.0;
    const double c5 = 1.0/120.0;
    int64_t ic1 = static_cast<int64_t>(std::round(c1 * denom));
    int64_t ic3 = static_cast<int64_t>(std::round(c3 * denom));
    int64_t ic5 = static_cast<int64_t>(std::round(c5 * denom));

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

    // ====== 시간 측정 시작 ======
    auto taylor_start = std::chrono::high_resolution_clock::now();

    // ====== 입력값 패킹 및 암호화 ======
    auto p_x = cc->MakePackedPlaintext(x_digits);
    auto ct_x = cc->Encrypt(keyPair.publicKey, p_x);

    // ====== 암호공간에서 벡터 연산 ======
    auto ct_x2 = cc->EvalMult(ct_x, ct_x);           // x^2
    auto ct_x3 = cc->EvalMult(ct_x2, ct_x);          // x^3
    auto ct_x5 = cc->EvalMult(ct_x3, ct_x2);         // x^5

    // ====== 항별 상수곱 (음수 상수는 modulus + 음수값으로 변환) ======
    int64_t PlaintextModulus = 1099512004609;
    int64_t ic3_mod = (ic3 < 0) ? (PlaintextModulus + ic3) : ic3;
    int64_t ic5_mod = (ic5 < 0) ? (PlaintextModulus + ic5) : ic5;
    auto term1 = cc->EvalMult(ct_x, cc->MakePackedPlaintext(std::vector<int64_t>(num_digits, ic1)));
    auto term2 = cc->EvalMult(ct_x3, cc->MakePackedPlaintext(std::vector<int64_t>(num_digits, ic3_mod)));
    auto term3 = cc->EvalMult(ct_x5, cc->MakePackedPlaintext(std::vector<int64_t>(num_digits, ic5_mod)));

    // ====== 합산 ======
    auto ct_y = cc->EvalAdd(term1, term2);
    ct_y = cc->EvalAdd(ct_y, term3);

    // ====== 복호화 ======
    Plaintext p_y;
    cc->Decrypt(keyPair.secretKey, ct_y, &p_y);
    std::vector<int64_t> y_vec = p_y->GetPackedValue();
    // centered modular 보정
    for (size_t i = 0; i < y_vec.size(); ++i) {
        if (y_vec[i] > PlaintextModulus/2) y_vec[i] -= PlaintextModulus;
    }

    // ====== 자리수 보정 및 합산 ======
    double y_sum = 0.0;
    for (size_t i = 0; i < num_digits; ++i) {
        y_sum += (static_cast<double>(y_vec[i]) / denom) * digit_scale[i];
    }

    auto taylor_end = std::chrono::high_resolution_clock::now();
    auto taylor_ms = std::chrono::duration_cast<std::chrono::milliseconds>(taylor_end - taylor_start).count();

    // ====== 실제값 및 오차 ======
    double x_true = 0.5236;
    double y_true = std::sin(x_true);
    double error = std::abs(y_true - y_sum);

    // ====== 결과 출력 ======
    std::cout << "[패킹된 벡터 복호화 결과]" << std::endl;
    std::cout << "y_vec = [";
    for (size_t i = 0; i < num_digits; ++i) std::cout << y_vec[i] << (i+1<num_digits?", ":"]\n");
    std::cout << "자리수 보정 및 합산 결과: " << y_sum << std::endl;
    std::cout << "실제값: " << y_true << std::endl;
    std::cout << "오차: " << error << std::endl;
    std::cout << "\n[테일러 근사 전체 소요 시간]" << std::endl;
    std::cout << "총 " << taylor_ms << " ms" << std::endl;
    return 0;
} 