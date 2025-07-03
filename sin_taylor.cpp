#include <openfhe/pke/openfhe.h>
#include <iostream>
#include <vector>
#include <cmath>
#include <iomanip>
#include <chrono>

using namespace lbcrypto;

int main() {
    // ====== 파라미터 ======
    const int64_t s = 50;         // 스케일링 상수
    const int64_t denom = 120;     // 정수화 분모
    const double x_input = 0.5236; // 30도(라디안)
    const int64_t PlaintextModulus = 1099512004609; // NTT-friendly 소수

    // ====== 테일러 계수 (정수화) ======
    const double c1 = 1.0;
    const double c3 = -1.0/6.0;
    const double c5 = 1.0/120.0;
    int64_t ic1 = static_cast<int64_t>(std::round(c1 * denom * std::pow(s,4)));
    int64_t ic3 = static_cast<int64_t>(std::round(c3 * denom * std::pow(s,2)));
    int64_t ic5 = static_cast<int64_t>(std::round(c5 * denom));

    // ====== 입력값 ======
    int64_t x_scaled = static_cast<int64_t>(std::round(s * x_input));

    // ====== 암호화 파라미터 설정 ======
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetPlaintextModulus(PlaintextModulus);
    parameters.SetMultiplicativeDepth(5);
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

    // ====== 암호화~암호공간 연산~복호화 전체 ======
    auto p_x = cc->MakePackedPlaintext({x_scaled});
    auto ct_x = cc->Encrypt(keyPair.publicKey, p_x);
    auto ct_x2 = cc->EvalMult(ct_x, ct_x);
    auto ct_x3 = cc->EvalMult(ct_x2, ct_x);
    auto ct_x5 = cc->EvalMult(ct_x3, ct_x2);

    int64_t ic3_mod = (ic3 < 0) ? (PlaintextModulus + ic3) : ic3;
    int64_t ic5_mod = (ic5 < 0) ? (PlaintextModulus + ic5) : ic5;
    auto term1 = cc->EvalMult(ct_x, cc->MakePackedPlaintext({ic1}));
    auto term2 = cc->EvalMult(ct_x3, cc->MakePackedPlaintext({ic3_mod}));
    auto term3 = cc->EvalMult(ct_x5, cc->MakePackedPlaintext({ic5_mod}));

    Plaintext p_term1, p_term2, p_term3;
    cc->Decrypt(keyPair.secretKey, term1, &p_term1);
    cc->Decrypt(keyPair.secretKey, term2, &p_term2);
    cc->Decrypt(keyPair.secretKey, term3, &p_term3);
    int64_t t1 = p_term1->GetPackedValue()[0];
    int64_t t2 = p_term2->GetPackedValue()[0];
    int64_t t3 = p_term3->GetPackedValue()[0];
    int64_t t1_orig = ic1 * x_scaled;
    int64_t t2_orig = ic3 * (x_scaled * x_scaled * x_scaled);
    int64_t t3_orig = ic5 * (x_scaled * x_scaled * x_scaled * x_scaled * x_scaled);
    if (t1 > PlaintextModulus/2) t1 -= PlaintextModulus;
    if (t2 > PlaintextModulus/2) t2 -= PlaintextModulus;
    if (t3 > PlaintextModulus/2) t3 -= PlaintextModulus;

    int64_t y_scaled = t1 + t2 + t3;
    if (y_scaled > PlaintextModulus/2) y_scaled -= PlaintextModulus;
    if (y_scaled < -PlaintextModulus/2) y_scaled += PlaintextModulus;
    double y_recovered = static_cast<double>(y_scaled) / (denom * std::pow(s,5));
    double y_true = std::sin(x_input);
    double error = std::abs(y_true - y_recovered);

    auto taylor_end = std::chrono::high_resolution_clock::now();
    auto taylor_ms = std::chrono::duration_cast<std::chrono::milliseconds>(taylor_end - taylor_start).count();

    // ====== 결과 출력 ======
    std::cout << "[항별 복호화 결과]" << std::endl;
    std::cout << "term1 (암호): " << t1 << ", (plain): " << t1_orig << std::endl;
    std::cout << "term2 (암호): " << t2 << ", (plain): " << t2_orig << std::endl;
    std::cout << "term3 (암호): " << t3 << ", (plain): " << t3_orig << std::endl;
    std::cout << "[x, 근사값, 실제값, 오차]" << std::endl;
    std::cout << "x=" << x_input
              << ", 근사=" << y_recovered
              << ", 실제=" << y_true
              << ", 오차=" << error << std::endl;
    std::cout << "\n[테일러 근사 전체 소요 시간]" << std::endl;
    std::cout << "총 " << taylor_ms << " ms" << std::endl;
    return 0;
} 