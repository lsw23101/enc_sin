#include <openfhe/pke/openfhe.h>
#include <iostream>
#include <vector>
#include <cmath>
#include <iomanip>
#include <chrono>

using namespace lbcrypto;

int main() {
    // ====== 파라미터 ======
    const int64_t s = 50;         // 스케일링 상수 지금은 0.2 만큼의 해상도
    const int64_t denom = 6;     // 정수화 분모
    const int64_t PlaintextModulus = 536903681; // 더 작은 NTT-friendly 소수 (약 29비트)

    // ====== 테일러 계수 (정수화) ======
    const double c1 = 1.0;
    const double c3 = -1.0/6.0;
    int64_t ic1 = static_cast<int64_t>(std::round(c1 * denom * std::pow(s,2)));
    int64_t ic3 = static_cast<int64_t>(std::round(c3 * denom * std::pow(s,0)));

    std::cout << "=== 3차 근사 파라미터 정보 ===" << std::endl;
    std::cout << "PlaintextModulus: " << PlaintextModulus << " (약 " << std::log2(PlaintextModulus) << " 비트)" << std::endl;
    std::cout << "ic1: " << ic1 << std::endl;
    std::cout << "ic3: " << ic3 << std::endl;
    std::cout << "PlaintextModulus/2: " << PlaintextModulus/2 << std::endl;
    std::cout << "===============================" << std::endl;

    // ====== 암호화 파라미터 설정 ======
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetPlaintextModulus(PlaintextModulus);
    parameters.SetMultiplicativeDepth(4);
    // parameters.SetSecurityLevel(SecurityLevel::HEStd_NotSet);
    parameters.SetSecurityLevel(SecurityLevel::HEStd_128_classic);
    parameters.SetRingDim(16384);

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::cout << std::fixed << std::setprecision(6);
    std::cout << "각도(도)\tx_input(rad)\t근사값\t실제값\t오차\tterm1_raw\tterm2_raw\tterm1_mod\tterm2_mod\t암호화(ms)\t연산(ms)\t복호화(ms)\t총시간(ms)" << std::endl;

    for (int deg = -180; deg <= 180; deg += 10) {
        double x_input = deg * M_PI / 180.0;
        int64_t x_scaled = static_cast<int64_t>(std::round(s * x_input));

        // ====== 시간 측정 변수들 ======
        auto start_total = std::chrono::high_resolution_clock::now();
        auto start_encrypt = std::chrono::high_resolution_clock::now();
        
        // ====== 암호화 ======
        auto p_x = cc->MakePackedPlaintext({x_scaled});
        auto ct_x = cc->Encrypt(keyPair.publicKey, p_x);
        
        auto end_encrypt = std::chrono::high_resolution_clock::now();
        auto start_compute = std::chrono::high_resolution_clock::now();
        
        // ====== 암호공간 연산 ======
        auto ct_x2 = cc->EvalMult(ct_x, ct_x);
        auto ct_x3 = cc->EvalMult(ct_x2, ct_x);

        int64_t ic3_mod = (ic3 < 0) ? (PlaintextModulus + ic3) : ic3;
        auto term1 = cc->EvalMult(ct_x, cc->MakePackedPlaintext({ic1}));
        auto term2 = cc->EvalMult(ct_x3, cc->MakePackedPlaintext({ic3_mod}));
        
        auto end_compute = std::chrono::high_resolution_clock::now();
        auto start_decrypt = std::chrono::high_resolution_clock::now();

        // ====== 복호화 ======
        Plaintext p_term1, p_term2;
        cc->Decrypt(keyPair.secretKey, term1, &p_term1);
        cc->Decrypt(keyPair.secretKey, term2, &p_term2);
        
        auto end_decrypt = std::chrono::high_resolution_clock::now();
        auto end_total = std::chrono::high_resolution_clock::now();

        // ====== 결과 계산 ======
        int64_t t1_raw = p_term1->GetPackedValue()[0];
        int64_t t2_raw = p_term2->GetPackedValue()[0];
        int64_t t1 = t1_raw;
        int64_t t2 = t2_raw;
        if (t1 > PlaintextModulus/2) t1 -= PlaintextModulus;
        if (t2 > PlaintextModulus/2) t2 -= PlaintextModulus;

        int64_t y_scaled = t1 + t2;
        if (y_scaled > PlaintextModulus/2) y_scaled -= PlaintextModulus;
        if (y_scaled < -PlaintextModulus/2) y_scaled += PlaintextModulus;
        double y_recovered = static_cast<double>(y_scaled) / (denom * std::pow(s,3));
        double y_true = std::sin(x_input);
        double error = std::abs(y_true - y_recovered);

        // ====== 시간 계산 ======
        auto encrypt_time = std::chrono::duration_cast<std::chrono::microseconds>(end_encrypt - start_encrypt).count() / 1000.0;
        auto compute_time = std::chrono::duration_cast<std::chrono::microseconds>(end_compute - start_compute).count() / 1000.0;
        auto decrypt_time = std::chrono::duration_cast<std::chrono::microseconds>(end_decrypt - start_decrypt).count() / 1000.0;
        auto total_time = std::chrono::duration_cast<std::chrono::microseconds>(end_total - start_total).count() / 1000.0;

        std::cout << deg << "\t" << x_input << "\t" << y_recovered << "\t" << y_true << "\t" << error 
                  << "\t" << t1_raw << "\t" << t2_raw << "\t" << t1 << "\t" << t2
                  << "\t" << std::fixed << std::setprecision(2) << encrypt_time 
                  << "\t" << compute_time 
                  << "\t" << decrypt_time 
                  << "\t" << total_time << std::endl;
    }

    return 0;
} 