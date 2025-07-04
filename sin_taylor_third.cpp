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
    const int64_t PlaintextModulus = 1099512004609; // NTT-friendly 소수


    // ====== 테일러 계수 (정수화) ======
    const double c1 = 1.0;
    const double c3 = -1.0/6.0;
    int64_t ic1 = static_cast<int64_t>(std::round(c1 * denom * std::pow(s,2)));
    int64_t ic3 = static_cast<int64_t>(std::round(c3 * denom * std::pow(s,0)));

    // ====== 암호화 파라미터 설정 ======
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetPlaintextModulus(PlaintextModulus);
    parameters.SetMultiplicativeDepth(4);
    parameters.SetSecurityLevel(SecurityLevel::HEStd_NotSet);
    // parameters.SetSecurityLevel(SecurityLevel::HEStd_128_classic);
    parameters.SetRingDim(8192);

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::cout << std::fixed << std::setprecision(6);
    std::cout << "각도(도)\tx_input(rad)\t근사값\t실제값\t오차" << std::endl;

    for (int deg = -90; deg <= 90; deg += 10) {
        double x_input = deg * M_PI / 180.0;
        int64_t x_scaled = static_cast<int64_t>(std::round(s * x_input));

        // ====== 암호화~암호공간 연산~복호화 전체 ======
        auto p_x = cc->MakePackedPlaintext({x_scaled});
        auto ct_x = cc->Encrypt(keyPair.publicKey, p_x);
        auto ct_x2 = cc->EvalMult(ct_x, ct_x);
        auto ct_x3 = cc->EvalMult(ct_x2, ct_x);

        int64_t ic3_mod = (ic3 < 0) ? (PlaintextModulus + ic3) : ic3;
        auto term1 = cc->EvalMult(ct_x, cc->MakePackedPlaintext({ic1}));
        auto term2 = cc->EvalMult(ct_x3, cc->MakePackedPlaintext({ic3_mod}));

        Plaintext p_term1, p_term2;
        cc->Decrypt(keyPair.secretKey, term1, &p_term1);
        cc->Decrypt(keyPair.secretKey, term2, &p_term2);
        int64_t t1 = p_term1->GetPackedValue()[0];
        int64_t t2 = p_term2->GetPackedValue()[0];
        if (t1 > PlaintextModulus/2) t1 -= PlaintextModulus;
        if (t2 > PlaintextModulus/2) t2 -= PlaintextModulus;

        int64_t y_scaled = t1 + t2;
        if (y_scaled > PlaintextModulus/2) y_scaled -= PlaintextModulus;
        if (y_scaled < -PlaintextModulus/2) y_scaled += PlaintextModulus;
        double y_recovered = static_cast<double>(y_scaled) / (denom * std::pow(s,3));
        double y_true = std::sin(x_input);
        double error = std::abs(y_true - y_recovered);

        std::cout << deg << "\t" << x_input << "\t" << y_recovered << "\t" << y_true << "\t" << error << std::endl;
    }

    return 0;
} 