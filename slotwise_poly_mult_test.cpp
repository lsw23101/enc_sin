#include <openfhe/pke/openfhe.h>
#include <iostream>
#include <vector>
#include <iomanip>

using namespace lbcrypto;

int main() {
    // 파라미터 설정
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(3);
    parameters.SetSecurityLevel(SecurityLevel::HEStd_NotSet); // 이거 바꾸지마
    parameters.SetRingDim(8192);

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);
    cc->EvalRotateKeyGen(keyPair.secretKey, {1, 2, 3, 4, 5, 6, 7, -1, -2, -3, -4, -5, -6, -7});

    // 입력 벡터 [0, 5, 2, 4, 0, 0, 0, 0] (8슬롯)
    std::vector<int64_t> x = {0, 5, 2, 4, 0, 0, 0, 0};
    auto pt_x = cc->MakePackedPlaintext(x);
    auto ct_x = cc->Encrypt(keyPair.publicKey, pt_x);

    // 곱셈 계수 [5, 2, 4]
    std::vector<int64_t> coeffs = {5, 2, 4};
    size_t slots = x.size();

    // 결과 누적합용 벡터
    Ciphertext<DCRTPoly> ct_sum;
    bool first = true;

    for (size_t k = 0; k < coeffs.size(); ++k) {
        // k칸 왼쪽 순환 시프트
        auto ct_shift = (k == 0) ? ct_x : cc->EvalRotate(ct_x, k);
        // 제로패딩 마스크: 앞 k개는 0, 나머지는 1, wrap-around 방지
        std::vector<int64_t> mask(slots, 0);
        for (size_t i = k; i < slots - k; ++i) mask[i] = 1;
        auto ct_masked = cc->EvalMult(ct_shift, cc->MakePackedPlaintext(mask));
        // 곱셈 계수 적용: 앞 k개는 0, 나머지는 coeffs[k], wrap-around 방지
        std::vector<int64_t> coeff_mask(slots, 0);
        for (size_t i = k; i < slots - k; ++i) coeff_mask[i] = coeffs[k];
        auto ct_mult = cc->EvalMult(ct_masked, cc->MakePackedPlaintext(coeff_mask));
        if (first) {
            ct_sum = ct_mult;
            first = false;
        } else {
            ct_sum = cc->EvalAdd(ct_sum, ct_mult);
        }
    }

    // 복호화
    Plaintext pt_result;
    cc->Decrypt(keyPair.secretKey, ct_sum, &pt_result);
    pt_result->SetLength(slots);
    std::vector<int64_t> result = pt_result->GetPackedValue();

    // centered modular 보정
    int64_t mod = 65537;
    for (size_t i = 0; i < result.size(); ++i) {
        if (result[i] > mod/2) result[i] -= mod;
    }

    // 결과 출력
    std::cout << "[슬롯별 곱셈+제로패딩시프트+누적합 결과]" << std::endl;
    std::cout << "[";
    for (size_t i = 0; i < result.size(); ++i) {
        std::cout << result[i];
        if (i != result.size() - 1) std::cout << ", ";
    }
    std::cout << "]" << std::endl;

    // plain 계산과 비교
    std::vector<int64_t> plain_x = {0, 5, 2, 4, 0, 0, 0, 0};
    std::vector<int64_t> plain_coeffs = {5, 2, 4};
    std::vector<int64_t> plain_result(8, 0);
    for (size_t k = 0; k < plain_coeffs.size(); ++k) {
        for (size_t i = k; i < 8 - k; ++i) {
            plain_result[i] += plain_x[i - k] * plain_coeffs[k];
        }
    }
    std::cout << "[plain 계산 결과] [";
    for (size_t i = 0; i < plain_result.size(); ++i) {
        std::cout << plain_result[i];
        if (i != plain_result.size() - 1) std::cout << ", ";
    }
    std::cout << "]" << std::endl;

    return 0;
} 