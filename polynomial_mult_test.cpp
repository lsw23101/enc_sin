#define PROFILE
#include <openfhe/pke/openfhe.h>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <vector>

using namespace lbcrypto;

// 다항식 곱셈 함수 (직접 구현)
std::vector<int64_t> polynomial_multiply(const std::vector<int64_t>& poly1, 
                                        const std::vector<int64_t>& poly2,
                                        int64_t mod) {
    int n1 = poly1.size();
    int n2 = poly2.size();
    int result_size = n1 + n2 - 1;
    std::vector<int64_t> result(result_size, 0);
    
    for (int i = 0; i < n1; i++) {
        for (int j = 0; j < n2; j++) {
            result[i + j] = (result[i + j] + poly1[i] * poly2[j]) % mod;
        }
    }
    
    return result;
}

int main() {
    // 파라미터 설정
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(2);  // 다항식 곱셈을 위해 2로 설정
    parameters.SetSecurityLevel(SecurityLevel::HEStd_NotSet);
    parameters.SetRingDim(4096);

    std::cout << "========== 다항식 곱셈 테스트 시작 ==========\n";
    
    // 컨텍스트 생성
    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    // 키 생성
    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);
    cc->EvalRotateKeyGen(keyPair.secretKey, {1, 2, -1}); // 시프트 키 생성

    // 테스트 다항식 준비
    // poly1 = 2x + 3, poly2 = 5x + 5
    std::vector<int64_t> poly1 = {3, 2};  // 상수항, 1차항
    std::vector<int64_t> poly2 = {5, 6};  // 상수항, 1차항
    
    std::cout << "다항식 1: " << poly1[1] << "x + " << poly1[0] << std::endl;
    std::cout << "다항식 2: " << poly2[1] << "x + " << poly2[0] << std::endl;

    // Plain 다항식 곱셈 결과
    auto plain_result = polynomial_multiply(poly1, poly2, 65537);
    std::cout << "\n[Plain 다항식 곱셈 결과]" << std::endl;
    std::cout << "결과: ";
    for (size_t i = 0; i < plain_result.size(); i++) {
        if (i > 0) std::cout << " + ";
        std::cout << plain_result[i] << "x^" << i;
    }
    std::cout << std::endl;

    // 암호화
    auto plaintext1 = cc->MakePackedPlaintext(poly1);
    auto plaintext2 = cc->MakePackedPlaintext(poly2);
    auto ciphertext1 = cc->Encrypt(keyPair.publicKey, plaintext1);
    auto ciphertext2 = cc->Encrypt(keyPair.publicKey, plaintext2);

    // 방법 1: 진정한 다항식 컨볼루션 곱셈
    std::cout << "\n[방법 1: 진정한 다항식 컨볼루션 곱셈]" << std::endl;
    
    // 다항식 곱셈: (2x + 3) * (5x + 5) = 10x² + 25x + 15
    
    // 각 항을 개별적으로 계산
    // 1. 상수항: 3 * 5 = 15
    auto ct_const_const = cc->EvalMult(
        cc->EvalMult(ciphertext1, cc->MakePackedPlaintext({1, 0})), // 3
        cc->EvalMult(ciphertext2, cc->MakePackedPlaintext({1, 0}))  // 5
    );
    
    // 2. 1차항: 3*5x + 2x*5 = 15x + 10x = 25x
    // 3*5x 계산
    auto ct_const_linear = cc->EvalMult(
        cc->EvalMult(ciphertext1, cc->MakePackedPlaintext({1, 0})), // 3
        cc->EvalMult(ciphertext2, cc->MakePackedPlaintext({0, 1}))  // 5x
    );
    
    // 2x*5 계산
    auto ct_linear_const = cc->EvalMult(
        cc->EvalMult(ciphertext1, cc->MakePackedPlaintext({0, 1})), // 2x
        cc->EvalMult(ciphertext2, cc->MakePackedPlaintext({1, 0}))  // 5
    );
    
    // 1차항 합산
    auto ct_linear_sum = cc->EvalAdd(ct_const_linear, ct_linear_const);
    
    // 3. 2차항: 2x * 5x = 10x²
    auto ct_linear_linear = cc->EvalMult(
        cc->EvalMult(ciphertext1, cc->MakePackedPlaintext({0, 1})), // 2x
        cc->EvalMult(ciphertext2, cc->MakePackedPlaintext({0, 1}))  // 5x
    );
    
    // 복호화
    Plaintext dec_const_const, dec_linear_sum, dec_linear_linear;
    cc->Decrypt(keyPair.secretKey, ct_const_const, &dec_const_const);
    cc->Decrypt(keyPair.secretKey, ct_linear_sum, &dec_linear_sum);
    cc->Decrypt(keyPair.secretKey, ct_linear_linear, &dec_linear_linear);
    
    std::vector<int64_t> result_const_const = dec_const_const->GetPackedValue();
    std::vector<int64_t> result_linear_sum = dec_linear_sum->GetPackedValue();
    std::vector<int64_t> result_linear_linear = dec_linear_linear->GetPackedValue();
    
    // centered modular 보정
    int64_t mod = 65537;
    for (int i = 0; i < 2; i++) {
        if (result_const_const[i] > mod/2) result_const_const[i] -= mod;
        if (result_linear_sum[i] > mod/2) result_linear_sum[i] -= mod;
        if (result_linear_linear[i] > mod/2) result_linear_linear[i] -= mod;
    }
    
    std::cout << "상수항 (x⁰): " << result_const_const[0] << std::endl;
    std::cout << "1차항 (x¹): " << result_linear_sum[0] << std::endl;
    std::cout << "2차항 (x²): " << result_linear_linear[0] << std::endl;
    
    // 최종 결과 조합
    std::vector<int64_t> final_result = {result_const_const[0], result_linear_sum[0], result_linear_linear[0]};
    std::cout << "암호문끼리 곱셈 결과: [" << final_result[0] << ", " << final_result[1] << ", " << final_result[2] << "]" << std::endl;

    // 방법 2: 단순 암호문 곱셈 (요소별 곱셈)
    std::cout << "\n[방법 2: 단순 암호문 곱셈 (요소별)]" << std::endl;
    auto ct_simple_mult = cc->EvalMult(ciphertext1, ciphertext2);
    
    Plaintext dec_simple;
    cc->Decrypt(keyPair.secretKey, ct_simple_mult, &dec_simple);
    std::vector<int64_t> result_simple = dec_simple->GetPackedValue();
    
    // centered modular 보정
    for (size_t i = 0; i < result_simple.size(); i++) {
        if (result_simple[i] > mod/2) result_simple[i] -= mod;
    }
    
    std::cout << "요소별 곱셈 결과: [" << result_simple[0] << ", " << result_simple[1] << "]" << std::endl;

    // 결과 비교
    std::cout << "\n[결과 비교]" << std::endl;
    std::cout << "Plain 다항식 곱셈: [" << plain_result[0] << ", " << plain_result[1] << ", " << plain_result[2] << "]" << std::endl;
    std::cout << "암호문끼리 곱셈: [" << final_result[0] << ", " << final_result[1] << ", " << final_result[2] << "]" << std::endl;
    std::cout << "요소별 곱셈: [" << result_simple[0] << ", " << result_simple[1] << "]" << std::endl;
    std::cout << "예상 결과: [15, 25, 10]" << std::endl;
    
    // 정확성 검증
    bool is_correct = (final_result[0] == plain_result[0] && 
                      final_result[1] == plain_result[1] && 
                      final_result[2] == plain_result[2]);
    std::cout << "\n암호문끼리 곱셈 정확성: " << (is_correct ? "O" : "X") << std::endl;
    
    // 계산 과정 설명
    std::cout << "\n[계산 과정]" << std::endl;
    std::cout << "(2x + 3) * (5x + 5) = 2x*5x + 2x*5 + 3*5x + 3*5" << std::endl;
    std::cout << "                    = 10x² + 10x + 15x + 15" << std::endl;
    std::cout << "                    = 10x² + 25x + 15" << std::endl;

    return 0;
} 