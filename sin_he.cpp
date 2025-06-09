#include <openfhe/pke/openfhe.h>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <vector>
#include <cmath>

using namespace lbcrypto;

// 스케일링 상수
const int64_t SCALE = 1000;  // 10^3

// double을 스케일된 정수로 변환
int64_t scaleToInt(double val) {
    return static_cast<int64_t>(std::round(val * SCALE));
}

// 스케일된 정수를 double로 변환
double scaleToDouble(int64_t val) {
    return static_cast<double>(val) / SCALE;
}

int main() {
    // 파라미터 설정
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetPlaintextModulus(65537);  // 2^16 + 1 (Fermat 소수)
    parameters.SetMultiplicativeDepth(8);    // 곱셈 깊이
    parameters.SetSecurityLevel(SecurityLevel::HEStd_NotSet);  // 테스트용 보안 레벨
    parameters.SetRingDim(8192);            // 2^13

    std::cout << "========== 동형암호 Sin 근사 테스트 시작 ==========\n";
    
    // 암호화 컨텍스트 생성
    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    // 키 생성
    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    // 초기값 설정
    double theta = 0.0;
    double d = 0.01;  // 스텝 크기

    // 초기 sin, cos 값 (스케일링 적용)
    int64_t s_int = scaleToInt(sin(theta));
    int64_t c_int = scaleToInt(cos(theta));
    int64_t d_int = scaleToInt(d);

    std::cout << "초기값 (스케일링 적용):\n";
    std::cout << "s_int: " << s_int << " (sin(0) * " << SCALE << ")\n";
    std::cout << "c_int: " << c_int << " (cos(0) * " << SCALE << ")\n";
    std::cout << "d_int: " << d_int << " (0.01 * " << SCALE << ")\n\n";

    // 초기값 암호화
    std::vector<int64_t> vec_s = {s_int};
    std::vector<int64_t> vec_c = {c_int};
    std::vector<int64_t> vec_d = {d_int};

    auto p_s = cc->MakePackedPlaintext(vec_s);
    auto p_c = cc->MakePackedPlaintext(vec_c);
    auto p_d = cc->MakePackedPlaintext(vec_d);

    auto ct_s = cc->Encrypt(keyPair.publicKey, p_s);
    auto ct_c = cc->Encrypt(keyPair.publicKey, p_c);
    auto ct_d = cc->Encrypt(keyPair.publicKey, p_d);

    // 1차 근사 2회 반복
    for(int i = 0; i < 2; i++) {
        std::cout << "\n스텝 " << i+1 << " 시작\n";
        
        // s_new = s + c*d
        auto term_s = cc->EvalMult(ct_c, ct_d);  // c*d (SCALE^2)
        term_s = cc->EvalMult(term_s, cc->MakePackedPlaintext(std::vector<int64_t>{1000}));  // SCALE로 나누기
        auto ct_s_new = cc->EvalAdd(ct_s, term_s);

        // c_new = c - s*d
        auto term_c = cc->EvalMult(ct_s, ct_d);  // s*d (SCALE^2)
        term_c = cc->EvalMult(term_c, cc->MakePackedPlaintext(std::vector<int64_t>{1000}));  // SCALE로 나누기
        auto ct_c_new = cc->EvalSub(ct_c, term_c);

        // 결과 복호화 및 출력
        Plaintext p_result_s, p_result_c;
        cc->Decrypt(keyPair.secretKey, ct_s_new, &p_result_s);
        cc->Decrypt(keyPair.secretKey, ct_c_new, &p_result_c);
        
        std::cout << "암호화된 sin 값: " << scaleToDouble(p_result_s->GetPackedValue()[0]) << "\n";
        std::cout << "암호화된 cos 값: " << scaleToDouble(p_result_c->GetPackedValue()[0]) << "\n";
        
        // 실제 값과 비교
        theta += d;
        std::cout << "실제 sin 값: " << sin(theta) << "\n";
        std::cout << "실제 cos 값: " << cos(theta) << "\n";
        
        // 다음 스텝을 위한 값 업데이트
        ct_s = ct_s_new;
        ct_c = ct_c_new;
    }

    return 0;
} 