#define PROFILE  // for TIC TOC
#include <openfhe/pke/openfhe.h>
#include <chrono>
#include <iomanip>
#include <iostream>

using namespace lbcrypto;

int main() {
    // 파라미터 설정
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(0);  // 덧셈만 사용하므로 0으로 설정
    parameters.SetSecurityLevel(SecurityLevel::HEStd_128_classic);
    parameters.SetRingDim(4096);  // 2^12

    std::cout << "========== BGV 암호화 성능 테스트 시작 ==========\n";
    
    // 컨텍스트 생성 시간 측정
    auto context_start = std::chrono::high_resolution_clock::now();
    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    auto context_end = std::chrono::high_resolution_clock::now();
    auto context_time = std::chrono::duration_cast<std::chrono::microseconds>(
        context_end - context_start).count() / 1000.0;
    std::cout << "컨텍스트 생성 시간: " << context_time << " ms\n";

    // 키 생성 시간 측정
    auto keygen_start = std::chrono::high_resolution_clock::now();
    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);
    cc->EvalSumKeyGen(keyPair.secretKey);
    auto keygen_end = std::chrono::high_resolution_clock::now();
    auto keygen_time = std::chrono::duration_cast<std::chrono::microseconds>(
        keygen_end - keygen_start).count() / 1000.0;
    std::cout << "키 생성 시간: " << keygen_time << " ms\n\n";

    // 테스트 데이터 준비
    std::vector<int64_t> x = {5544};  // 테스트 값
    std::vector<int64_t> y = {5544};

    // 암호화 시간 측정
    auto enc_start = std::chrono::high_resolution_clock::now();
    auto plaintextX = cc->MakePackedPlaintext(x);
    auto plaintextY = cc->MakePackedPlaintext(y);
    auto ciphertextX = cc->Encrypt(keyPair.publicKey, plaintextX);
    auto ciphertextY = cc->Encrypt(keyPair.publicKey, plaintextY);
    auto enc_end = std::chrono::high_resolution_clock::now();
    auto enc_time = std::chrono::duration_cast<std::chrono::microseconds>(
        enc_end - enc_start).count() / 1000.0;
    std::cout << "암호화 시간 (두 개의 값): " << enc_time << " ms\n";

    // 복호화 시간 측정
    auto dec_start = std::chrono::high_resolution_clock::now();
    Plaintext decryptedX;
    Plaintext decryptedY;
    cc->Decrypt(keyPair.secretKey, ciphertextX, &decryptedX);
    cc->Decrypt(keyPair.secretKey, ciphertextY, &decryptedY);
    decryptedX->SetLength(1);
    decryptedY->SetLength(1);
    auto dec_end = std::chrono::high_resolution_clock::now();
    auto dec_time = std::chrono::duration_cast<std::chrono::microseconds>(
        dec_end - dec_start).count() / 1000.0;
    std::cout << "복호화 시간 (두 개의 값): " << dec_time << " ms\n";

    // 결과 확인
    std::cout << "\n복호화된 결과:\n";
    std::cout << "X: " << decryptedX->GetPackedValue()[0] << "\n";
    std::cout << "Y: " << decryptedY->GetPackedValue()[0] << "\n";

    // 전체 시간 계산
    auto total_time = context_time + keygen_time + enc_time + dec_time;
    std::cout << "\n========== 성능 요약 ==========\n";
    std::cout << "컨텍스트 생성: " << context_time << " ms (" 
              << std::fixed << std::setprecision(1) << (context_time/total_time)*100 << "%)\n";
    std::cout << "키 생성: " << keygen_time << " ms (" 
              << (keygen_time/total_time)*100 << "%)\n";
    std::cout << "암호화: " << enc_time << " ms (" 
              << (enc_time/total_time)*100 << "%)\n";
    std::cout << "복호화: " << dec_time << " ms (" 
              << (dec_time/total_time)*100 << "%)\n";
    std::cout << "총 시간: " << total_time << " ms (100%)\n";
    std::cout << "==============================\n";

    return 0;
} 