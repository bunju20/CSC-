#include "seal/seal.h"
#include <iostream>
#include <vector>

using namespace std;
using namespace seal;

int main()
{
    cout << "Start" << endl;

    // 동형 암호 파라미터 설정
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    SEALContext context(parms);
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder encoder(context);

    size_t slot_count = encoder.slot_count();

    // 총 5번의 투표를 입력받고 암호화하여 집계
    Ciphertext total_votes;
    bool first_vote = true;
    for (int i = 0; i < 5; i++)
    {
        cout << "Enter vote (candidate number 1-10): ";
        int vote_choice;
        cin >> vote_choice;

        // 입력 유효성 검사
        if (vote_choice < 1 || vote_choice > 10)
        {
            cout << "Invalid vote. Please enter a number between 1 and 10." << endl;
            i--; // 유효하지 않은 입력일 경우, 다시 입력받기
            continue;
        }

        vector<uint64_t> vote_vector(slot_count, 0ULL); // 각 투표마다 새로운 벡터 초기화
        vote_vector[vote_choice - 1] = 1;               // 선택된 후보에 투표

        Plaintext plain_vote;
        encoder.encode(vote_vector, plain_vote);

        Ciphertext encrypted_vote;
        encryptor.encrypt(plain_vote, encrypted_vote);

        // 첫 번째 투표인 경우 total_votes 초기화
        if (first_vote)
        {
            total_votes = encrypted_vote;
            first_vote = false;
        }
        else
        {
            evaluator.add_inplace(total_votes, encrypted_vote);
        }

        cout << "Vote " << (i + 1) << " encrypted and added to total." << endl;
    }

    // 암호화된 총 투표 결과의 일부 속성 출력
    cout << "Encrypted total votes size: " << total_votes.size() << endl;
    cout << "Noise budget in encrypted total votes: " << decryptor.invariant_noise_budget(total_votes) << " bits" << endl;

    // 집계된 투표 결과 복호화
    Plaintext plain_result;
    decryptor.decrypt(total_votes, plain_result);

    vector<uint64_t> result_vector;
    encoder.decode(plain_result, result_vector);

    // 투표 결과 출력
    cout << "Vote counting completed!" << endl;
    cout << "Result: " << endl;
    for (size_t i = 0; i < 10; i++)
    {
        cout << "Candidate " << i + 1 << ": " << result_vector[i] << " votes" << endl;
    }

    return 0;
}
