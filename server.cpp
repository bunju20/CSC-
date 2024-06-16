#include "seal/seal.h"
#include <iostream>
#include <fstream>
#include <vector>

using namespace std;
using namespace seal;

int main()
{
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

    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder encoder(context);

    ifstream in("encrypted_votes.bin", ios::binary);
    if (!in.is_open())
    {
        cerr << "Failed to open the votes file." << endl;
        return 1;
    }

    if (in.peek() == EOF)
    {
        cout << "No votes have been cast." << endl;
        return 0;
    }

    Ciphertext total_votes;
    bool first_vote = true;

    try
    {
        while (true)
        {
            Ciphertext encrypted_vote;

            if (in.peek() == EOF)
            {
                break; // 파일 끝이면 루프 종료
            }

            // 데이터 읽기
            try
            {
                encrypted_vote.load(context, in);
                cout << "Loaded encrypted vote." << endl; // 디버깅 출력
            }
            catch (const exception &e)
            {
                cerr << "Failed to load an encrypted vote: " << e.what() << endl;
                break;
            }

            if (first_vote)
            {
                total_votes = encrypted_vote;
                first_vote = false;
            }
            else
            {
                evaluator.add_inplace(total_votes, encrypted_vote);
            }
        }
    }
    catch (const exception &e)
    {
        cerr << "An unexpected error occurred: " << e.what() << endl;
        return 1;
    }

    in.close();

    // 결과를 복호화하고 디코드하는 과정
    Plaintext plain_result;
    decryptor.decrypt(total_votes, plain_result);
    vector<uint64_t> result_vector;
    encoder.decode(plain_result, result_vector);

    cout << "Vote counting completed!" << endl;
    cout << "Result: " << endl;
    for (size_t i = 0; i < 10; i++)
    {
        cout << "Candidate " << i + 1 << ": " << result_vector[i] << " votes" << endl;
    }

    return 0;
}
