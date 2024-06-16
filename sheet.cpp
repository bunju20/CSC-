#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <fstream>

using namespace std;
using namespace seal;

void client(const PublicKey &public_key, const string &filename)
{
    // 동형 암호 파라미터 설정
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    // 클라이언트 설정
    SEALContext context(parms);
    Encryptor encryptor(context, public_key);
    BatchEncoder encoder(context);
    size_t slot_count = encoder.slot_count();

    char another_vote;
    ofstream out(filename, ios::binary | ios::trunc); // 파일 초기화
    out.close();

    do
    {
        int vote_choice;
        cout << "Enter vote (candidate number 1-10): ";
        cin >> vote_choice;

        if (vote_choice < 1 || vote_choice > 10)
        {
            cerr << "Invalid vote. Please enter a number between 1 and 10." << endl;
            continue;
        }

        vector<uint64_t> vote_vector(slot_count, 0ULL);
        vote_vector[vote_choice - 1] = 1;

        Plaintext plain_vote;
        encoder.encode(vote_vector, plain_vote);

        Ciphertext encrypted_vote;
        encryptor.encrypt(plain_vote, encrypted_vote);

        try
        {
            ofstream out(filename, ios::binary | ios::app);
            if (!out.is_open())
            {
                cerr << "Failed to open file for writing." << endl;
                return;
            }
            encrypted_vote.save(out);
            out.close();
        }
        catch (const exception &e)
        {
            cerr << "Failed to save encrypted vote: " << e.what() << endl;
            return;
        }

        cout << "Your vote is encrypted and stored." << endl;

        cout << "Would you like to enter another vote? (y/n): ";
        cin >> another_vote;
    } while (another_vote == 'y' || another_vote == 'Y');
}

Ciphertext server(const string &filename)
{
    // 동형 암호 파라미터 설정
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    // 서버 설정
    SEALContext context(parms);
    Evaluator evaluator(context);
    BatchEncoder encoder(context);

    ifstream in(filename, ios::binary);
    if (!in.is_open())
    {
        cerr << "Failed to open the votes file." << endl;
        throw runtime_error("Failed to open the votes file.");
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

            try
            {
                encrypted_vote.load(context, in);
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
        throw;
    }

    in.close();
    return total_votes;
}

void client_decrypt_and_display_results(const SecretKey &secret_key, const Ciphertext &total_votes)
{
    // 동형 암호 파라미터 설정
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    // 클라이언트 설정
    SEALContext context(parms);
    Decryptor decryptor(context, secret_key);
    BatchEncoder encoder(context);

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
}

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

    // 클라이언트가 투표하는 과정
    client(public_key, "encrypted_votes.bin");

    // 서버가 집계하는 과정
    Ciphertext total_votes = server("encrypted_votes.bin");

    // 클라이언트가 결과를 복호화하고 출력하는 과정
    client_decrypt_and_display_results(secret_key, total_votes);

    return 0;
}
