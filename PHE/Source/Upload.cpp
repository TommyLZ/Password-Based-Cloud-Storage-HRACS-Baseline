#include "Decryption.h"

#include "Client.h"
#include "KeyServer.h"
#include "CloudServer.h"
#include <cryptopp/osrng.h>
#include <pbc/pbc.h>
#include <filesystem>
#include <fstream>

extern pairing_t pairing;

namespace fs = std::filesystem;

void Upload(string &psw, string &id)
{
    cout << "***********************************Upload Phase*********************************" << endl;

    // User inputs password & ID to the Client
    // Object instantiation
    Client client(psw, id);
    KeyServer keyserver;
    CloudServer cloudserver;

    // Password blindness
    element_t a;
    element_init_G1(a, pairing);
    client.blindPassword(a);
    cout << "The client blinds the password and sends it to the key server!" << endl;

    // Password hardening
    element_t b;
    element_init_G1(b, pairing);
    keyserver.hardenPassword(b, a);
    cout << "Password Hardening Finished!" << endl;

    // Log in to the cloud server
    string cred_cs;
    client.CredentialGen(cred_cs, b, a, keyserver.public_key);
    cout << "The client ready to log in the cloud server!" << endl;

    // Cloud server authenticates the client
    cloudserver.authenInEnc(id, cred_cs);
    cout << "You have successfully logged in the cloud server!" << endl;

    // Encrypt the file
    element_t c0;
    element_init_G1(c0, pairing);
    element_t c1;
    element_init_G1(c1, pairing);
    element_t hr1;
    element_init_G1(hr1, pairing);
    element_t hs1;
    element_init_G1(hs1, pairing);

    element_t mk;
    element_init_G1(mk, pairing);

    cloudserver.decrypt(c0, cred_cs, hr1, hs1);
    keyserver.decrypt(c1, c0);
    cloudserver.key_Recover(mk, c1, hr1, hs1, keyserver.public_key);
    cout << "The key recovery is finished!" << endl;

    element_printf("mk = %B\n", mk);

    std::string plainDir = "../File/TestMultiple/Origin";
    std::string cipherDir = "../File/TestMultiple/Cipher";

    // Ensure output directory exists
    fs::create_directories(cipherDir);
    // fs::create_directories(recoverDir);

    // RNG for IV
    AutoSeededRandomPool prng;

    // Iterate all files in plainDir
    for (const auto &entry : fs::directory_iterator(plainDir))
    {
        if (!entry.is_regular_file())
            continue;

        fs::path infilePath = entry.path();
        std::string stem = infilePath.stem().string(); // filename without extension
        cout << "stem: " << stem << endl;
        std::string outfilePath = cipherDir + "/" + stem + "_cipher.dat";
        std::string ivPath = cipherDir + "/" + stem + ".iv";

        // Generate random IV: 16*16 bytes as in your function
        CryptoPP::byte iv[16 * 16];
        prng.GenerateBlock(iv, sizeof(iv));

        // Call your existing encryption function
        cloudserver.fileEncryption(mk, iv, infilePath, outfilePath, ivPath);

        std::cout << "Encrypted: " << infilePath.string() << " -> " << outfilePath << std::endl;
    }

    std::cout << "All files encrypted successfully!" << std::endl;
}