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

void BatchQuery(string &psw, string &id, vector<int> indexList)
{
    cout << "***********************************SingleQuery Phase*********************************" << endl;

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

    std::string cipherDir = "../File/TestMultiple/Cipher";
    std::string recoverDir = "../File/TestMultiple/Recover(Batch)";

    for (int index : indexList)
    {
        char buf[16];
        sprintf(buf, "%03d", index); // 001, 002, 010 ...

        std::string prefix = "Test_" + std::string(buf);

        std::string cipherPath = cipherDir + "/" + prefix + "_cipher.dat";
        std::string ivPath = cipherDir + "/" + prefix + ".iv";
        std::string outPath = recoverDir + "/" + prefix + "_recover.dat";

        // 检查文件是否存在
        if (!fs::exists(cipherPath))
        {
            std::cout << "⚠️ Cipher not found: " << cipherPath << endl;
            continue;
        }
        if (!fs::exists(ivPath))
        {
            std::cout << "⚠️ IV not found: " << ivPath << endl;
            continue;
        }

        // 读取 IV
        CryptoPP::byte iv[16 * 16];
        std::ifstream ivFile(ivPath, std::ios::binary);
        ivFile.read(reinterpret_cast<char *>(iv), sizeof(iv));
        ivFile.close();

        // Call decryption function
        cloudserver.fileDecryption(mk, iv, cipherPath, outPath);

        std::cout << "✔️ Decrypted: " << cipherPath
                  << " -> " << outPath << endl;
    }

    cout << "BatchQuery Finished!" << endl;
}