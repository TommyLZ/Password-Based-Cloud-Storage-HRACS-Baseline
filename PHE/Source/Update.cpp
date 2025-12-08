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

void Update(string &psw, string &id, int index)
{
    cout << "***********************************Update Phase*********************************" << endl;

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
    std::string recoverDir = "../File/TestMultiple/Recover(Update)";

    char buf[16];
    sprintf(buf, "%03d", index); // 001, 002, 010, ...
    std::string filePrefix = "Test_" + std::string(buf);

    std::string cipherPath = cipherDir + "/" + filePrefix + "_cipher.dat";
    std::string ivPath = cipherDir + "/" + filePrefix + ".iv";
    cout << "ivPath" << ivPath << endl;
    std::string outputPath = recoverDir + "/" + filePrefix + "_recover.dat";

    // Load IV from file
    CryptoPP::byte iv[16 * 16];
    std::ifstream ivFile(ivPath, std::ios::binary);
    ivFile.read(reinterpret_cast<char *>(iv), sizeof(iv));
    ivFile.close();

    // Call decryption function
    cloudserver.fileDecryption(mk, iv, cipherPath, outputPath);

    cout << "after decryption" << endl;

    std::string plainDir = "../File/Update/Origin";

    // Ensure output directory exists
    fs::create_directories(cipherDir);
    // fs::create_directories(recoverDir);

    // RNG for IV
    AutoSeededRandomPool prng;

    // 计数器：用来生成 Test_XXX_cipher.dat
    int fileIndex = 1;

    // 遍历明文目录
    for (const auto &entry : fs::directory_iterator(plainDir))
    {
        if (!entry.is_regular_file())
            continue;

        fs::path infilePath = entry.path();

        // ============================
        // 构造 3 位序号
        // ============================
        char buf[16];
        sprintf(buf, "%03d", index); // 001, 002, 003, ...

        // 输出路径
        std::string outfilePath = cipherDir + "/" + filePrefix + "_cipher.dat";
        std::string ivPath = cipherDir + "/" + filePrefix + ".iv";

        // ============================
        // 生成随机 IV（16*16 字节）
        // ============================
        CryptoPP::byte iv[16 * 16];
        prng.GenerateBlock(iv, sizeof(iv));

        // 执行加密
        cloudserver.fileEncryption(mk, iv, infilePath, outfilePath, ivPath);

        // 保存 IV
        std::ofstream ivFile(ivPath, std::ios::binary);
        ivFile.write(reinterpret_cast<const char *>(iv), sizeof(iv));
        ivFile.close();

        std::cout << "Update: " << infilePath.string()
                  << " -> " << outfilePath
                  << ", IV saved at " << ivPath << std::endl;

        fileIndex++; // 序号 +1
    }

    std::cout << "All files encrypted successfully!" << std::endl;
}