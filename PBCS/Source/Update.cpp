#include "Take.h"
#include "Client.h"
#include "KeyServer.h"
#include "CloudServer.h"
#include "PublicParam.h"
#include "SingleQuery.h"

#include <iostream>
#include <fstream>
#include <cryptopp/osrng.h>
#include <filesystem>
using namespace std;

extern pairing_t pairing;

namespace fs = std::filesystem;

void Update(string &psw, string &id, int index)
{
    cout << "**********************************Update phase**********************************" << endl;
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
    keyserver.hardenPassword(b, a, id);
    cout << "Password Hardening Finished!" << endl;

    // Log in to the cloud server
    string cred_cs;
    client.pwdGen(b, cred_cs);
    cout << "The client ready to log in the cloud server!" << endl;

    // Cloud server authenticates the client
    string s_id;
    string r_id;
    cloudserver.authenInTake_CS(s_id, r_id, id, cred_cs);
    cout << "You have successfully logged in the cloud server!" << endl;

    string t;
    string k_1;
    string k_2;
    client.loginToKS_Take(t, k_1, k_2, s_id, r_id);
    cout << "The client ready to log in the key server!" << endl;

    string ct;
    string tag;
    keyserver.authenInTake_KS(ct, tag, t, id);
    cout << "You have successfully logged in the key server!" << endl;

    string mk;
    client.recover(mk, k_1, k_2, ct, tag);
    cout << "The key recovery is finished!" << endl;

    	CryptoPP::byte key[16];
	std::memcpy(key, mk.data(), 16);

	// Directories
	std::string cipherDir = "../File/TestMultiple/Cipher";
	std::string recoverDir = "../File/TestMultiple/Recover(Single)";

	char buf[16];
	sprintf(buf, "%03d", index); // 001, 002, 010, ...
	std::string filePrefix = "Test_" + std::string(buf);

	// fs::create_directories(recoverDir);

	// Ensure output directory exists
	// fs::create_directories(cipherDir);

	std::string cipherPath = cipherDir + "/" + filePrefix + "_cipher.dat";
	std::string ivPath = cipherDir + "/" + filePrefix + ".iv";
	std::string outputPath = recoverDir + "/" + filePrefix + "_recover.dat";

    // 检查文件是否存在
    if (!fs::exists(cipherPath))
    {
        std::cerr << "Cipher file not found: " << cipherPath << std::endl;
        return;
    }
    if (!fs::exists(ivPath))
    {
        std::cerr << "IV file not found: " << ivPath << std::endl;
        return;
    }

    // 读取 IV
    CryptoPP::byte iv[16 * 16];
    std::ifstream ivFile(ivPath, std::ios::binary);
    ivFile.read(reinterpret_cast<char *>(iv), sizeof(iv));
    ivFile.close();

    // 执行解密
    aes_EAX_FileDec(cipherPath, key, iv, outputPath);

    // CryptoPP::byte key[16];
    // std::memcpy(key, mk.data(), 16);
    std::string plainDir = "../File/Update/Origin";
    std::string cipherDir_upt = "../File/TestMultiple/Cipher(Update)";

    // 创建输出目录
    fs::create_directories(cipherDir_upt);

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

        std::string prefix = "Test_" + string(buf) + "_cipher";

        // 输出路径
        std::string outfilePath = cipherDir_upt + "/" + prefix + ".dat";
        std::string ivPath = cipherDir_upt + "/" + prefix + ".iv";

        // ============================
        // 生成随机 IV（16*16 字节）
        // ============================
        CryptoPP::byte iv[16 * 16];
        prng.GenerateBlock(iv, sizeof(iv));

        // 执行加密
        aes_EAX_FileEnc(infilePath.string(), key, iv, outfilePath);

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