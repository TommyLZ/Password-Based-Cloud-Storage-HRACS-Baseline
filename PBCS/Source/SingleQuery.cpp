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

void SingleQuery(string& psw, string& id, int index)
{
    cout << "**********************************SingleQuery phase**********************************" << endl;
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

	// CryptoPP::byte iv[16 * 16];
	// AutoSeededRandomPool prng;
	// prng.GenerateBlock(iv, 16 * 16);
	
	// client.dataEncryption(mk, iv);
	// cout << "The applicaiton data is encrypted and outsourced successfully!" << endl;
	// client.dataDecryption(mk, iv);
	// cout << "The applicaiton data is recovered successfully!" << endl;

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
	fs::create_directories(cipherDir);

	// RNG for IV
	AutoSeededRandomPool prng;

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

	std::cout << "Decrypted: " << cipherPath << "  →  " << outputPath << std::endl;
}