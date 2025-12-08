#include "Take.h"
#include "Client.h"
#include "KeyServer.h"
#include "CloudServer.h"
#include "PublicParam.h"

#include <iostream>
#include <fstream>
#include <cryptopp/osrng.h>
#include <filesystem>
using namespace std;

extern pairing_t pairing;

namespace fs = std::filesystem;

void Upload(string& psw, string& id)
{
    cout << "**********************************Upload phase**********************************" << endl;
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
	// std::string plainDir = "../File/TestSingleSize/Origin";
	// std::string cipherDir = "../File/TestSingleSize/Cipher";
	// std::string recoverDir = "../File/TestSingleSize/Recover";

	std::string plainDir = "../File/TestMultiple/Origin";
	std::string cipherDir = "../File/TestMultiple/Cipher";

	// fs::create_directories(recoverDir);

	// Ensure output directory exists
	fs::create_directories(cipherDir);

	// RNG for IV
	AutoSeededRandomPool prng;

	// Iterate all files in plainDir
	for (const auto &entry : fs::directory_iterator(plainDir))
	{
		if (!entry.is_regular_file())
			continue;

		fs::path infilePath = entry.path();
		std::string stem = infilePath.stem().string(); // filename without extension
		std::string outfilePath = cipherDir + "/" + stem + "_cipher.dat";
		std::string ivPath = cipherDir + "/" + stem + ".iv"; // IV file

		// Generate random IV: 16*16 bytes
		CryptoPP::byte iv[16 * 16];
		prng.GenerateBlock(iv, sizeof(iv));

		// Call encryption function
		aes_EAX_FileEnc(infilePath.string(), key, iv, outfilePath);

		// Save IV to file
		std::ofstream ivFile(ivPath, std::ios::binary);
		ivFile.write(reinterpret_cast<const char *>(iv), sizeof(iv));
		ivFile.close();

		std::cout << "Encrypted: " << infilePath.string() << " -> " << outfilePath
				  << ", IV saved at " << ivPath << std::endl;
	}
	std::cout << "All files encrypted successfully!" << std::endl;
}