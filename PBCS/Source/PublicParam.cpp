#include "PublicParam.h"

#include <iostream>
#include <sstream>
#include <fstream>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/eax.h>
#include <cryptopp/files.h>
#include <pbc/pbc.h>

using namespace std;
using namespace CryptoPP;

pairing_t pairing;
element_t g, h;

// System Initialization
void sysInitial()
{
    cout << "*********************************System Initialization********************************" << endl;
    // Set pbc param
    char param[1024];
    size_t count = fread(param, 1, 1024, stdin);
    if (!count)
        pbc_die("input error");

    // Initialize pairing
    pairing_init_set_buf(pairing, param, count);

    // Declare and initialize variables
    element_init_G1(h, pairing);
    element_init_G2(g, pairing);
    
    // Generate the variables
    element_random(g);

    cout << "System initialization finished!" << endl;
}


// Random Generation
Integer randomGeneration(const int &secureParam)
{
    AutoSeededRandomPool prng;
    SecByteBlock randomBlock(secureParam / 8);
    prng.GenerateBlock(randomBlock, randomBlock.size());

    Integer randomInt(randomBlock, randomBlock.size());

    if (randomInt.BitCount() < 128) {
        randomInt <<= (128 - randomInt.BitCount());
    }

    return randomInt;
}

string Integer_to_string(const Integer &integer)
{
    string str;
    stringstream ss;

    ss << hex << integer;
    ss >> str;
    transform(str.begin(), str.end(), str.begin(), ::toupper);
    str = str.substr(0, str.size() - 1);

    return str;
}

// Hash computation
string sha256Hash(string &str)
{
    string value; // To store the hash string
    SHA256 sha256;

    StringSource ss(
        str,
        true,
        new HashFilter(sha256, new HexEncoder(new CryptoPP::StringSink(value))));
    return value;
}

void writeToBin(ofstream& outFile, string str) {
    int strLength = str.length();
    outFile.write(reinterpret_cast<char *>(&strLength), sizeof(int));
    outFile.write(str.c_str(), strLength);
}

void readFromBin(ifstream& inFile, string& str) {
    int strLength;
    inFile.read(reinterpret_cast<char *>(&strLength), sizeof(int));
    char *str_char = new char[strLength + 1];
    inFile.read(str_char, strLength);
    str_char[strLength] = '\0';
    str = str_char;
}

Integer string_To_Integer(string &str)
{
    char *a = new char[200];
    int i = 0;

    for (; i < str.size(); ++i)
    {
        a[i] = str[i];
    }

    a[i++] = 'h';
    a[i] = '\0';

    Integer H(a);

    return H;
}

void KDF(string& key, string& psw, string& salt, CryptoPP::byte* derivedKey) {
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf; 
    pbkdf.DeriveKey(derivedKey, 16, 0, (CryptoPP::byte*)psw.data(), psw.size(), (CryptoPP::byte*)salt.data(), salt.size(), 10000);
    HexEncoder hex(new StringSink(key));
    hex.Put(derivedKey, 16);
    hex.MessageEnd();
}

void aes_CBC_Enc(const string &plain, const CryptoPP::byte *key, const CryptoPP::byte *iv, string &cipher)
{

    CBC_Mode<AES>::Encryption e;
    e.SetKeyWithIV(key, 16, iv);
    StringSource(plain, true,
                 new StreamTransformationFilter(e,
                                                new Base64Encoder(
                                                    new StringSink(cipher),
                                                    false // do not append a newline
                                                    )));

    // // Pretty print cipher
    // std::string encoded;
    // HexEncoder encoder(new StringSink(encoded));
    // encoder.Put((const CryptoPP::byte *)cipher.data(), cipher.size());
    // encoder.MessageEnd();

    // cout << "plaintext: " << plain << endl;
    // cout << "cipher text: " << encoded << endl;

    // // Pretty print iv
    // encoded.clear();
    // StringSource(iv, 16, true,
    //              new HexEncoder(
    //                  new StringSink(encoded)) // HexEncoder
    // );                                        // StringSource
    // cout << "iv: " << encoded << endl;

    // // Pretty print key
    // encoded.clear();
    // StringSource(key, 16, true,
    //              new HexEncoder(
    //                  new StringSink(encoded)) // HexEncoder
    // );                                        // StringSource
    // cout << "key: " << encoded << endl;
}

void aes_CBC_Dec(const string &cipher, const CryptoPP::byte *key, const CryptoPP::byte *iv, string &plain)
{
    // // Pretty print cipher
    // std::string encoded;
    // HexEncoder encoder(new StringSink(encoded));
    // encoder.Put((const CryptoPP::byte *)cipher.data(), cipher.size());
    // encoder.MessageEnd();
    // std::cout << "cipher text: " << encoded << std::endl;

    // // Pretty print iv
    // encoded.clear();
    // StringSource(iv, 16, true,
    //              new HexEncoder(
    //                  new StringSink(encoded)) // HexEncoder
    // );                                        // StringSource
    // cout << "iv: " << encoded << endl;

    // // Pretty print key
    // encoded.clear();
    // StringSource(key, 16, true,
    //              new HexEncoder(
    //                  new StringSink(encoded)) // HexEncoder
    // );                                        // StringSource
    // cout << "key: " << encoded << endl;

    CBC_Mode<AES>::Decryption decryption;
    decryption.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
    StringSource(cipher, true,
                 new Base64Decoder(
                     new StreamTransformationFilter(decryption,
                                                    new StringSink(plain))));
}

void aes_EAX_FileEnc(const std::string &infilename,
                     const CryptoPP::byte *key,
                     const CryptoPP::byte *iv,
                     const std::string &outfilename)
{
    std::ifstream input(infilename, std::ios::binary);
    if (!input.is_open()) {
        std::cerr << "Error opening file for reading: " << infilename << std::endl;
        return;
    }

    // --- Use FileSink directly with filename ---
    EAX<AES>::Encryption enc;
    enc.SetKeyWithIV(key, 16, iv, 16);  // 16-byte IV

    AuthenticatedEncryptionFilter ef(enc, new FileSink(outfilename.c_str()));

    const size_t bufferSize = 8192;
    CryptoPP::byte buffer[bufferSize];

    while (input) {
        input.read(reinterpret_cast<char*>(buffer), bufferSize);
        std::streamsize bytesRead = input.gcount();
        if (bytesRead > 0)
            ef.Put(buffer, static_cast<size_t>(bytesRead));
    }

    ef.MessageEnd(); // finalize and write tag
    input.close();

    std::cout << "Encrypted: " << infilename << " -> " << outfilename << std::endl;
}


// AES-EAX file decryption function
void aes_EAX_FileDec(const std::string &infilename,
                     const CryptoPP::byte *key,
                     const CryptoPP::byte *iv,
                     const std::string &outfilename)
{
    // Open input file
    ifstream input(infilename, ios::binary);
    if (!input.is_open()) {
        cerr << "Error opening file for reading: " << infilename << endl;
        return;
    }

    // Initialize AES/EAX decryption object
    EAX<AES>::Decryption dec;
    dec.SetKeyWithIV(key, 16, iv, 16);  // 16-byte IV

    // Create an authenticated decryption filter and attach FileSink
    AuthenticatedDecryptionFilter df(dec, new FileSink(outfilename.c_str()));

    const size_t bufferSize = 8192;    // Read buffer size
    CryptoPP::byte buffer[bufferSize];

    // Read ciphertext in chunks and feed into decryption filter
    while (input) {
        input.read(reinterpret_cast<char*>(buffer), bufferSize);
        std::streamsize bytesRead = input.gcount();
        if (bytesRead > 0)
            df.Put(buffer, static_cast<size_t>(bytesRead));
    }

    // Finalize decryption and verify authentication tag
    df.MessageEnd();
    input.close();

    // Check authentication result
    if (!df.GetLastResult()) {
        cerr << "❌ Authentication failed for file: " << infilename << endl;
        return;
    }

    // Print success message
    cout << "Decrypted: " << infilename << " -> " << outfilename << endl;
}