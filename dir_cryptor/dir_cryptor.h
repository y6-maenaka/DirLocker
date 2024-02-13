#ifndef B2CF82F1_9A01_4CEC_8CAD_8DADD41374A5
#define B2CF82F1_9A01_4CEC_8CAD_8DADD41374A5


#include <iostream>
#include <string>
#include <vector>
#include <filesystem>



namespace openssl_wrapper
{
namespace aes
{
  class W_AESKey_128;
};
};


namespace fs = std::filesystem;
const std::string LockedExtension = ".locked";


class DirCryptor
{

private:
  // fs::path _dirPath;
  std::vector< fs::path > _dirPaths;
  openssl_wrapper::aes::W_AESKey_128* _key;
  bool _encryptFlag = false;


protected:
  void cleanUp();
  bool encryptFile( const fs::directory_entry& entry );
  bool decryptFile( const fs::directory_entry& entry );

public:
  DirCryptor( const std::vector< const std::string> dirPaths );
  DirCryptor( const std::vector< const std::string> dirPaths , openssl_wrapper::aes::W_AESKey_128* key );

  void init();
  bool startEncrypt();
  bool startDecrypt();

  void claerLockedFile();
};



#endif 


