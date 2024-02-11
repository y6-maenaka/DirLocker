#include "user.h"

#include "../w_aes/aes_manager.h"

#include "../dir_cryptor/dir_cryptor.h"


int main( int argc , char* argv[] )
{
  std::cout << "(User) : HelloWorld." << "\n";

  std::string pubPemPath = argv[1];
  // std::string targetDirPath = argv[2];
  std::string targetDirPath = "../__TARGET__";

  std::string pass = {'0','1','2','3','4','5','6','7','8','9','0','1','2','3','4','5'};
  openssl_wrapper::aes::W_AESKey_128 key( pass );




  DirCryptor cryptor{ targetDirPath , &key  };
  //cryptor.init();

  // cryptor.startEncrypt();
  cryptor.startDecrypt();
  // cryptor.claerLockedFile();
}


