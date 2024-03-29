#ifndef F71D9744_2F6F_4A69_A671_C924DAC6E5CE
#define F71D9744_2F6F_4A69_A671_C924DAC6E5CE

#include <iostream>
#include <memory>

#include "openssl/evp.h"
#include "openssl/rsa.h"
 #include "openssl/engine.h"



namespace openssl_wrapper
{
namespace evp_pkey
{
  class W_EVP_PKEY;
}


namespace rsa
{





class W_RSAManager
{
public:
  static size_t encrypt( evp_pkey::W_EVP_PKEY* wpkey , const unsigned char* plainBin , const size_t plainBinLength ,std::shared_ptr<unsigned char> *cipherBin );
  static size_t sign( evp_pkey::W_EVP_PKEY* wpkey , const unsigned char* plainBin , const size_t plainBinLength ,std::shared_ptr<unsigned char> *signBin );

  static size_t decrypt( evp_pkey::W_EVP_PKEY* wpkey , const unsigned char* cipherBin , const size_t cipherBinLength ,std::shared_ptr<unsigned char> *plainBin );
  static bool verify( evp_pkey::W_EVP_PKEY* wpkey , const unsigned char* signBin , const size_t signBinLength , const unsigned char* msgBin /* ハッシュ前の本体バイナリ */ , const size_t msgBinLength );

  // void decrypt( evp_pkey::W_EVP_PKEY );
};






};
};




#endif 
