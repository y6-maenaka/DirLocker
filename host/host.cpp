#include "host.h"

#include "../w_evp_pkey/evp_pkey.h"
#include "../w_base64/base64.h"
#include "../w_rsa/rsa_manager.h"


int main( int argc , char* argv[] )
{
  std::cout << "(Host) : HelloWorld." << "\n";

  std::string modeStr = argv[1];

 auto modeItr = mode.find(modeStr);
 if( modeItr == mode.end() ) return -1;
 int modeIndex = modeItr->second;

  switch(modeIndex)
  {
	case 1:
	  {
		std::cout << "新たにユーザ用公開鍵を生成します" << "\n";
		std::string pemPass = argv[2];
		std::shared_ptr<openssl_wrapper::evp_pkey::W_EVP_PKEY> pkey = openssl_wrapper::evp_pkey::w_rsa_pkey( 2048 );

		std::time_t ct = std::time(0);
		int unixTime = static_cast<int>(ct);
		std::string newPriPemPath = "./private_key_" + std::to_string(unixTime) + ".pem";
		std::string newPubPemPath = "./public_key_" + std::to_string(unixTime) + ".pem";

		pkey->savePub( newPubPemPath );
		pkey->savePri( newPriPemPath , pemPass );
  
		std::cout << "公開鍵の生成が完了しました" << "\n";
		break;
	  }

	case 2:
	  {
		std::string privatePemPass = argv[2];
		std::string encodedCommonKey = argv[3];

		std::cout << "ユーザ用共通鍵を復号します" << "\n";
		std::vector<unsigned char> decodedCommonKey;
		decodedCommonKey = openssl_wrapper::base64::W_Base64::decode( reinterpret_cast<const unsigned char*>(encodedCommonKey.c_str()) , encodedCommonKey.size() );

		openssl_wrapper::evp_pkey::W_EVP_PKEY pkey{};
		pkey.loadPri( privatePemPath ,privatePemPass ); // 鍵のロード

		std::shared_ptr<unsigned char> decryptedCommonKey; size_t decryptedCommonKeyLength = 0;
		decryptedCommonKeyLength = openssl_wrapper::rsa::W_RSAManager::decrypt(
			&pkey,
			std::shared_ptr<unsigned char>( decodedCommonKey.data(), [](unsigned char*) {}).get(),
			decodedCommonKey.size(),
			&decryptedCommonKey
		);

		std::cout << "復号キー :: ";
		for( int i=0; i<decryptedCommonKeyLength; i++ ){
			printf("%c", (decryptedCommonKey.get()[i]) );
		} std::cout << "\n";

		break;
	  }
	default:
	  {
		std::cout << "Hello" << "\n";
	  }
  }
}
