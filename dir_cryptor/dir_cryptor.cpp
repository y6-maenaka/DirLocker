#include "dir_cryptor.h"
#include "../w_aes/aes_manager.h"



DirCryptor::DirCryptor( std::string dirPath )
{
  _dirPath = dirPath;
}

DirCryptor::DirCryptor( std::string dirPath , openssl_wrapper::aes::W_AESKey_128* key ) : _key(key)
{
  _dirPath = dirPath;
  return;
}

void DirCryptor::claerLockedFile()
{
  unsigned int count = 0;
  for( const fs::directory_entry& entry : fs::recursive_directory_iterator(_dirPath) )
  {
	if( fs::is_regular_file(entry) && entry.path().extension() == LockedExtension ){
	  std::string entryPath = entry.path().string();
	  fs::remove(entry);
	  std::cout << entryPath << " - " << "\x1b[31m" << "delete" << "\x1b[39m" << "\n";
	  count++;
	}
  }

  std::cout << "\n\n" << "deleted :: " << count << " files" << "\n\n";
}

void DirCryptor::init()
{
  std::cout << fs::exists(_dirPath) << "\n";
  std::cout << fs::is_directory(_dirPath) << "\n";

  const auto rDirItr = fs::recursive_directory_iterator(_dirPath);
  for( auto itr : rDirItr )
  {
	std::cout << itr.path().string() << "\x1b[31m" << " - raw" << "\x1b[39m" << "\n";
  }

  _encryptFlag = true;
}



bool DirCryptor::encryptFile( const fs::directory_entry& entry )
{
  if( !(fs::is_regular_file(entry)) ) return false;

  size_t encryptedLength = 0;
  std::string lockedFilePath = entry.path().string() + LockedExtension;
  encryptedLength = openssl_wrapper::aes::W_AES128Manager::encryptStream( entry.path().string() , 0, 0, _key, lockedFilePath );
  
  return (encryptedLength != 0) ;
}

bool DirCryptor::decryptFile( const fs::directory_entry& entry )
{
  if( !(fs::is_regular_file(entry) )) return false;

  size_t decryptedLength;
  std::string unLockedFilePath = entry.path().parent_path().string() + "/" + entry.path().stem().string();

  decryptedLength = openssl_wrapper::aes::W_AES128Manager::decryptStream( entry.path().string() , 0 , 0 , _key, unLockedFilePath );

  return (decryptedLength != 0);
}


bool DirCryptor::startEncrypt()
{
  unsigned int count = 0;
  for( const fs::directory_entry& entry : fs::recursive_directory_iterator(_dirPath) )
  {
	if( this->encryptFile( entry ) )
	{
	  std::cout << entry.path().string() << " - " << "\x1b[32m" << "lock" << "\x1b[39m" << "\n";
	  fs::remove( entry );
	  count++;
	}
  }

  std::cout << "\n\n" << "locked :: " << count << " files" << "\n\n";
  return true;
}


bool DirCryptor::startDecrypt()
{
  unsigned int count = 0;
  for( const fs::directory_entry& entry : fs::recursive_directory_iterator(_dirPath) )
  {
	if( entry.path().extension() == LockedExtension )
	{
	  if( this->decryptFile( entry ) )
	  {
		std::cout << entry.path().string() << " - " << "\x1b[34m" << "unlock" << "\x1b[39m" << "\n";
		fs::remove( entry );
		count++;
	  }
	}
  }

  std::cout << "\n\n" << "unlocked :: " << count << " files" << "\n\n";
  return true;
}
