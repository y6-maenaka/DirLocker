cmake_minimum_required( VERSION 3.2 )

project( DIR_LOCKER CXX )

find_package( PkgConfig REQUIRED )
find_package( OPENSSL REQUIRED )

if( OPENSSL_FOUND )
  include_directories( ${OPENSSL_INCLUDE_DIR} )
  message( STATUS "Using OpenSSL ${OPENSSL_VERSION}" )
  message( STATUS "Openssl IncludeDir :: ${OPENSSL_INCLUDE_DIR}" )
else()
  message("(Failure) Found OPENSSL")
endif()



add_library( CRYPTO_MANAGER SHARED
		  ./w_sha/sha.cpp
		  ./w_evp_pkey/evp_pkey.cpp
		  ./w_aes/aes_manager.cpp
		  ./w_rsa/rsa_manager.cpp

)
target_link_libraries( CRYPTO_MANAGER PUBLIC
						${OPENSSL_LIBRARIES}	
)

add_library( DIR_CRYPTOR SHARED
			./dir_cryptor/dir_cryptor.cpp
)
target_link_libraries( DIR_CRYPTOR PUBLIC
					  CRYPTO_MANAGER

)


if( BUILD_HOST )
add_executable( host ./host/host.cpp )
target_link_libraries( host PRIVATE 
						CRYPTO_MANAGER
)
endif()

if( BUILD_USER )
add_executable( user ./user/user.cpp )
target_link_libraries( user PRIVATE
					  CRYPTO_MANAGER
					  DIR_CRYPTOR

)
endif()



# add_definitions( -std=c++20 -w )
add_definitions( -std=c++20 )

