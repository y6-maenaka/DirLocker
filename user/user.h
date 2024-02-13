#ifndef D173D6B9_EA76_4B81_B3D3_78C7691ED6E0
#define D173D6B9_EA76_4B81_B3D3_78C7691ED6E0





#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <random>
#include <filesystem>

const std::map< std::string , const int > mode = {
  { "lock" , 1 },
  { "unlock" ,2 },
  { "clear", 3 }
};

const std::string targetDirPath_1 = "../__TARGET__";
const std::string targetDirPath_2 = "../__SUB_TARGET__";



const std::string publicPemPath = "../public.pem";
const bool debug = true;


#endif // 
