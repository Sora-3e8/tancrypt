#ifndef DUTILS_HPP
#define DUTILS_HPP

#include <initializer_list>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>

namespace dutils
{
  class dbuffer : public std::vector<unsigned char>
  {
      public:
        dbuffer() : std::vector<unsigned char>(){}
        dbuffer(int size) : std::vector<unsigned char>(size){}
        dbuffer(std::vector<unsigned char> vec) : std::vector<unsigned char>(vec){}
        dbuffer(std::string s_data) : std::vector<unsigned char>(s_data.begin(),s_data.end()){}
        dbuffer(std::initializer_list<unsigned char> list) : std::vector<unsigned char>(list){}
        std::string toStr()
        {
          std::string str(this->data(),this->data()+this->size());
          return str;
        }
  };

  static std::string hexStr(const std::vector<unsigned char> &data)
  {
    int counter = 0;
    std::stringstream hex_str;
    for(unsigned char val : data)
    {
     hex_str << std::hex << std::setw(2) << std::setfill('0') << (int) val << ((counter<data.size()-1) ? ":" :"");
     counter++;
    }

    return hex_str.str();
  }

}
#endif
