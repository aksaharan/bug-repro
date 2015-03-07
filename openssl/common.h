#ifndef _common_h_
#define _common_h_

#include <string>

std::string getSSLErrorMessage(long errorCode);
std::string getSystemErrorMessage(int errorCode);

std::string getLogTimestamp(const std::string& type);
std::string getBytesString(unsigned long long& totalBytes);

#endif
