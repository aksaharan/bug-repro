#include <openssl/err.h>
#include <string.h>
#include <sstream>
#include <chrono>
#include <ctime>
#include <iomanip>

#include "common.h"

using namespace std;

string getSSLErrorMessage(long errorCode) {
	static const size_t ErrorMsgLen = 256;

	char errorMsg[ErrorMsgLen];
	ERR_error_string_n(errorCode, errorMsg, ErrorMsgLen);
	return errorMsg;
}

string getSystemErrorMessage(int errorCode) {
	// Not thread-safe 
	static char errorString[1024];
	errorString[0] = '\0';
	strerror_r(errorCode, errorString, sizeof(errorString));
	return errorString;
}

string getLogTimestamp(const string& type) {
	stringstream ss;

	// Chrono is broken in libstdc++
	//time_t tt = chrono::system_clock::to_time_t(chrono::system_clock::now());
	time_t tt = ::time(NULL);
	struct tm tt_local = {};
	localtime_r(&tt, &tt_local);

	ss << "[" << tt_local.tm_year + 1900 << "-" << setw(2) << setfill('0') << tt_local.tm_mon << "-" << tt_local.tm_mday
		<< "T" << tt_local.tm_hour << ":" << tt_local.tm_min << ":" << tt_local.tm_sec << "] " << type << " ";
	return ss.str();
}
