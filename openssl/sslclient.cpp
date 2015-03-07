#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <csignal>

#include <iostream>
#include <string>
#include <map>
#include <utility>

#include <boost/lexical_cast.hpp>

#include "common.h"

using namespace std;

const unsigned long MAX_SEGMENTS = 100;
const unsigned long MIN_SEGMENT_SIZE = 1024 * 1024 * 5;
const unsigned long MAX_SEGMENT_SIZE = (1024 * 1024 * 10) - 255;

// Index -> (BufferSegmentStart, BufferSegmentLength)
typedef std::map<unsigned long, std::pair<unsigned long, unsigned long> > BufferSegmentList; 

bool createClientSocket(const string& hostname, int port, int& fd) {

    ::signal(SIGPIPE, SIG_IGN);

	struct hostent* host = gethostbyname(hostname.c_str());
	if (host == nullptr) {
		cout << getLogTimestamp("ERROR") << "Failed to get host by name [Hostname: " << hostname << ", Error: " << getSystemErrorMessage(errno)
			<< "], will not continue further." << endl;
		return false;
	}

	fd = socket(PF_INET, SOCK_STREAM, 0);

	struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = *(long*)(host->h_addr);
	if (connect(fd, (sockaddr*)&addr, sizeof(addr)) != 0) {
		close(fd);
		cout << getLogTimestamp("ERROR") << "Failed to connect to " << hostname << ":" << port << "[Error: " << getSystemErrorMessage(errno)
			<< "], will not continue further." << endl;
		return false;
	}

	return true;
}

SSL_CTX* initializeSSL() {
	SSL_CTX *sslContext;

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	const SSL_METHOD* sslMethod = SSLv23_client_method();
	sslContext = SSL_CTX_new(sslMethod);
	if (sslContext == NULL) {
		cout << getLogTimestamp("ERROR") << "Failed to create SSL Context: " << getSSLErrorMessage(ERR_get_error());
		return NULL;
	}
	return sslContext;
}

void displayServerCertificate(SSL* sslConnection) {
	X509* cert = SSL_get_peer_certificate(sslConnection);	
	if (!cert) {
		cout << getLogTimestamp("INFO") << "No peer certificates detected....";
		return;
	}

	char* peerCertSubject = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
	char* peerCertIssuerSubject = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
	cout << getLogTimestamp("INFO") << "SSL Details [Cipher: " << SSL_get_cipher(sslConnection) << ", Server certificate {Cert: " 
		<< peerCertSubject << ", Issuer: " << peerCertIssuerSubject << "} ]" << endl;

	::free(peerCertSubject);
	::free(peerCertIssuerSubject);
	::X509_free(cert);
}

bool generateRandomBuffer(char*& buffer, BufferSegmentList& bufferSegmentList, unsigned long maxSegments) {
	// Initialize random seed
	::srandom(time(nullptr));

	unsigned long bufferSize = 0;
	unsigned long segmentRange = MAX_SEGMENT_SIZE - MIN_SEGMENT_SIZE;
	for (unsigned long i = 0; i < maxSegments; ++i) {
		auto segmentOffsets = make_pair<long unsigned, long unsigned>(0, 0);
		segmentOffsets.first = bufferSize;
		segmentOffsets.second = MIN_SEGMENT_SIZE + (random() % segmentRange);

		// Make sure the address is aligned by 4 bytes
		bufferSize += ((segmentOffsets.second + sizeof(unsigned int)) >> 2) << 2;
		bufferSegmentList[i] = segmentOffsets;
		cout << getLogTimestamp("DEBUG") << "Generate data segment #" << i << " [base: " << segmentOffsets.first 
				<< ", size: " << segmentOffsets.second << ", end: " << bufferSize << "]" << endl;
	}

	cout << getLogTimestamp("DEBUG") << "Allocating buffer for random data segment [size: " << bufferSize << "]" << endl;
	buffer = new char[bufferSize];
	for (unsigned long i = 0; i < bufferSize; ++i) {
		buffer[i] = random() % 255;
	}

	return true;
}


int main(int argc, const char* argv[]) {
	if (argc != 3) {
		cout << "Usage: " << argv[0] << " <hostname> <portnum>" << endl;
		return 1;
	}


	SSL_CTX* sslContext = initializeSSL();
	if (!sslContext) {
		cout << getLogTimestamp("FATAL") << "Failed to iitialize SSL, will not continue further." << endl;
		return 2;
	}

	string hostname = argv[1];
	int fd, port = boost::lexical_cast<int>(argv[2]);
	if (!createClientSocket(hostname, port, fd)) {
		cout << getLogTimestamp("FATAL") << "Failed to create client connection to server, will not continue further" << endl;
		return 2;
	}

	BufferSegmentList bufferSegmentList;
	char* buffer = NULL;
	if (!generateRandomBuffer(buffer, bufferSegmentList, MAX_SEGMENTS)) {
		cout << getLogTimestamp("FATAL") << "Failed to generate random buffer for use, will not continue further" << endl;
		return 2;
	}

	SSL* sslConnection = SSL_new(sslContext);
	SSL_set_fd(sslConnection, fd);
	if (SSL_connect(sslConnection) <= 0) {
		cout << getLogTimestamp("ERROR") << "Failed to SSL Connect on the underlying socket [Error: " << getSSLErrorMessage(ERR_get_error())
			<< "], will not continue further." << endl;
	} else {   
		displayServerCertificate(sslConnection);

		unsigned long long totalBytesWritten = 0, totalBytesRead = 0;

		unsigned long totalDocuments = 100 * 1000 * 1000;
		unsigned long longBuffer = htonl(totalDocuments);
		SSL_write(sslConnection, &longBuffer, sizeof(longBuffer));
		totalBytesWritten += sizeof(longBuffer);

		for (unsigned long i = 0; i < totalDocuments; ++i) {
			//auto bufferSegment = bufferSegmentList[random() % MAX_SEGMENTS];
			auto bufferSegment = bufferSegmentList[i % MAX_SEGMENTS];
			longBuffer = htonl(bufferSegment.second);
			SSL_write(sslConnection, &longBuffer, sizeof(longBuffer));
			totalBytesWritten += sizeof(longBuffer);

			SSL_write(sslConnection, buffer + bufferSegment.first, bufferSegment.second);
			totalBytesWritten += bufferSegment.second;

			if (SSL_read(sslConnection, &longBuffer, sizeof(longBuffer)) <= 0) {
				cout << endl << getLogTimestamp("ERROR") << "Failed to read from SSL socket [Error: " << getSSLErrorMessage(ERR_get_error())
				<< "], will not continue further." << endl;
				break;
			}
			totalBytesRead += sizeof(longBuffer);

			if (!(i % 1000) && i > 0) {
				cout << endl << "Ack received for #" << i << " [SentBytes: " << bufferSegment.second << ", AckFor: " << ntohl(longBuffer) 
					<< ", Total {Read: " << totalBytesRead << ", Written: " << totalBytesWritten << "} ]" << endl;
			}

			cout << "." << flush;
		}

		cout << endl << getLogTimestamp("INFO") << "Total {Read: " << totalBytesRead << ", Written: " << totalBytesWritten << "} ]" << endl;

		SSL_shutdown(sslConnection);
		SSL_free(sslConnection);
	}
	close(fd);
	SSL_CTX_free(sslContext);

	EVP_cleanup(); // Should be last freeup call for the OpenSSL
	return 0;
}
