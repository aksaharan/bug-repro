#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <csignal>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <iostream>
#include <string>

#include "common.h"

using namespace std;

bool createServerSocket(int port, int& fd) {   
    // set SIGPIPE to IGNORE for the sockets
    ::signal(SIGPIPE, SIG_IGN);

    fd = socket(PF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr;
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(fd, (sockaddr*)(&addr), sizeof(addr)) != 0) {
		cout << getLogTimestamp("ERROR") << "Failed to bind on the port [Port: " << port << ", Error: " << getSystemErrorMessage(errno)
			<< "], will not continue further." << endl;
        return false;
    }

    if (listen(fd, 10) != 0) {
		cout << getLogTimestamp("ERROR") << "Failed to configure the listening port [Port: " << port << ", Error: " << getSystemErrorMessage(errno)
			<< "], will not continue further." << endl;
        return false;
    }
    return true;
}

SSL_CTX* initializeSSL(const string& certFile, const string& cipherConfig) {

	SSL_library_init();
	SSL_load_error_strings();

	/* ERR_load_crypto_strings(); */
	// OPENSSL_config(NULL);

    SSL_CTX* sslContext = SSL_CTX_new(SSLv23_method());
    if (!sslContext) {
    	cout << getLogTimestamp("ERROR") << "Failed to create context for the SSL: " << getSSLErrorMessage(ERR_get_error()) << endl;
    	return NULL;
    }

	// SSL_OP_ALL - Activate all bug workaround options, to support buggy client SSL's.
	// SSL_OP_NO_SSLv2 - Disable SSL v2 support
	// SSL_OP_NO_SSLv3 - Disable SSL v3 support
	SSL_CTX_set_options(sslContext, SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);

	// HIGH - Enable strong ciphers
	// !EXPORT - Disable export ciphers (40/56 bit) 
	// !aNULL - Disable anonymous auth ciphers
	// @STRENGTH - Sort ciphers based on strength 
	string contextCiphers = "HIGH:!EXPORT:!aNULL@STRENGTH";
	//string contextCiphers = "HIGH:!EXPORT:!AESGCM:!aNULL@STRENGTH";
	if (!cipherConfig.empty()) {
		contextCiphers = cipherConfig;
	}
	cout << getLogTimestamp("INFO") << "Using cipherContext = " << contextCiphers << endl;

	if (!SSL_CTX_set_cipher_list(sslContext, contextCiphers.c_str())) {
    	cout << getLogTimestamp("ERROR") << "Failed to set the context cipher list for SSL: " << getSSLErrorMessage(ERR_get_error()) << endl;
    	return NULL;
	}

	// Disabling the AESGCM - should work fine without any issues
	//SSL_CTX_set_cipher_list(sslContext, "HIGH:!EXPORT:!AESGCM:!aNULL@STRENGTH");

	// If renegotiation is needed, don't return from recv() or send() until it's successful.
	// Note: this is for blocking sockets only.
	SSL_CTX_set_mode(sslContext, SSL_MODE_AUTO_RETRY);

	// Disable session caching (see SERVER-10261)
	SSL_CTX_set_session_cache_mode(sslContext, SSL_SESS_CACHE_OFF);

	// Now try loading the server certificate for the key
	if (SSL_CTX_use_certificate_chain_file(sslContext, certFile.c_str() ) != 1) {
		cout << getLogTimestamp("ERROR") << "Failed to read certificate file: " << certFile << " - " << getSSLErrorMessage(ERR_get_error()) << endl;
		SSL_CTX_free(sslContext);
		return NULL;
	}   

	if (SSL_CTX_use_PrivateKey_file(sslContext, certFile.c_str(), SSL_FILETYPE_PEM ) != 1) {
		cout << getLogTimestamp("ERROR") << "Failed to read PEM key file: " << certFile << " - " << getSSLErrorMessage(ERR_get_error()) << endl;
		SSL_CTX_free(sslContext);
		return NULL;
	}

	// Verify that the certificate and the key go together.
	if (SSL_CTX_check_private_key(sslContext) != 1) {
		cout << getLogTimestamp("ERROR") << "SSL certificate validation: " << getSSLErrorMessage(ERR_get_error()) << endl;
		SSL_CTX_free(sslContext);
		return NULL;
	}

	return sslContext;
}

bool processClient(SSL_CTX* sslContext, int clientFd) {   
	char docBuffer[4096 * 1024];
    int fd, bytesRead;
	bool retValue = true;
	unsigned long docCount = 0;
	unsigned long longBuffer = 0;
	unsigned long long totalBytesRead = 0, totalBytesWritten = 0;

	// Check for error conditions on buffer failure
	SSL* ssl = SSL_new(sslContext);
	SSL_set_fd(ssl, clientFd);

	if (SSL_accept(ssl) <= 0) {
		cout << getLogTimestamp("ERROR") << "Failed to SSL Accept the underlying socket [Error: " << getSSLErrorMessage(ERR_get_error()) << "]" << endl;
		goto cleanup;
	}

	bytesRead = 0;
	bytesRead = SSL_read(ssl, &longBuffer, sizeof(longBuffer));
	if (bytesRead <= 0) {
		cout << getLogTimestamp("ERROR") << "Failed to read data from SSL socket [Error: " << getSSLErrorMessage(ERR_get_error()) << "]" << endl;
		retValue = false;
		goto cleanup;
	}
	totalBytesRead += sizeof(longBuffer);

	docCount = ntohl(longBuffer);
	if (docCount <= 0) {
		cout << getLogTimestamp("ERROR") << "Invalid doc count received from the client: " << docCount << endl;
		goto cleanup;
	}

	cout << getLogTimestamp("DEBUG") << "Total Documents to be copied: " << docCount << endl;
	for (unsigned long i = 0; i < docCount; ++i) {
		// Read the document length
		bytesRead = 0;
		bytesRead = SSL_read(ssl, &longBuffer, sizeof(longBuffer));
		if (bytesRead <= 0) {
			cout << getLogTimestamp("ERROR") << "Failed to read the data from cosket [bytesRead: " << bytesRead
				<< ", Error: " << getSSLErrorMessage(ERR_get_error()) << "], will not continue further." << endl;
			retValue = false;
			goto cleanup;
		}
		totalBytesRead += sizeof(longBuffer);

		unsigned long docLength = ntohl(longBuffer);
		if (docLength <= 0) {
			cout << getLogTimestamp("ERROR") << "Encountered <= 0 document length [docLength: " << docLength << "], not continuing on this connection." << endl;
			goto cleanup;
		}

		if (!(i % 1000) && i > 0) {
			cout << getLogTimestamp("DEBUG") << "Processing #" << i + 1 << " [ReceivedBytes: " << totalBytesRead << ", Sent: " 
				<< totalBytesWritten << "]" << endl;
		}

		unsigned long bytesRemaining = docLength;
		while (bytesRemaining > 0) {
			docBuffer[0] = 0;
			bytesRead = SSL_read(ssl, docBuffer, min(bytesRemaining, sizeof(docBuffer)));
			if (bytesRead <= 0) {
				cout << getLogTimestamp("ERROR") << "Failed to read the entire document from the client connection [Doc#: " << i
					<< ", Expected: " << docLength << ", Remaining: " << bytesRemaining << ", Read: " << bytesRead 
					<< ", TotalBytes {Read: " << totalBytesRead << ", Written: " << totalBytesWritten << "}, error: " 
					<< getSSLErrorMessage(ERR_get_error()) << "], will not continue further." << endl;
				goto cleanup;
			} else if ((unsigned long)bytesRead <= bytesRemaining) {
				totalBytesRead += bytesRead;
				bytesRemaining -= bytesRead;
			} else {
				cout << getLogTimestamp("WARNING") << "More bytes read than requested [Requested: " << bytesRemaining << ", Read: " << bytesRead << "]" << endl;
				totalBytesRead += bytesRead;
				bytesRemaining = 0;
			}
		}

		unsigned long longBuffer = htonl(i);
		SSL_write(ssl, &longBuffer, sizeof(longBuffer));
		totalBytesWritten += sizeof(longBuffer);
	}

cleanup:
	fd = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(fd);

	return retValue;
}

int main(int argc, const char* argv[]) {
	if (argc < 3) {
		cout << "Usage: " << argv[0] << " <portnum> <pemfile> [cipherString]" << endl;
		exit(0);
	}

	string cipherConfig = "";
	if (argc > 3) {
		cipherConfig = argv[3];
	}

	SSL_CTX* sslContext = initializeSSL(argv[2], cipherConfig);
	if (!sslContext) {
		cout << getLogTimestamp("FATAL") << "Failed to create SSL context for the server, will not continue further..." << endl;
	}

	int serverFd = 0;
	if (!createServerSocket(atoi(argv[1]), serverFd)) {
		cout << getLogTimestamp("FATAL") << "Failed to create server socket, will not continue further." << endl;
		goto cleanup;
	}

	while (1) {
		struct sockaddr_in addr;
		socklen_t len = sizeof(addr);

		int clientFd = accept(serverFd, (sockaddr*)&addr, &len);
		cout << getLogTimestamp("INFO") << "Connection Accepted: " << inet_ntoa(addr.sin_addr) << ":" << ntohs(addr.sin_port) << endl;
		processClient(sslContext, clientFd);
	}

cleanup:
	close(serverFd);
	SSL_CTX_free(sslContext);
}
