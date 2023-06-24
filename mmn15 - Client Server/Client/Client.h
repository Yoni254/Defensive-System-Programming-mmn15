#pragma once
#ifndef CLIENT_H
#define CLIENT_H

#include <string.h>
#include <vector>
#include <cstring>
#include <boost/asio.hpp>
#include <filesystem>
#include <cmath>

#include "SocketHandler.h"
#include "Utils.h"
#include "protocol.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "Base64Wrapper.h"

#define MAX_ADDRESS_LENGTH 20
#define MAX_PORT_LENGTH 8

using boost::asio::ip::tcp;


/*
Client code for mmn15 - Defensive System Programing
course number 20937

this is a simple server-client code for exchanging encrypted files based on users
client should have a file named transfer.info as follows:

line 1 - ip of the server
line 2 - client name
line 3 - file to send

@author yonatan tzukerman
@date 23/03/2023
*/
class Client {


private:
	SocketHandler* socketHandler;

	// TODO: see if this can be changed to a normal string
	char name[NAME_SIZE];
	char filePath[NAME_SIZE];
	std::string privKey;
	sClientID clientID;
	sPublicKey publicKey;
	sSymmetricKey aesKey;

	// internal error counter
	int errorCnt;

	// parse the transfer.info file used by client
	void parseTransferInfo(std::vector<std::string> args);
	// parse the me.info file used by client
	void parseMeInfo(std::vector<std::string> args);

	/* check if we have data from previous registration */
	bool isRegistered();

	// sending 1100 to try and register, gets 2100 if all good or 2101 if name already taken
	void registerUser();
	// sending 1101 to exchange keys, gets 2102 with AES key
	void exchangeEncryptionKeys();

	// user is alredy registered. sending 1102 and getting 2105 with AES key, or 2106 requesting to register again
	void loginUser();

	// after login or first registration, we get an ecrypted AES key from server.
	// this decrypts it using the private RSA key
	void processAESKey(sEncSymmKey encSymmKey, int len);

	// calls sendFile until success or 3 failed attempts
	void trySendingFile();

	// crc responses
	// crc was valid. send 1104 and receive 2104
	void validCRC();
	// crc was wrong, trying again. send 1105 
	void warningCRC();
	// crc was wrong, no more tries. send 1106 and receive 2104
	void failedCRC();

	// sending 1103 with encrypted file. gets 2103 with checksum or 2107 for error
	bool sendFile();


public:
	Client(std::string transferFile);
	~Client();

	/* main logic method. communicates with server and sends it the file in transfer.info */
	void connectToServer();
	
};



#endif
