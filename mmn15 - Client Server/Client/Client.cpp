#include "Client.h"


/*
Basic builder for Client class
Gets string transferFile - path for the transfer.info file
then parses the info from it
*/
Client::Client(std::string transferFile) {
	errorCnt = 0;
	std::vector<std::string> args = parseTransfer(transferFile);
	Client::parseTransferInfo(args);
}

/*
destructor just to makes sure the socket is closed
*/
Client::~Client() {
	Client::socketHandler->close();
}

/* check if we have data from previous registration */
bool Client::isRegistered() {
	return doesFileExist("me.info");
}


void Client::connectToServer() {
	/*
	registerUser() and loginUser() follow the following logic:
	is user registered ?
	
	no - > register - > exchange keys - > process AES key
	yes - > login (ok from server?)
	yes - > login (yes) - > process AES key
	no - > exchange keys - > process AES key
	*/
	if (!isRegistered()) {
		std::cout << "New account, registering." << std::endl;
		Client::registerUser();
	}
	else {
		std::cout << "Already registered, logging in." << std::endl;
		std::vector<std::string> args = parseMe("me.info");
		Client::parseMeInfo(args);
		loginUser();
	}

	/*
	now that we have the encryption key, we can try to send the file
	*/
	trySendingFile();
}

/*
CODE = 1100

user registration.
this sends to the server a 1100 request to register with user name as the payload

gets 2100 if all good
or 2101 if name is taken
*/
void Client::registerUser() {
	sRegistrationRequest request;
	sRegistrationResponse response;

	// load data into request
	request.header.payloadSize = sizeof(request.payload);
	strcpy_s(reinterpret_cast<char*>(request.payload.clientName.name), NAME_SIZE, Client::name);

	if (!socketHandler->exchangeWithServer(reinterpret_cast<const uint8_t*>(&request), sizeof(request),
		reinterpret_cast<uint8_t*>(&response), sizeof(response))) 
		errorHandler("user registration", "error while communicating with server");
	

	// after sending the information, we treat the 3 different results
	std::cout << "Succesfully sent code: " << request.header.code << std::endl;
	std::cout << "Got response from server with code : " << response.header.code << std::endl;

	if (response.header.code == 2100) { 
		errorCnt = 0;
		// all good. copy client UUID from result and keep going
		Client::clientID = response.payload.clientID;
		exchangeEncryptionKeys();
	}
	else if (response.header.code == 2101) 
		errorHandler("server response to registering", "error code (2101). looks like this name is already taken");

	else if (response.header.code == 2107) {
		errorCnt += 1;
		
		if (errorCnt == 3)	// if we reached 3 failed attempts - abort. 
			errorHandler("server response to registering", "server responded with 3 error messages");
		else
			registerUser();
	}
	else { // general breaking statment. we should never get here due to the logic of the server
		std::cout << "not sure how we got here... code from server is wrong" << std::endl;
		exit(0);
	}
		
	
}


/*
CODE = 1101

exchange keys with server.
this generates a pair of RSA keys.
priv key is stored in me.info and public key is sent to server

gets 2102 as a result with encrypted AES key

*/
void Client::exchangeEncryptionKeys() {
	sPublicKeyRequest request;
	sPublicKeyResponse response;

	request.header.payloadSize = sizeof(request.payload);
	request.header.clientID = Client::clientID;
	Base64Wrapper base64;
	

	// for some reason the RSAPrivateWrapper caused me some weird problems but they stopped after a rewrite
	// if any errors still happen, running it again should solve it. it had to do with cryptopp and not something I could effect

	std::string publicKey;
	std::string privKey;
	try {
		RSAPrivateWrapper rsaPrivate;

		// create private and public keys. also making sure the public key size is good for the protocol
		publicKey = rsaPrivate.getPublicKey();
		privKey = base64.encode(rsaPrivate.getPrivateKey());
		if (publicKey.size() != PUBLIC_KEY_SIZE)
			errorHandler("getting encryption key", "public key size is invalid");
	}
	catch (...) {
		errorHandler("creating rsa wrapper", "unknown issue when trying to create keys");
		return;
	}

	// creating me file
	std::stringstream fileData;
	fileData << Client::name << std::endl;
	fileData << toHexStr(Client::clientID.uuid, CLIENT_ID_SIZE) << std::endl;
	fileData << privKey;
	createFile("me.info", fileData.str());
	std::cout << "created me.info file!" << std::endl;

	// load payload data - client name and public key
	strcpy_s(reinterpret_cast<char*>(request.payload.clientName.name), NAME_SIZE, Client::name);
	memcpy(request.payload.publicKey.publicKey, publicKey.c_str(), sizeof(request.payload.publicKey.publicKey));


	if (!socketHandler->exchangeWithServer(reinterpret_cast<const uint8_t*>(&request), sizeof(request),
		reinterpret_cast<uint8_t*>(&response), sizeof(response))) 
		errorHandler("exchanging keys", "error while communicating with server");
	

	// after sending the information, we treat the 2 different results
	std::cout << "Succesfully sent code: " << request.header.code << std::endl;
	std::cout << "Got response from server with code : " << response.header.code << std::endl;

	// 1: we got result 2102. meaning all is good and payload is user id + AES key
	if (response.header.code == 2102) {
		errorCnt = 0;
		// double check that the client IDs match
		if (toHexStr(Client::clientID.uuid, CLIENT_ID_SIZE) != toHexStr(response.payload.clientID.uuid, CLIENT_ID_SIZE)) 
			errorHandler("server response to key exchange attempt", "client ids don't match with result from server.");
		
		int len = response.header.payloadSize - sizeof(response.payload.clientID);
		processAESKey(response.payload.encSymmKey, len);
	}
	else if (response.header.code == 2107) {
		errorCnt += 1;

		if (errorCnt == 3)	// if we reached 3 failed attempts - abort. 
			errorHandler("server response to exchanging keys", "server responded with 3 error messages");
		else
			exchangeEncryptionKeys();
	}
	else { // general breaking statment. we should never get here due to the logic of the server
		std::cout << "not sure how we got here... code from server is wrong" << std::endl;
		exit(0);
	}
}

/*
CODE = 1102

try to login to server 
sends just the username and client id in header

gets 2105 if login attempt is good. payload is the encrypted AES key
gets 2106 if needs to register again. as we're allready getting a user id we can just call 1101

*/
void Client::loginUser() {
	sLoginRequest request; // 1102
	sLoginResponse response;


	// load header data
	request.header.payloadSize = sizeof(request.payload);
	request.header.clientID = Client::clientID;

	// load payload data - client name
	strcpy_s(reinterpret_cast<char*>(request.payload.clientName.name), NAME_SIZE, Client::name);

	if (!socketHandler->exchangeWithServer(reinterpret_cast<const uint8_t*>(&request), sizeof(request),
		reinterpret_cast<uint8_t*>(&response), sizeof(response))) 
		errorHandler("login attempt", "error while communicating with server");
	
	
	// after sending the information, we treat the different results
	std::cout << "Succesfully sent code: " << request.header.code << std::endl;
	std::cout << "Got response from server with code : " << response.header.code << std::endl;
	// now after sending the information two things can happen

	
	if (response.header.code == 2105) {
		// 1: we got result 2105. meaning all is good and payload is user id + AES key
		errorCnt = 0;
		if (toHexStr(Client::clientID.uuid, CLIENT_ID_SIZE) != toHexStr(response.payload.clientID.uuid, CLIENT_ID_SIZE))
			errorHandler("server response to login attempt", "client ids don't match with result from server.");

		int len = response.header.payloadSize - sizeof(response.payload.clientID);
		processAESKey(response.payload.encSymmKey, len);
	}
	// 2: we get 2101 or 2107 which is some sort of an error
	else if (response.header.code == 2106) {
		errorCnt = 0;
		std::cout << "error code (2106) when trying to login. trying to register again" << std::endl;
		std::cout << "User ID from server: " << toHexStr(response.payload.clientID.uuid, CLIENT_ID_SIZE) << std::endl;;
		Client::clientID = response.payload.clientID;
		exchangeEncryptionKeys();
	}	
	else if (response.header.code == 2107) {
		errorCnt += 1;

		if (errorCnt == 3)	// if we reached 3 failed attempts - abort. 
			errorHandler("server response to login attempt", "server responded with 3 error messages");
		else
			loginUser();
	}
	else { // general breaking statment. we should never get here due to the logic of the server
		std::cout << "not sure how we got here... code from server is wrong" << std::endl;
		exit(0);
	}
}

/*
gets the encrypted AES symetric key and decrypts it using the private key in me.info
*/
void Client::processAESKey(sEncSymmKey encSymmKey, int len) {
	// decrypt the AES key based on private RSA key
	std::cout << "Decrypting session key... " << std::endl;

	if (!doesFileExist("me.info"))
		errorHandler("AES key proccessing", "e.info file is missing. this should not happen");

	// read the me.info file
	// it's not all in one line just so it'll be more readable and easy to work with for the base64Wrapper
	std::string line;
	std::string decodedPrivKey;
	std::ifstream meInfo("me.info");

	Base64Wrapper base64;

	// the first 2 lines aren't interesting
	std::getline(meInfo, line);
	std::getline(meInfo, line);

	while (std::getline(meInfo, line)) 
		decodedPrivKey.append(base64.decode(line));
	meInfo.close();

	if (decodedPrivKey.empty()) 
		errorHandler("reading me.info key", "private key is missing");

	try {
		RSAPrivateWrapper rsaPrivate(decodedPrivKey);
		std::string key = rsaPrivate.decrypt(encSymmKey.encSymmetricKey, len);
		
		std::string base64Key = base64.encode(key);
		std::cout << base64Key << std::endl;
		std::string keyStr = base64.decode(base64Key);
		const char* keyChar = keyStr.c_str();
		if (strlen(keyChar) != SYMM_KEY_SIZE)
			errorHandler("Me.Info parsing", "user id length doesn't match the required length in protocol");
		memcpy(Client::aesKey.symmetricKey, keyChar, SYMM_KEY_SIZE);
	}
	catch (...) {
		errorHandler("creating rsa decoder", "unknown issue when trying to decode");
		return;
	}
}

/*
CODE = 1104

CRC from server matches our CRC
meaning the file passed succsesfully

sending 1104 to notify the server it passed the test
recieve 2104 for confirmation 
*/
void Client::validCRC() {
	std::cout << "CRC Confirmed! exiting the program :)" << std::endl;
	sValidCRCRequest request;
	sGenericResponse response;

	request.header.payloadSize = NAME_SIZE;
	request.header.clientID = Client::clientID;
	strcpy_s(reinterpret_cast<char*>(request.payload.fileName.name), NAME_SIZE, Client::filePath);


	if (!socketHandler->exchangeWithServer(reinterpret_cast<const uint8_t*>(&request), sizeof(request),
		reinterpret_cast<uint8_t*>(&response), sizeof(response))) 
		errorHandler("login attempt", "error while communicating with server");


	std::cout << "Succesfully sent code: " << request.header.code << std::endl;
	std::cout << "Got response from server with code : " << response.header.code << std::endl;
	// now after sending the information two things can happen

	if (response.header.code == 2107) {
		errorCnt += 1;

		if (errorCnt == 3)	// if we reached 3 failed attempts - abort. 
			errorHandler("server response to valid CRC", "server responded with 3 error messages");
		else
			validCRC();
	}
	else {
		errorCnt = 0;
		std::cout << "It worked ^-^" << std::endl;
		exit(0);
	}
	
}

/*
CODE = 1105

CRC from server doesn not match our CRC
sending 1105 to notify the server that we'll send the file again
*/
void Client::warningCRC() {
	std::cout << "CRC warning" << std::endl;
	sWarningCRCRequest request;

	request.header.payloadSize = NAME_SIZE;
	request.header.clientID = Client::clientID;
	strcpy_s(reinterpret_cast<char*>(request.payload.fileName.name), NAME_SIZE, Client::filePath);

	// connect and write manually to server
	if (!Client::socketHandler->connect()) 
		errorHandler("CRC warning", "couldn't connect to server");
	

	if (!Client::socketHandler->writeToServer(reinterpret_cast<const uint8_t*>(&request), sizeof(request))) {
		Client::socketHandler->close();
		errorHandler("CRC warning", "error while writing to server");
	}
	Client::socketHandler->close();
}

/*
CODE = 1106

CRC from server doesn not match our CRC
if we got here that means we won't try again.

sending 1106 to notify the server
getting 2104 for confirmation
*/
void Client::failedCRC() {
	std::cout << "CRC failed" << std::endl;
	sErrorCRCRequest request;
	sGenericResponse response;

	request.header.payloadSize = NAME_SIZE;
	request.header.clientID = Client::clientID;
	strcpy_s(reinterpret_cast<char*>(request.payload.fileName.name), NAME_SIZE, Client::filePath);

	if (!socketHandler->exchangeWithServer(reinterpret_cast<const uint8_t*>(&request), sizeof(request),
		reinterpret_cast<uint8_t*>(&response), sizeof(response))) {
		errorHandler("failed CRC", "error while exchanging with server");
	}
	
	std::cout << "Succesfully sent code: " << request.header.code << std::endl;
	std::cout << "Got response from server with code : " << response.header.code << std::endl;

	if (response.header.code == 2107) {
		errorCnt += 1;

		if (errorCnt == 3)	// if we reached 3 failed attempts - abort. 
			errorHandler("server response to failed CRC", "server responded with 3 error messages");
		else
			failedCRC();
	}
	else 
		errorCnt = 0;
	
}

/*
trying to send the file 
sendFile() returned true if passed CRC check
*/
void Client::trySendingFile() {
	
	if (sendFile()) { // first attempt
		validCRC();
	}
	warningCRC();
	if (sendFile()) { // second attempt
		validCRC();
	}
	warningCRC();
	if (sendFile()) { // third attempt
		validCRC();
	}
	failedCRC();
	std::cout << "Server couldn't verify file CRC! exiting program" << std::endl;
	exit(1);
}


/*
CODE = 1103

trying to send an encrypted file to server

getting 2103 with checksum in it's payload
checks it matches our checksum and if so, returns true
*/
bool Client::sendFile() {
	sFileSendRequest request;
	sCRCResponse response;

	request.header.clientID = Client::clientID;
	strcpy_s(reinterpret_cast<char*>(request.payload.fileName.name), NAME_SIZE, Client::filePath);

	// if file size is bigger, we need to send in batches
	std::ifstream file(Client::filePath, std::ios::binary);
	if (!file.is_open()) 
		errorHandler("sending file", "couldn't open specified file");
	
	// disable white space ignoring and get file size
	file >> std::noskipws;
	file.seekg(0, std::ios::end);
	std::streampos fileSize = file.tellg();
	file.seekg(0, std::ios::beg);

	// some magic calculation to get sizes and things:

	// ignoring the header and file name + size, we want to find out how much to read from the file every time 
	int sizeToRead = PACKET_SIZE - HEADER_SIZE - NAME_SIZE - 4;
	sizeToRead = ((sizeToRead / CryptoPP::AES::BLOCKSIZE) - 1) * CryptoPP::AES::BLOCKSIZE; // -1 because of message end

	// this calculates the size of the final file
	/*
	first we figure out just how many packets we'll have to send based on the packet size while leaving space for the final block
	after that the size of of the first package and the last package is calculated based on their size + padding ((celling(X/BLOCK) + 1) * BLOCK)
	then add everything together...
	*/
	if ((int)fileSize > sizeToRead) {
		int numOfParts = (((int)fileSize - sizeToRead) / (PACKET_SIZE - CryptoPP::AES::BLOCKSIZE)) + 2;
		int sizeOfPart = PACKET_SIZE;
		int sizeOfFirstPart = ((sizeToRead / CryptoPP::AES::BLOCKSIZE) + 1) * CryptoPP::AES::BLOCKSIZE;
		int sizeOfLastPart = (((int)fileSize - sizeToRead - (numOfParts - 2) * (PACKET_SIZE - CryptoPP::AES::BLOCKSIZE)));
		sizeOfLastPart = ((sizeOfLastPart / CryptoPP::AES::BLOCKSIZE) + 1) * CryptoPP::AES::BLOCKSIZE;
		int totalSize = (numOfParts - 2) * sizeOfPart + sizeOfLastPart + sizeOfFirstPart;

		request.payload.contentSize = totalSize;
	}
	else 
		request.payload.contentSize = (((int)fileSize / CryptoPP::AES::BLOCKSIZE) + 1) * CryptoPP::AES::BLOCKSIZE;
	
	
	char* data = new char[ENC_BATCH_SIZE];
	Base64Wrapper base64;

	try {
		if (!socketHandler->connect())
			errorHandler("connecting to server", "couldn't connect when sending file");
		AESWrapper aesWrapper(Client::aesKey.symmetricKey, sizeof(Client::aesKey.symmetricKey));
		bool sendHeader = true;

		size_t bytesLeft = request.payload.contentSize;
		while (file)
		{
			// first time we send with the header
			if (sendHeader) {
				file.read(data, sizeToRead);
				size_t count = file.gcount();
				bytesLeft -= count;

				if (!count)
					break;

				std::string encryptedBytes = aesWrapper.encrypt(data, count);
				memcpy(request.payload.msgContent.file, encryptedBytes.c_str(), encryptedBytes.size());
				request.header.payloadSize = 4 + NAME_SIZE + encryptedBytes.size();

				if (!socketHandler->writeToServer(reinterpret_cast<const uint8_t*>(&request), request.header.payloadSize + HEADER_SIZE))
					throw;
				sendHeader = false;
			}
			// next time we just send the file in chunks based on the packet size
			else {
				size_t bytesToSend = MIN(bytesLeft, PACKET_SIZE - CryptoPP::AES::BLOCKSIZE);
				file.read(data, bytesToSend);
				size_t count = file.gcount();
				bytesLeft -= count;

				if (!count)
					break;

				std::string encryptedBytes = aesWrapper.encrypt(data, count);

				if (!socketHandler->writeToServer(reinterpret_cast<const uint8_t*>(encryptedBytes.c_str()), encryptedBytes.size()))
					throw;
			}
		}
	}
	catch (...) {
		socketHandler->close();
		file.close();
		errorHandler("file encryption", "Exception while encrypting file");
	}
	file.close();

	// calculate checksum
	uint32_t cksum = checksum(filePath);

	// recieve info from server
	if (!socketHandler->receiveFromServer(reinterpret_cast<uint8_t*>(&response), sizeof(response))) 
		errorHandler("recieving checksum from server", "unknown");
	socketHandler->close();

	std::cout << "Succesfully sent code: " << request.header.code << std::endl;
	std::cout << "Got response from server with code : " << response.header.code << std::endl;


	if (response.header.code == 2107) {
		errorCnt += 1;

		if (errorCnt == 3)	// if we reached 3 failed attempts - abort. 
			errorHandler("server response to file exchange", "you probably already have a file by this name");
		else
			sendFile();
	}
	else {
		errorCnt = 0;
		return (response.payload.checkSum == cksum);
	}
}


void Client::parseTransferInfo(std::vector<std::string> args) {
	// TODO: validate file content. sadly I ran out of time for that

	// First line - address and port
	std::string serverInfo = args.at(0);
	//std::cout << "trying to connect to: " << serverInfo << std::endl;

	std::string address = serverInfo.substr(0, serverInfo.find_last_of(":"));
	std::string port = serverInfo.substr(serverInfo.find_last_of(":") + 1, serverInfo.length());

	Client::socketHandler = new SocketHandler(address, port);

	// Second line - client name
	std::string clientName = args.at(1);
	strncpy_s(Client::name, clientName.c_str(), NAME_SIZE);

	// Third line - file to send
	std::string filePath = args.at(2);
	strncpy_s(Client::filePath, filePath.c_str(), NAME_SIZE);
}

void Client::parseMeInfo(std::vector<std::string> args) {
	// TODO: validate file content.  sadly I ran out of time for that too

	// first line - client name. make sure it's the same as transfer.info
	std::string clientName = args.at(0);
	if (strcmp(Client::name, clientName.c_str()) != 0) {
		errorHandler("Parsing me.info", "Transfer.info and Me.info files are of different users!");
	}

	// second line - user id in ASCII. convert to bytes and copy into client id
	std::string clientIdStr = args.at(1);
	std::string line = fromHexStr(clientIdStr);
	const char* clientIdChar = line.c_str();
	if (strlen(clientIdChar) != CLIENT_ID_SIZE)
		errorHandler("Me.Info parsing", "user id length doesn't match the required length in protocol");
	memcpy(Client::clientID.uuid, clientIdChar, CLIENT_ID_SIZE);

	// Third line - private key. no need for it right now 
}