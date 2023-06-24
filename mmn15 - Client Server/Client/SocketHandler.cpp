#include "SocketHandler.h"


SocketHandler::SocketHandler(std::string address, std::string port) : socket(nullptr)  {
	/*
	Handler class for boost socket
	connects and communicates with a server at a given address:port
	*/
	
	// test if we need to change from big to little endian
	short int word = 0x0001;
	char* b = (char*)&word;
	bigEndian = b[0] == 1 ? false : true;

	SocketHandler::address = address;
	SocketHandler::port = port;
}

SocketHandler::~SocketHandler() {
	SocketHandler::close();
}

bool SocketHandler::connect() {
	/*
	tries to connect with the server
	*/
	try {
		SocketHandler::close();
		io_context = new boost::asio::io_context;
		socket = new tcp::socket(*SocketHandler::io_context);
		resolver = new tcp::resolver(*SocketHandler::io_context);
		boost::asio::connect(*socket, resolver->resolve(SocketHandler::address, SocketHandler::port));
		socket->non_blocking(false);
		SocketHandler::connected = true;
	}
	catch (...) {
		std::cout << "Error while trying to connect to server" << std::endl;
		SocketHandler::connected = false;
	}
	return SocketHandler::connected;

}


bool SocketHandler::writeToServer(const uint8_t* const data, int size) const {
	
	if (!SocketHandler::connected || socket == nullptr) {
		std::cout << "no connection while writing to server" << std::endl;
		return false;
	}

	try {
		size_t bytesLeft = size;
		const uint8_t* ptr = data;

		// if there's any more data to send, go inside the loop
		while (bytesLeft > 0) {
			uint8_t tempBuffer[PACKET_SIZE] = { 0 };

			// always send at most PACKET_SIZE packets
			size_t bytesToSend = MIN(bytesLeft, PACKET_SIZE);

			memcpy(tempBuffer, ptr, bytesToSend);
			if (bigEndian)
				swapEndian(tempBuffer, bytesToSend);

			// communicate with server
			size_t bytesWritten = write(*socket, boost::asio::buffer(tempBuffer, PACKET_SIZE));
			if (bytesWritten == 0)
				return false;
			
			ptr += bytesWritten;
			// update bytes left 
			bytesLeft = (bytesLeft < bytesWritten) ? 0 : bytesLeft - bytesWritten;
		}
		return true;
	}
	catch (...) {
		std::cout << "Error while writing to server" << std::endl;
		return false;
	}
}


bool SocketHandler::receiveFromServer(uint8_t* const data, int size) const {
	
	bool alreadyReadFlag = false;

	try {
		size_t bytesLeft = size;
		uint8_t* ptr = data;

		// loop to read multiple packet_size packets
		while (bytesLeft > 0) {
			uint8_t tempBuffer[PACKET_SIZE] = { 0 };
			boost::system::error_code errorCode;
			size_t bytesRead = read(*socket, boost::asio::buffer(tempBuffer, PACKET_SIZE), errorCode);
			
			// error cases and endian swap if needed
			if (bytesRead == 0)
				return alreadyReadFlag;
			if (bigEndian)
				swapEndian(tempBuffer, bytesRead);

			// copy what we read into data
			size_t bytesToCopy = MIN(bytesRead, bytesLeft);
			memcpy(ptr, tempBuffer, bytesToCopy);
			ptr += bytesToCopy;
			bytesLeft = (bytesLeft < bytesToCopy) ? 0 : bytesLeft - bytesToCopy;
			alreadyReadFlag = true;
			
		}
		return true;
	}
	catch (...) {
		std::cout << "Error while reading from server" << std::endl;
		return false;
	}
}

void SocketHandler::close() {
	// try to close the connection and free the data
	try {
		if (socket != nullptr)
			SocketHandler::socket->close();
	}
	catch (...) {}

	delete io_context;
	delete resolver;
	delete socket;
	io_context = nullptr;
	resolver = nullptr;
	socket = nullptr;
	connected = false;
}

bool SocketHandler::exchangeWithServer(const uint8_t* const request, int requestSize, uint8_t* const response, int responseSize) {
	
	if (!connect())
		return false;

	if (!writeToServer(request, requestSize)) {
		close();
		std::cout << "Error while writing to server!" << std::endl;
		return false;
	}

	if (!receiveFromServer(response, responseSize)) {
		close();
		std::cout << "Error while reading from server" << std::endl;
		return false;
	}

	close();
	return true;

}