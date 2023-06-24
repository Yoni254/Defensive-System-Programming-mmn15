#pragma once
#ifndef SOCKETHANDLER_H
#define SOCKETHANDLER_H

#include <string>
#include <iostream>
#include <boost/asio.hpp>

#include "Utils.h"

using boost::asio::ip::tcp;


constexpr size_t PACKET_SIZE = 1024;

class SocketHandler {
private:
	std::string address;
	std::string port;

	boost::asio::io_context* io_context;
	tcp::socket* socket;
	tcp::resolver* resolver;

	// flag to check connection with server
	bool connected;
	// flag if need to switch endians
	bool bigEndian;

	

public:
	SocketHandler(std::string address, std::string port);
	~SocketHandler();

	bool connect();

	/*
	write data to server when size is size of data
	data is sent in fixed size packets
	*/
	bool writeToServer(const uint8_t* const data, int size) const;

	/*
	recieve data from server when size is size of data
	data is sent in fixed size packets
	*/
	bool receiveFromServer(uint8_t* const data, int size) const;
	void close();

	/* a mix of the write and recieve functions. also hanles connecting and closing the socket */
	bool exchangeWithServer(const uint8_t* const request, int requestSize, uint8_t* const response, int responseSize);

};

#endif
