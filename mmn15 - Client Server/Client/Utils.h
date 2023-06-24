#pragma once
#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <boost/algorithm/hex.hpp>

#define MIN(A, B) ((A > B) ? B : A)
#define MAX(A, B) ((A > B) ? A : B)


/* Error Handler. prints error message and exists the code */
void errorHandler(const std::string location, const std::string message);


// file section

/* 
Parse transfer.info file. including checks for line numbers 
first line - ip:port of server
second line - client name
third line - document path 
*/
std::vector<std::string> parseTransfer(std::string filePath);

/*
Parse me.info file. including checks for line numbers
first line - client name
second line - client id (hex)
third line (and onwards) - private RSA key
*/
std::vector<std::string> parseMe(std::string filePath);

/* simple check if fie exists. (returns true if yes) */
bool doesFileExist(std::string filePath);

/* create file in filePath and write data to it */
bool createFile(std::string filePath, std::string data);


// data converters

/* swaps from big endian to little endian (and other way around) */
void swapEndian(uint8_t* const buffer, size_t size);

/* given an array of number, returns a string of those number in hex form */
std::string toHexStr(const uint8_t* data, int len);

/* given a string of numbers in hex form, returns a string of bytes */
std::string fromHexStr(std::string& data);


// checksum
/* implementation of the linux cksum function in c++ (mainly the CRC part) */
uint32_t checksum(std::string filePath);


#endif