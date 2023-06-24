#include "protocol.h"
#include "Utils.h"

char* generateHeader(std::string clientId, int code, int size) {
	// first check that all data is valid
	if (clientId.size() > CLIENT_ID_SIZE) {
		errorHandler("generating header", "invalid client ID size");
		return nullptr;
	}
	
}