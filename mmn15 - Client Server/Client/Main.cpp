#include <iostream>
#include "Utils.h"
#include "Client.h"


int main() {
	Client* cl = new Client("transfer.info");
	cl->connectToServer();
}