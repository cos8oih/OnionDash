#include "socks5.h"

ErrorCode socks5_connect_with_TOR(SOCKET * sock, int port)
{
	unsigned long iMode = 1;
	SOCKADDR_IN addr;
	//Init values
	if (sock == nullptr)
	{
		return S5_ERR_ISOCKET;
	}
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(port);
	addr.sin_family = AF_INET;
	*sock = socket(AF_INET, SOCK_STREAM, NULL);
	if (*sock == INVALID_SOCKET)
	{
		return S5_ERR_ISOCKET;
	}
	//Connect
	if (connect(*sock, (SOCKADDR*)(&addr), sizeof(addr)) != 0)
	{
		closesocket(*sock);
		return S5_ERR_CONNECT;
	}
	//Set socket to non-blocking mode
	if (ioctlsocket(*sock, FIONBIO, &iMode) == SOCKET_ERROR)
	{
		return S5_ERR_IOCTLSO;
	}
	return S5_ERR_SUCCESS;
}

ErrorCode socks5_clientsgreet(SOCKET sock)
{
	fd_set fds = { 1,{ sock } };
	int iResult = 0;
	char response[2];
	//Wait till can send greet
	do { select(0, 0, &fds, 0, 0); } while (!FD_ISSET(sock, &fds));
	//Client's greet
	if (sendTrampoline(sock, new char[3]{ 0x05, 0x01, 0x00 }, 3, 0) == SOCKET_ERROR)
	{
		return S5_ERR_SNDFAIL;
	}
	//Wait for greeting to be sent
	do { select(0, &fds, 0, 0, 0); } while (!FD_ISSET(sock, &fds));
	//Server's response
	do
	{
		iResult = recv(sock, response, 2, 0);
		if (iResult >= 0) break;
	} while (iResult > 0);
	//Check if the response is valid
	if (response[0] != 0x05 || response[1] != 0x00)
	{
		return S5_ERR_INVRESP;
	}
	return S5_ERR_SUCCESS;
}

ErrorCode socks5_request(SOCKET sock, const std::string& domain_name, int port)
{
	fd_set fds = { 1,{ sock } };
	int iResult = 0;
	char response[36];
	//Wait till can send request
	do { select(0, 0, &fds, 0, 0); } while (!FD_ISSET(sock, &fds));
	//Build packet

	//Client's request
	//byte 1: socks version
	//byte 2: stream type
	//byte 3: reserved
	//byte 4: domain name length w/o null terminator
	//byte array[byte 4]: domain
	//last byte: port
	if (sendTrampoline(sock, new char[20]{ 0x05, 0x1, 0x0, 0x3, 0xD, 0x62, 0x6f, 0x6f, 0x6d, 0x6c, 0x69, 0x6e, 0x67, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x0, 0x50 }, 20, 0) == SOCKET_ERROR)
	{
		return S5_ERR_SNDFAIL;
	}
	//Wait for request to be sent
	do { select(0, &fds, 0, 0, 0); } while (!FD_ISSET(sock, &fds));
	//Server's response
	do
	{
		iResult = recv(sock, response, 36, 0);
		if (iResult >= 0) break;
	} while (iResult > 0);
	//Check if the response is valid
	if (response[0] != 0x05 || response[1] != 0x00)
	{
		return S5_ERR_INVRESP;
	}
	return S5_ERR_SUCCESS;
}
