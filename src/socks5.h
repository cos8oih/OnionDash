#ifndef _socks5_h
#define _socks5_h

#include "trampoline.h"
#include <string>
#include <vector>

typedef enum socks5_error
{
	S5_ERR_SUCCESS = 0, //No errors.
	S5_ERR_WINSOCK = 1, //Winsock failed to initialize.
	S5_ERR_CONNECT = 2, //The connection with the Tor proxy failed.
	S5_ERR_IOCTLSO = 3, //Failed to change the socket mode to non-blocking.
	S5_ERR_SNDFAIL = 4, //The client failed to send a packet.
	S5_ERR_INVRESP = 5, //The server sent an invalid response.
	S5_ERR_ISOCKET = 6, //Failed to create a socket.
	S5_ERR_PORTNUM = 7  //Invalid port number.
} ErrorCode;

typedef enum socks5_conntype
{
	TCP = 1,
	UDP = 3
};

typedef enum socks5_reqtype
{
	TOR_CONNECT = 0,
	HANDSHAKE = 1,
	REQ_HEADER = 2,
	SEND_PACKET = 3,
	LOGIN = 4
} RequestType;

typedef enum socks5_reqmethod
{
	GET = 0,
	POST = 1
} RequestMethod;

typedef enum socks5_authmethod
{
	NONE = 0,
	GSSAPI = 1,
	USRNAME_PWD = 2
};

ErrorCode socks5_connect_with_TOR(SOCKET * sock, int port);
ErrorCode socks5_clientsgreet(SOCKET sock);
ErrorCode socks5_request(SOCKET sock, const std::string& domain_name, int port);


#endif
