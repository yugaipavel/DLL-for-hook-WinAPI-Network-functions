#define _CRT_SECURE_NO_WARNINGS
#include <regex>
#include <ctime>
#include <sstream>
#include <fstream>
#include <iostream>
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <detours.h>
#include <time.h>
#include <tchar.h>
#include "leveldb/db.h"

#include <wininet.h>

#undef BOOLAPI
#undef SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
#undef SECURITY_FLAG_IGNORE_CERT_CN_INVALID

#define URL_COMPONENTS URL_COMPONENTS_ANOTHER
#define URL_COMPONENTSA URL_COMPONENTSA_ANOTHER
#define URL_COMPONENTSW URL_COMPONENTSW_ANOTHER
#define LPURL_COMPONENTS LPURL_COMPONENTS_ANOTHER
#define LPURL_COMPONENTSA LPURL_COMPONENTS_ANOTHER
#define LPURL_COMPONENTSW LPURL_COMPONENTS_ANOTHER
#define INTERNET_SCHEME INTERNET_SCHEME_ANOTHER
#define LPINTERNET_SCHEME LPINTERNET_SCHEME_ANOTHER
#define HTTP_VERSION_INFO HTTP_VERSION_INFO_ANOTHER
#define LPHTTP_VERSION_INFO LPHTTP_VERSION_INFO_ANOTHER

#include <winhttp.h>

#undef URL_COMPONENTS
#undef URL_COMPONENTSA
#undef URL_COMPONENTSW
#undef LPURL_COMPONENTS
#undef LPURL_COMPONENTSA
#undef LPURL_COMPONENTSW
#undef INTERNET_SCHEME
#undef LPINTERNET_SCHEME
#undef HTTP_VERSION_INFO
#undef LPHTTP_VERSION_INFO

#pragma comment (lib, "winhttp.lib")
#pragma comment (lib, "wininet.lib")
#pragma comment (lib, "ws2_32.lib")

using namespace std;
#define _CRT_SECURE_NO_WARNINGS

string get_time();
void log(const char *msg);
void send_message(string msg, int choice);
char* get_current_process();
char *wchar_to_char(const wchar_t* pwchar);
BOOL check_domain(char* CheckDomain, const char* FunctionName);
BOOL check_signatures(string data);

HINTERNET(WINAPI* pWinHttpConnect)
(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved)
= WinHttpConnect;

BOOL(WINAPI* pWinHttpReadData)
(IN HINTERNET hRequest, LPVOID lpBuffer, IN DWORD dwNumberOfBytesToRead, OUT LPDWORD lpdwNumberOfBytesRead)
= WinHttpReadData;

BOOL(WINAPI* pWinHttpSendRequest)
(IN HINTERNET hRequest, LPCWSTR lpszHeaders, IN DWORD dwHeadersLength, LPVOID lpOptional, IN DWORD dwOptionalLength, IN DWORD dwTotalLength, IN DWORD_PTR dwContext)
= WinHttpSendRequest;

BOOL(WINAPI* pHttpSendRequestA)
(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength)
= HttpSendRequestA;

HINTERNET(WSAAPI* pHttpOpenRequestA)
(HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext)
= HttpOpenRequestA;

BOOL(WINAPI* pInternetReadFile)
(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead)
= InternetReadFile;

HINTERNET(WINAPI* pInternetConnectA)
(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext)
= InternetConnectA;

HINTERNET(WINAPI* pInternetOpenUrlA)
(HINTERNET hInternet, LPCSTR lpszUrl, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext)
= InternetOpenUrlA;

HINTERNET(WINAPI* pInternetOpenA)
(LPCSTR lpszAgent, DWORD  dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags)
= InternetOpenA;

SOCKET(WSAAPI* pWSAAccept)
(SOCKET s, sockaddr* addr, LPINT addrlen, LPCONDITIONPROC lpfnCondition, DWORD_PTR dwCallbackData)
= WSAAccept;

int (WSAAPI* pWSAConnect)
(SOCKET s, const sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS)
= WSAConnect;

BOOL(WSAAPI* pWSAConnectByNameA)
(SOCKET s, LPCSTR nodename, LPCSTR servicename, LPDWORD LocalAddressLength, LPSOCKADDR LocalAddress, LPDWORD RemoteAddressLength, LPSOCKADDR RemoteAddress, const timeval* timeout, LPWSAOVERLAPPED Reserved)
= WSAConnectByNameA;

int(WSAAPI* pWSARecv)
(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
= WSARecv;

int(WSAAPI* pWSASend)
(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
= WSASend;

int(WSAAPI* pconnect)(SOCKET s, const sockaddr* name, int namelen)
= connect;

int(WSAAPI* psend)(SOCKET s, const char* buf, int len, int flags)
= send;

int(WSAAPI* precv)(SOCKET s, char* buf, int len, int flags)
= recv;

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

HINTERNET WINAPI  MyWinHttpConnect(
	HINTERNET     hSession,
	LPCWSTR       pswzServerName,
	INTERNET_PORT nServerPort,
	DWORD         dwReserved
)
{
	log("Checking WinHttpConnect...");

	BOOL res;
	res = check_domain(wchar_to_char(pswzServerName), "WinHttpConnect");
	if (res == TRUE)
	{
		send_message("Block WinHttpConnect call", 1);
		log("Block WinHttpConnect call");
		send_message(get_current_process(), 4);
		return NULL;
	}
	else
	{
		return pWinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);
	}
}

BOOL WINAPI MyWinHttpReadData(
	IN HINTERNET hRequest,
	LPVOID       lpBuffer,
	IN DWORD     dwNumberOfBytesToRead,
	OUT LPDWORD  lpdwNumberOfBytesRead)
{
	log("Checking WinHttpReadData...");

	BOOL res;
	string data = (char*)lpBuffer;
	res = check_signatures(data);
	if (res == FALSE)
	{
		log("Call WinHttpReadData");
		return pWinHttpReadData(hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
	}
	else
	{
		send_message("Block WinHttpReadData call", 1);
		log("Block WinHttpReadData call");
		send_message(get_current_process(), 4);
		return NULL;
	}
}

BOOL WINAPI MyWinHttpSendRequest(
	IN HINTERNET hRequest,
	LPCWSTR      lpszHeaders,
	IN DWORD     dwHeadersLength,
	LPVOID       lpOptional,
	IN DWORD     dwOptionalLength,
	IN DWORD     dwTotalLength,
	IN DWORD_PTR dwContext)
{
	log("Call WinHttpSendRequest");
	return pWinHttpSendRequest(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext);
}

BOOL WINAPI MyHttpSendRequestA(
	HINTERNET hRequest,
	LPCSTR    lpszHeaders,
	DWORD     dwHeadersLength,
	LPVOID    lpOptional,
	DWORD     dwOptionalLength)
{
	log("Call HttpSendRequestA");
	return pHttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
}

HINTERNET WSAAPI MyHttpOpenRequestA(
	HINTERNET hConnect,
	LPCSTR    lpszVerb,
	LPCSTR    lpszObjectName,
	LPCSTR    lpszVersion,
	LPCSTR    lpszReferrer,
	LPCSTR* lplpszAcceptTypes,
	DWORD     dwFlags,
	DWORD_PTR dwContext
)
{
	log("Checking HttpOpenRequestA...");

	BOOL res;
	res = check_domain((char*)lpszObjectName, "HttpOpenRequestA");
	if (res == TRUE)
	{
		send_message("Block HttpOpenRequestA call", 1);
		log("Block HttpOpenRequestA call");
		send_message(get_current_process(), 4);
		return NULL;
	}
	else
	{
		log("Call HttpOpenRequestA");
		return pHttpOpenRequestA(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);
	}
}

BOOL WINAPI MyInternetReadFile(
	HINTERNET hFile,
	LPVOID    lpBuffer,
	DWORD     dwNumberOfBytesToRead,
	LPDWORD   lpdwNumberOfBytesRead)
{
	log("Checking InternetReadFile...");

	BOOL res;
	string data = (char*)lpBuffer;
	res = check_signatures(data);
	if (res == FALSE)
	{
		log("Call InternetReadFile");
		return pInternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
	}
	else
	{
		send_message("Block InternetReadFile call", 1);
		log("Block InternetReadFile call");
		send_message(get_current_process(), 4);
		return NULL;
	}
}

HINTERNET WINAPI MyInternetConnectA(
	HINTERNET     hInternet,
	LPCSTR        lpszServerName,
	INTERNET_PORT nServerPort,
	LPCSTR        lpszUserName,
	LPCSTR        lpszPassword,
	DWORD         dwService,
	DWORD         dwFlags,
	DWORD_PTR     dwContext
)
{
	log("Checking InternetConnectA...");

	BOOL res;
	res = check_domain((char*)lpszServerName, "InternetConnectA");
	if (res == TRUE)
	{
		send_message("Block InternetConnectA call", 1);
		log("Block InternetConnectA call");
		send_message(get_current_process(), 4);
		return NULL;
	}
	else
	{
		log("Call InternetConnectA");
		return pInternetConnectA(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
	}	
}

HINTERNET WINAPI MyInternetOpenA(
	LPCSTR lpszAgent,
	DWORD  dwAccessType,
	LPCSTR lpszProxy,
	LPCSTR lpszProxyBypass,
	DWORD  dwFlags
)
{
	log("Call InternetOpenA");
	return pInternetOpenA(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
}

HINTERNET WINAPI MyInternetOpenUrlA(
	HINTERNET hInternet,
	LPCSTR    lpszUrl,
	LPCSTR    lpszHeaders,
	DWORD     dwHeadersLength,
	DWORD     dwFlags,
	DWORD_PTR dwContext
)
{
	log("Checking InternetOpenUrlA...");

	BOOL res;
	res = check_domain((char*)lpszUrl, "InternetOpenUrlA");
	if (res == TRUE)
	{
		send_message("Block InternetOpenUrlA call", 1);
		log("Block InternetOpenUrlA call");
		send_message(get_current_process(), 4);
		return NULL;
	}
	else
	{
		log("Call InternetOpenUrlA");
		return pInternetOpenUrlA(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
	}
}

SOCKET WSAAPI MyWSAAccept(
	SOCKET          s,
	sockaddr* addr,
	LPINT           addrlen,
	LPCONDITIONPROC lpfnCondition,
	DWORD_PTR       dwCallbackData
)
{
	log("Call WSAAccept");
	return pWSAAccept(s, addr, addrlen, lpfnCondition, dwCallbackData);
}

int WSAAPI MyWSAConnect(
	SOCKET         s,
	const sockaddr* name,
	int            namelen,
	LPWSABUF       lpCallerData,
	LPWSABUF       lpCalleeData,
	LPQOS          lpSQOS,
	LPQOS          lpGQOS
)
{
	log("Call WSAConnect");
	return pWSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
}

BOOL WSAAPI MyWSAConnectByNameA(
	SOCKET          s,
	LPCSTR          nodename,
	LPCSTR          servicename,
	LPDWORD         LocalAddressLength,
	LPSOCKADDR      LocalAddress,
	LPDWORD         RemoteAddressLength,
	LPSOCKADDR      RemoteAddress,
	const timeval* timeout,
	LPWSAOVERLAPPED Reserved
)
{
	log("Checking WSAConnectByNameA...");

	BOOL res;
	res = check_domain((char*)nodename, "WSAConnectByNameA");
	if (res == TRUE)
	{
		send_message("Block WSAConnectByNameA call", 1);
		log("Block WSAConnectByNameA call");
		send_message(get_current_process(), 4);
		return NULL;
	}
	else
	{
		log("Call WSAConnectByNameA");
		return pWSAConnectByNameA(s, nodename, servicename, LocalAddressLength, LocalAddress, RemoteAddressLength, RemoteAddress, timeout, Reserved);
	}
}

int WSAAPI MyWSARecv(
	SOCKET                             s,
	LPWSABUF                           lpBuffers,
	DWORD                              dwBufferCount,
	LPDWORD                            lpNumberOfBytesRecvd,
	LPDWORD                            lpFlags,
	LPWSAOVERLAPPED                    lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
)
{
	log("Call WSARecv");
	return pWSARecv(s,lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
}

int WSAAPI MyWSASend(
	SOCKET                             s,
	LPWSABUF                           lpBuffers,
	DWORD                              dwBufferCount,
	LPDWORD                            lpNumberOfBytesSent,
	DWORD                              dwFlags,
	LPWSAOVERLAPPED                    lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
)
{
	log("Call WSASend");
	return pWSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
}

int WSAAPI Myconnect(
	SOCKET         s,
	const sockaddr* name,
	int            namelen
)
{
	log("Call connect");
	return pconnect(s, name, namelen);
}

int WSAAPI Mysend(
	SOCKET s,
	const char* buf,
	int len,
	int flags
)
{
	log("Call send");
	return psend(s, buf, len, flags);
}

int WSAAPI Myrecv(
	SOCKET s, 
	char* buf, 
	int len, 
	int flags)
{
	log("Checking recv...");

	BOOL res;
	string data = buf;
	res = check_signatures(data);
	if (res == FALSE)
	{
		log("Call recv");
		return precv(s, buf, len, flags);
	}
	else
	{
		send_message("Block recv call", 1);
		log("Block recv call");
		send_message(get_current_process(), 4);
		return NULL;
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
	
	if (DetourIsHelperProcess()) {
		return TRUE;
	}
	
	if (dwReason == DLL_THREAD_ATTACH || DLL_PROCESS_ATTACH) {
		DetourRestoreAfterWith();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		DetourAttach(&(PVOID&)pWinHttpConnect, MyWinHttpConnect);
		DetourAttach(&(PVOID&)pWinHttpSendRequest, MyWinHttpSendRequest);
		DetourAttach(&(PVOID&)pWinHttpReadData, MyWinHttpReadData);
		DetourAttach(&(PVOID&)pHttpSendRequestA, MyHttpSendRequestA);
		DetourAttach(&(PVOID&)pInternetReadFile, MyInternetReadFile);
		DetourAttach(&(PVOID&)pInternetConnectA, MyInternetConnectA);
		DetourAttach(&(PVOID&)pInternetOpenA, MyInternetOpenA);
		DetourAttach(&(PVOID&)pInternetOpenUrlA, MyInternetOpenUrlA);
		DetourAttach(&(PVOID&)pWSAAccept, MyWSAAccept);
		DetourAttach(&(PVOID&)pWSAConnect, MyWSAConnect);
		DetourAttach(&(PVOID&)pWSAConnectByNameA, MyWSAConnectByNameA);
		DetourAttach(&(PVOID&)pWSARecv, MyWSARecv);
		DetourAttach(&(PVOID&)pWSASend, MyWSASend);
		DetourAttach(&(PVOID&)pconnect, Myconnect);
		DetourAttach(&(PVOID&)psend, Mysend);
		DetourAttach(&(PVOID&)precv, Myrecv);
		DetourAttach(&(PVOID&)pHttpOpenRequestA, MyHttpOpenRequestA);
				
		DetourTransactionCommit();
	}

	return TRUE;
}

string get_time()
{
	string reg_time;
	char local_time[32] = "";

	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	strftime(local_time, 32, "%d.%m.%Y %H:%M:%S", &tm);

	reg_time += "[";
	reg_time += local_time;
	reg_time += "] ";

	return reg_time;
}

void log(const char *msg) {
	char local_time[32] = "";
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	strftime(local_time, 32, "[%d.%m.%Y %H:%M:%S] ", &tm);
	FILE *pfile = fopen("C:/UnterAV/Logs/log_dll_network_WINAPI.txt", "a+");
	fprintf(pfile, "%s%s\n", local_time, msg);
	fclose(pfile);
}

void send_message(string msg, int choice)
{
	DWORD last_error;
	unsigned int elapsed_seconds = 0;
	const unsigned int timeout_seconds = 5;

	HANDLE hNamedPipe;
	char szPipeName[256] = "\\\\.\\pipe\\WINAPINetworkDLL";

	string message_to_send;

	// 0 - log; 1 - event
	if (choice == 0)
	{
		message_to_send += "log." + get_time();
	}
	else if (choice == 1)
	{
		message_to_send += "event." + get_time();
	}
	else if (choice == 4)
	{
		// bad
		message_to_send += "file(-).";
	}

	hNamedPipe = CreateFileA(szPipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

	while (INVALID_HANDLE_VALUE == hNamedPipe && elapsed_seconds < timeout_seconds)
	{
		last_error = GetLastError();

		if (last_error != ERROR_PIPE_BUSY)
		{
			break;
		}

		Sleep(1 * 1000);
		elapsed_seconds++;

		hNamedPipe = CreateFileA(szPipeName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	}

	if (hNamedPipe == INVALID_HANDLE_VALUE)
	{
		string error = "CreateFile: Error ";
		error += to_string(GetLastError());
		log(error.c_str());
	}
	else
	{
		string msg_to_log;
		string temp = "Connected to ";
		temp += szPipeName;
		log(temp.c_str());

		message_to_send += msg;
		message_to_send += "(^_^)";

		DWORD  cbWritten;
		if (WriteFile(hNamedPipe, message_to_send.c_str(), message_to_send.length(), &cbWritten, NULL))
		{
			msg_to_log += "Sent message to";
			msg_to_log += szPipeName;
			msg_to_log += ": " + message_to_send;
			log(msg_to_log.c_str());
		}
		else
		{
			msg_to_log += "Error of sending message by pipe with name '";
			msg_to_log += szPipeName;
			msg_to_log += "'";
			log(msg_to_log.c_str());
		}
	}
	CloseHandle(hNamedPipe);
}

char *wchar_to_char(const wchar_t* pwchar)
{
	// get the number of characters in the string.
	int currentCharIndex = 0;
	char currentChar = pwchar[currentCharIndex];

	while (currentChar != '\0')
	{
		currentCharIndex++;
		currentChar = pwchar[currentCharIndex];
	}

	const int charCount = currentCharIndex + 1;

	// allocate a new block of memory size char (1 byte) instead of wide char (2 bytes)
	char* filePathC = (char*)malloc(sizeof(char) * charCount);

	for (int i = 0; i < charCount; i++)
	{
		// convert to char (1 byte)
		char character = pwchar[i];

		*filePathC = character;

		filePathC += sizeof(char);

	}
	filePathC += '\0';
	filePathC -= (sizeof(char) * charCount);

	return filePathC;
}

BOOL check_domain(char *CheckDomain, const char *FunctionName)
{
	string out_str;
	out_str += "Checking function ";
	out_str += "'";
	out_str += FunctionName;
	out_str += "'";
	out_str += "arguments for malicious domains";
	log(out_str.c_str());

	leveldb::DB* db_domains;
	leveldb::Options options_domains;
	string MyFind, msg,
		strCheckDomain = CheckDomain,
		leveldb_domains = "C:/UnterAV/DataBases/LevelDB/DomainsDB";

	smatch matchhttp, matchwww;
	regex regularhttp("(https?://)");
	regex regularwww("(www\.)");

	regex_search(strCheckDomain, matchhttp, regularhttp);
	if (matchhttp.size() != 0)
	{
		strCheckDomain.clear();
		strCheckDomain = matchhttp.suffix();
	}

	regex_search(strCheckDomain, matchwww, regularwww);
	if (matchwww.size() != 0)
	{
		strCheckDomain.clear();
		strCheckDomain = matchwww.suffix();
	}

	clock_t start;
	start = clock();

	while (1)
	{
		options_domains.create_if_missing = false;
		leveldb::Status status_domains = leveldb::DB::Open(options_domains, leveldb_domains, &db_domains);

		if (status_domains.ok())
		{
			log("Opened DomainsDB");
			leveldb::Status local_status;
			local_status = db_domains->Get(leveldb::ReadOptions(), strCheckDomain, &MyFind);
			if (local_status.ok())
			{
				msg = "ALERT!!! Detected dangerous domain: " + strCheckDomain;
				send_message(msg.c_str(), 1);
				log(msg.c_str());
				msg.clear();

				if (db_domains)
					delete db_domains;
				return TRUE;
			}
			else
			{
				if (db_domains)
					delete db_domains;
				return FALSE;
			}
			break;
		}

		if (2.0 <= (double)((clock() - start) / 1000.0))
		{
			msg += "ERROR of openning DataBase of domains " + leveldb_domains;
			send_message(msg.c_str(), 0);
			log(msg.c_str());
			msg.clear();
			break;
		}
		/*
		else
		{
			string FileName = "C:/UnterAV/spywaredomains.zones";

			msg += "ERROR of openning DataBase of domains " + leveldb_domains;
			//send_message(msg.c_str());
			log(msg.c_str());
			msg.clear();
			//send_message("Try to create DataBase of domains...");
			log("Try to create DataBase of domains...");

			ifstream FileDomains(FileName);
			if (FileDomains.is_open())
			{
				int flag_created = 0;
				leveldb::WriteOptions writeOptions;

				options_domains.create_if_missing = true;
				leveldb::Status status_domains = leveldb::DB::Open(options_domains, leveldb_domains, &db_domains);

				string line;
				while (getline(FileDomains, line))
				{
					string domain;
					smatch match;
					regex regulardomains("(zone \")""(\.+)""(\" )");
					regex_search(line, match, regulardomains);

					if (match[2] != "" && match.size() == 4)
					{
						domain += match[2];
						status_domains = db_domains->Put(leveldb::WriteOptions(), domain, domain);
						flag_created = 1;
						if (false == status_domains.ok())
						{
							msg += "Error of putting key-value: ";
							msg += domain;
							log(msg.c_str());
							msg.clear();
						}
					}
				}
				if (flag_created == 1)
				{
					msg += "DataBase of domains " + leveldb_domains + " successfull created";
					//send_message(msg.c_str());
					log(msg.c_str());
					msg.clear();

					leveldb::Status local_status;
					local_status = db_domains->Get(leveldb::ReadOptions(), strCheckDomain, &MyFind);
					if (local_status.ok())
					{
						msg = "ALERT!!! Detected dangerous domain: " + MyFind;
						//send_message(msg.c_str());
						log(msg.c_str());
						msg.clear();
						if (db_domains)
							delete db_domains;
						return TRUE;
					}
					else
					{
						if (db_domains)
							delete db_domains;
						return FALSE;
					}
				}
				FileDomains.close();
			}
			else
			{
				//send_message("Cannot find spywaredomains.zones for creating database of dangerous domains");
				log("Cannot find spywaredomains.zones for creating database of dangerous domains");
			}

			if (db_domains)
				delete db_domains;
			return FALSE;
		}
		*/
	}
}

BOOL check_signatures(string data)
{
	int flag = 0;
	leveldb::DB* db_WebSignatures;
	leveldb::Options options_WebSignatures;
	string leveldb_WebSignatures = "C:/UnterAV/DataBases/LevelDB/WebSignaturesDB";

	options_WebSignatures.create_if_missing = false;

	leveldb::Status status_WebSignatures = leveldb::DB::Open(options_WebSignatures, leveldb_WebSignatures, &db_WebSignatures);

	clock_t start;
	start = clock();

	while (1)
	{
		if (status_WebSignatures.ok())
		{
			log("Opened WebSignaturesDB");
			leveldb::Iterator* it = db_WebSignatures->NewIterator(leveldb::ReadOptions());

			for (it->SeekToFirst(); it->Valid(); it->Next())
			{
				string msg;
				string temp = it->key().ToString();

				smatch match;
				regex regular(temp.c_str());

				regex_search(data, match, regular);

				if (match.size() != 0)
				{
					flag = 1;
					msg += "Find malware signature in webpage: ";
					msg += it->value().ToString();
					send_message(msg.c_str(), 1);
					log(msg.c_str());
				}
			}
			if (it)
				delete it;

			break;
		}

		if (2.0 <= (double)((clock() - start) / 1000.0))
		{
			send_message("Error of openning database C:\\UnterAV\\DataBases\\LevelDB\\WebSignaturesDB", 0);
			log("Error of openning database C:\\UnterAV\\DataBases\\LevelDB\\WebSignaturesDB");
			break;
		}		
	}

	if (db_WebSignatures)
		delete db_WebSignatures;

	if (flag == 0)
		return FALSE;
	else
		return TRUE;
}

char* get_current_process()
{
	CHAR buffer[MAX_PATH] = "";
	GetModuleFileNameA(NULL, buffer, sizeof(buffer) / sizeof(buffer[0]));
	return buffer;
}