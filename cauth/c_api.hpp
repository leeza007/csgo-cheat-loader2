#pragma once
#include "c_xor.hpp"
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/hex.h>
#include <cryptopp/ccm.h>

#include <curl/curl.h>

#include <atlsecurity.h> 
#include <string>
#include <ctime>

#pragma comment(lib, "rpcrt4.lib") //uuid

//CRYPTOPP AND LIBCURL ARE NEEDED

//NEEDS C++ 17

#ifndef c_auth_h
#define c_auth_h

namespace c_auth {
	namespace c_encryption {
		inline std::string encrypt_string(const std::string& str_in, const std::string& key, const std::string& iv) {
			std::string str_out;

			try {
				CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption;
				encryption.SetKeyWithIV((byte*)key.c_str(), key.size(), (byte*)iv.c_str());

				CryptoPP::StringSource encryptor(str_in, true,
					new CryptoPP::StreamTransformationFilter(encryption,
						new CryptoPP::HexEncoder(
							new CryptoPP::StringSink(str_out),
							false // not uppercase
						)
					)
				);
			}
			catch (CryptoPP::Exception ex) {
				MessageBoxA(0, ex.what(), "cAuth", MB_ICONERROR);
				exit(0);
			}
			return str_out;
		}

		inline std::string decrypt_string(const std::string& str_in, const std::string& key, const std::string& iv) {
			std::string str_out;

			try {
				CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption;
				decryption.SetKeyWithIV((byte*)key.c_str(), key.size(), (byte*)iv.c_str());

				CryptoPP::StringSource decryptor(str_in, true,
					new CryptoPP::HexDecoder(
						new CryptoPP::StreamTransformationFilter(decryption,
							new CryptoPP::StringSink(str_out)
						)
					)
				);
			}
			catch (CryptoPP::Exception ex) {
				MessageBoxA(0, "Invalid API/Encryption key", "cAuth", MB_ICONERROR);
				exit(0);
			}
			return str_out;
		}

		inline std::string sha256(const std::string& _) {
			std::string res;
			CryptoPP::SHA256 hash;

			try {
				CryptoPP::StringSource hashing(_, true,
					new CryptoPP::HashFilter(hash,
						new CryptoPP::HexEncoder(
							new CryptoPP::StringSink(res),
							false
						)
					)
				);
			}
			catch (CryptoPP::Exception ex) {
				MessageBoxA(0, ex.what(), "cAuth", MB_ICONERROR);
				exit(0);
			}

			return res;
		}

		inline std::string hex_encode(const std::string& _) {
			std::string res;

			try {
				CryptoPP::StringSource encoding(_, true,
					new CryptoPP::HexEncoder(
						new CryptoPP::StringSink(res),
						false
					)
				);
			}
			catch (CryptoPP::Exception ex) {
				MessageBoxA(0, ex.what(), "cAuth", MB_ICONERROR);
				exit(0);
			}

			return res;
		}

		inline std::string iv_key() {
			UUID uuid = { 0 };
			std::string guid;

			::UuidCreate(&uuid);

			RPC_CSTR szUuid = NULL;
			if (::UuidToStringA(&uuid, &szUuid) == RPC_S_OK)
			{
				guid = (char*)szUuid;
				::RpcStringFreeA(&szUuid);
			}

			return guid.substr(0, 8);
		}

		inline std::string encrypt(std::string message, std::string enc_key, std::string iv = "default_iv") {
			std::string res;

			enc_key = sha256(enc_key).substr(0, 32);

			if (iv == "default_iv")
				return encrypt_string(message, enc_key, c_xor("1514834626578394"));
			else
				return encrypt_string(message, enc_key, sha256(iv).substr(0, 16));

			return res;
		}

		inline std::string decrypt(std::string message, std::string enc_key, std::string iv = "default_iv") {
			std::string res;

			enc_key = sha256(enc_key).substr(0, 32);

			if (iv == "default_iv")
				return decrypt_string(message, enc_key, c_xor("1514834626578394"));
			else
				return decrypt_string(message, enc_key, sha256(iv).substr(0, 16));

			return res;
		}
	}

	namespace c_utils {
		inline std::vector<std::string> split(const std::string& str, const char separator)
		{
			std::vector<std::string> output;
			std::string::size_type prev_pos = 0, pos = 0;

			while ((pos = str.find(separator, pos)) != std::string::npos)
			{
				auto substring(str.substr(prev_pos, pos - prev_pos));
				output.push_back(substring);
				prev_pos = ++pos;
			}

			output.push_back(str.substr(prev_pos, pos - prev_pos));
			return output;
		}

		//this here returns the same as the c# get hwid function
		inline std::string get_hwid() {
			ATL::CAccessToken accessToken;
			ATL::CSid currentUserSid;
			if (accessToken.GetProcessToken(TOKEN_READ | TOKEN_QUERY) &&
				accessToken.GetUser(&currentUserSid))
				return std::string(CT2A(currentUserSid.Sid()));
		}
	}

	namespace c_userdata {
		inline std::string username;
		inline std::string email;
		inline std::time_t expires; //its stored as a timestamp, convert it if you want to display it
		inline std::string var;
		inline int rank;
	}

	namespace c_api {
		inline std::string program_key;
		inline std::string enc_key;
		inline std::string iv_key;

		inline std::string session_id;

		inline std::string api_link = c_xor("https://cauth.me/api/");
		inline std::string user_agent = c_xor("Mozilla cAuth");

		inline std::string stored_pass;

		inline size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
			((std::string*)userp)->append((char*)contents, size * nmemb);
			return size * nmemb;
		}

		inline char* pub_key() {
			return (char*)c_xor("sha256//Mk6vhbkCoRzUhXoUryC8tjIxmehtu4uLVhwqGQM9Cmc=");
		}

		inline void c_init(std::string c_version, std::string c_program_key, std::string c_encryption_key) {
			program_key = c_program_key;
			iv_key = c_encryption::iv_key();
			enc_key = c_encryption_key;

			std::string result;

			try {
				CURL* c_url = curl_easy_init();
				CURLcode code;
				if (c_url) {
					curl_easy_setopt(c_url, CURLOPT_URL, std::string(api_link + c_xor("handler.php?type=init")).c_str());
					curl_easy_setopt(c_url, CURLOPT_USERAGENT, user_agent.c_str());

					curl_easy_setopt(c_url, CURLOPT_NOPROXY, c_xor("cauth.me"));

					curl_easy_setopt(c_url, CURLOPT_SSL_VERIFYPEER, 0);

					curl_easy_setopt(c_url, CURLOPT_PINNEDPUBLICKEY, pub_key());

					std::string values =
						c_xor("version=") + c_encryption::encrypt(c_version, enc_key) +
						c_xor("&session_iv=") + c_encryption::encrypt(iv_key, enc_key) +
						c_xor("&api_version=") + c_encryption::encrypt(c_xor("3.3b"), enc_key) +
						c_xor("&program_key=") + c_encryption::hex_encode(program_key);

					curl_easy_setopt(c_url, CURLOPT_POSTFIELDSIZE, values.size());
					curl_easy_setopt(c_url, CURLOPT_POSTFIELDS, values.c_str());

					curl_easy_setopt(c_url, CURLOPT_WRITEFUNCTION, write_callback);
					curl_easy_setopt(c_url, CURLOPT_WRITEDATA, &result);

					code = curl_easy_perform(c_url);

					curl_easy_cleanup(c_url);

					if (result != c_xor("program_doesnt_exist")) {

						result = c_encryption::decrypt(result, enc_key);

						if (result == c_xor("killswitch_is_enabled")) {
							MessageBoxA(0, c_xor("The killswitch of the program is enabled, contact the developer"), "cAuth", MB_ICONERROR);
							exit(0);
						}
						else if (result.find(c_xor("wrong_version")) != std::string::npos) {
							MessageBoxA(0, c_xor("Wrong program version"), "cAuth", MB_ICONERROR);
							ShellExecuteA(0, "open", c_utils::split(result, '|')[1].c_str(), 0, 0, SW_SHOWNORMAL); //only for windows 
							exit(0);
						}
						else {
							std::vector<std::string> x = c_utils::split(result, '|');

							iv_key += x[1];
							session_id = x[2];
						}
					}
					else {
						MessageBoxA(0, c_xor("The program doesnt exist"), "cAuth", MB_ICONERROR);
						exit(0);
					}
				}
			}
			catch (...) {
				//ignore the exceptions thrown here
				exit(0);
			}
		}

		inline bool c_login(std::string c_username, std::string c_password, std::string c_hwid = "default") {
			if (c_hwid == "default") c_hwid = c_utils::get_hwid();

			std::string result;

			try {
				CURL* c_url = curl_easy_init();
				CURLcode code;
				if (c_url) {
					curl_easy_setopt(c_url, CURLOPT_URL, std::string(api_link + c_xor("handler.php?type=login")).c_str());
					curl_easy_setopt(c_url, CURLOPT_USERAGENT, user_agent.c_str());

					curl_easy_setopt(c_url, CURLOPT_NOPROXY, c_xor("cauth.me"));
					curl_easy_setopt(c_url, CURLOPT_SSL_VERIFYPEER, 0);

					curl_easy_setopt(c_url, CURLOPT_PINNEDPUBLICKEY, pub_key());

					std::string values =
						c_xor("username=") + c_encryption::encrypt(c_username, enc_key, iv_key) +
						c_xor("&password=") + c_encryption::encrypt(c_password, enc_key, iv_key) +
						c_xor("&hwid=") + c_encryption::encrypt(c_hwid, enc_key, iv_key) +
						c_xor("&sessid=") + c_encryption::hex_encode(session_id);

					curl_easy_setopt(c_url, CURLOPT_POSTFIELDSIZE, values.size());
					curl_easy_setopt(c_url, CURLOPT_POSTFIELDS, values.c_str());

					curl_easy_setopt(c_url, CURLOPT_WRITEFUNCTION, write_callback);
					curl_easy_setopt(c_url, CURLOPT_WRITEDATA, &result);

					code = curl_easy_perform(c_url);

					curl_easy_cleanup(c_url);

					result = c_encryption::decrypt(result, enc_key, iv_key);

					if (result == c_xor("killswitch_is_enabled")) {
						MessageBoxA(0, c_xor("The killswitch of the program is enabled, contact the developer"), "cAuth", MB_ICONERROR);
						return false;
					}
					else if (result == c_xor("invalid_username")) {
						MessageBoxA(0, c_xor("Invalid username"), "cAuth", MB_ICONERROR);
						return false;
					}
					else if (result == c_xor("invalid_password")) {
						MessageBoxA(0, c_xor("Invalid password"), "cAuth", MB_ICONERROR);
						return false;
					}
					else if (result == c_xor("user_is_banned")) {
						MessageBoxA(0, c_xor("The user is banned"), "cAuth", MB_ICONERROR);
						return false;
					}
					else if (result == c_xor("no_sub")) {
						MessageBoxA(0, c_xor("Your subscription is over"), "cAuth", MB_ICONERROR);
						return false;
					}
					else if (result == c_xor("invalid_hwid")) {
						MessageBoxA(0, c_xor("Invalid HWID"), "cAuth", MB_ICONERROR);
						return false;
					}
					else if (result.find(c_xor("logged_in")) != std::string::npos) {
						std::vector<std::string> s = c_utils::split(result, '|');

						c_userdata::username = s[1];
						c_userdata::email = s[2];

						c_userdata::expires = (time_t)strtol(s[3].c_str(), NULL, 10);

						c_userdata::var = s[4];

						c_userdata::rank = std::stoi(s[5]);

						stored_pass = c_encryption::encrypt(c_password, enc_key, iv_key);

						MessageBoxA(0, c_xor("Logged in!!"), "cAuth", MB_ICONINFORMATION);
						return true;
					}
					else {
						MessageBoxA(0, c_xor("Invalid encryption key/iv or session expired"), "cAuth", MB_ICONERROR);
						return false;
					}
				}
			}
			catch (std::exception x) {
				MessageBoxA(0, x.what(), "cAuth", MB_ICONERROR);
				exit(0);
			}
			return false;
		}

		inline bool c_register(std::string c_username, std::string c_email, std::string c_password, std::string c_token, std::string c_hwid = "default") {
			if (c_hwid == "default") c_hwid = c_utils::get_hwid();

			std::string result;

			try {
				CURL* c_url = curl_easy_init();
				CURLcode code;
				if (c_url) {
					curl_easy_setopt(c_url, CURLOPT_URL, std::string(api_link + c_xor("handler.php?type=register")).c_str());
					curl_easy_setopt(c_url, CURLOPT_USERAGENT, user_agent.c_str());

					curl_easy_setopt(c_url, CURLOPT_NOPROXY, c_xor("cauth.me"));
					curl_easy_setopt(c_url, CURLOPT_SSL_VERIFYPEER, 0);

					curl_easy_setopt(c_url, CURLOPT_PINNEDPUBLICKEY, pub_key());

					std::string values =
						c_xor("username=") + c_encryption::encrypt(c_username, enc_key, iv_key) +
						c_xor("&email=") + c_encryption::encrypt(c_email, enc_key, iv_key) +
						c_xor("&password=") + c_encryption::encrypt(c_password, enc_key, iv_key) +
						c_xor("&token=") + c_encryption::encrypt(c_token, enc_key, iv_key) +
						c_xor("&hwid=") + c_encryption::encrypt(c_hwid, enc_key, iv_key) +
						c_xor("&sessid=") + c_encryption::hex_encode(session_id);

					curl_easy_setopt(c_url, CURLOPT_POSTFIELDSIZE, values.size());
					curl_easy_setopt(c_url, CURLOPT_POSTFIELDS, values.c_str());

					curl_easy_setopt(c_url, CURLOPT_WRITEFUNCTION, write_callback);
					curl_easy_setopt(c_url, CURLOPT_WRITEDATA, &result);

					code = curl_easy_perform(c_url);

					curl_easy_cleanup(c_url);

					result = c_encryption::decrypt(result, enc_key, iv_key);

					if (result == c_xor("killswitch_is_enabled")) {
						MessageBoxA(0, c_xor("The killswitch of the program is enabled, contact the developer"), "cAuth", MB_ICONERROR);
						return false;
					}
					else if (result == c_xor("user_already_exists")) {
						MessageBoxA(0, c_xor("User already exists"), "cAuth", MB_ICONERROR);
						return false;
					}
					else if (result == c_xor("email_already_exists")) {
						MessageBoxA(0, c_xor("Email already exists"), "cAuth", MB_ICONERROR);
						return false;
					}
					else if (result == c_xor("invalid_email_format")) {
						MessageBoxA(0, c_xor("Invalid email format"), "cAuth", MB_ICONERROR);
						return false;
					}
					else if (result == c_xor("invalid_token")) {
						MessageBoxA(0, c_xor("Invalid token"), "cAuth", MB_ICONERROR);
						return false;
					}
					else if (result == c_xor("maximum_users_reached")) {
						MessageBoxA(0, c_xor("Maximum users of the program was reached, please contact the program owner"), "cAuth", MB_ICONERROR);
						return false;
					}
					else if (result == c_xor("used_token")) {
						MessageBoxA(0, c_xor("Already used token"), "cAuth", MB_ICONERROR);
						return false;
					}
					else if (result == c_xor("success")) {
						MessageBoxA(0, c_xor("Success!!"), "cAuth", MB_ICONINFORMATION);
						return false;
					}
					else {
						MessageBoxA(0, c_xor("Invalid encryption key/iv or session expired"), "cAuth", MB_ICONERROR);
						return false;
					}
				}
			}
			catch (std::exception x) {
				MessageBoxA(0, x.what(), "cAuth", MB_ICONERROR);
				exit(0);
			}
			return false;
		}

		inline bool c_activate(std::string c_username, std::string c_password, std::string c_token) {
			std::string result;

			try {
				CURL* c_url = curl_easy_init();
				CURLcode code;
				if (c_url) {
					curl_easy_setopt(c_url, CURLOPT_URL, std::string(api_link + c_xor("handler.php?type=activate")).c_str());
					curl_easy_setopt(c_url, CURLOPT_USERAGENT, user_agent.c_str());

					curl_easy_setopt(c_url, CURLOPT_NOPROXY, c_xor("cauth.me"));
					curl_easy_setopt(c_url, CURLOPT_SSL_VERIFYPEER, 0);

					curl_easy_setopt(c_url, CURLOPT_PINNEDPUBLICKEY, pub_key());

					std::string values =
						c_xor("username=") + c_encryption::encrypt(c_username, enc_key, iv_key) +
						c_xor("&password=") + c_encryption::encrypt(c_password, enc_key, iv_key) +
						c_xor("&token=") + c_encryption::encrypt(c_token, enc_key, iv_key) +
						c_xor("&sessid=") + c_encryption::hex_encode(session_id);

					curl_easy_setopt(c_url, CURLOPT_POSTFIELDSIZE, values.size());
					curl_easy_setopt(c_url, CURLOPT_POSTFIELDS, values.c_str());

					curl_easy_setopt(c_url, CURLOPT_WRITEFUNCTION, write_callback);
					curl_easy_setopt(c_url, CURLOPT_WRITEDATA, &result);

					code = curl_easy_perform(c_url);

					curl_easy_cleanup(c_url);

					result = c_encryption::decrypt(result, enc_key, iv_key);

					if (result == c_xor("killswitch_is_enabled")) {
						MessageBoxA(0, c_xor("The killswitch of the program is enabled, contact the developer"), "cAuth", MB_ICONERROR);
						return false;
					}
					else if (result == c_xor("invalid_username")) {
						MessageBoxA(0, c_xor("Invalid username"), "cAuth", MB_ICONERROR);
						return false;
					}
					else if (result == c_xor("invalid_password")) {
						MessageBoxA(0, c_xor("Invalid password"), "cAuth", MB_ICONERROR);
						return false;
					}
					else if (result == c_xor("user_is_banned")) {
						MessageBoxA(0, c_xor("The user is banned"), "cAuth", MB_ICONERROR);
						return false;
					}
					else if (result == c_xor("invalid_token")) {
						MessageBoxA(0, c_xor("Invalid token"), "cAuth", MB_ICONERROR);
						return false;
					}
					else if (result == c_xor("used_token")) {
						MessageBoxA(0, c_xor("Already used token"), "cAuth", MB_ICONERROR);
						return false;
					}
					else if (result == c_xor("success")) {
						MessageBoxA(0, c_xor("Success!!"), "cAuth", MB_ICONINFORMATION);
						return false;
					}
					else {
						MessageBoxA(0, c_xor("Invalid encryption key/iv or session expired"), "cAuth", MB_ICONERROR);
						return false;
					}
				}
			}
			catch (std::exception x) {
				MessageBoxA(0, x.what(), "cAuth", MB_ICONERROR);
				exit(0);
			}
			return false;
		}

		inline bool c_all_in_one(std::string c_token, std::string c_hwid = "default") {
			if (c_hwid == "default") c_hwid = c_utils::get_hwid();

			if (c_login(c_token, c_token, c_hwid))
				return true;

			else if (c_register(c_token, c_token + "@email.com", c_token, c_token, c_hwid)) {
				exit(0);
				return true;
			}

			return false;
		}

		inline std::string c_var(std::string c_var_name, std::string c_hwid = "default") {
			if (c_hwid == "default") c_hwid = c_utils::get_hwid();

			std::string result;

			try {
				CURL* c_url = curl_easy_init();
				CURLcode code;
				if (c_url) {
					curl_easy_setopt(c_url, CURLOPT_URL, std::string(api_link + c_xor("handler.php?type=var")).c_str());
					curl_easy_setopt(c_url, CURLOPT_USERAGENT, user_agent.c_str());

					curl_easy_setopt(c_url, CURLOPT_NOPROXY, c_xor("cauth.me"));
					curl_easy_setopt(c_url, CURLOPT_SSL_VERIFYPEER, 0);

					curl_easy_setopt(c_url, CURLOPT_PINNEDPUBLICKEY, pub_key());

					std::string values =
						c_xor("var_name=") + c_encryption::encrypt(c_var_name, enc_key, iv_key) +
						c_xor("&username=") + c_encryption::encrypt(c_userdata::username, enc_key, iv_key) +
						c_xor("&password=") + stored_pass +
						c_xor("&hwid=") + c_encryption::encrypt(c_hwid, enc_key, iv_key) +
						c_xor("&sessid=") + c_encryption::hex_encode(session_id);

					curl_easy_setopt(c_url, CURLOPT_POSTFIELDSIZE, values.size());
					curl_easy_setopt(c_url, CURLOPT_POSTFIELDS, values.c_str());

					curl_easy_setopt(c_url, CURLOPT_WRITEFUNCTION, write_callback);
					curl_easy_setopt(c_url, CURLOPT_WRITEDATA, &result);

					code = curl_easy_perform(c_url);

					curl_easy_cleanup(c_url);

					result = c_encryption::decrypt(result, enc_key, iv_key);

					return result;
				}
			}
			catch (std::exception x) {
				MessageBoxA(0, x.what(), "cAuth", MB_ICONERROR);
				exit(0);
			}
			return "";
		}

		inline void c_log(std::string c_message) {
			if (c_userdata::username.empty()) c_userdata::username = "NONE";

			std::string result;

			try {
				CURL* c_url = curl_easy_init();
				CURLcode code;
				if (c_url) {
					curl_easy_setopt(c_url, CURLOPT_URL, std::string(api_link + c_xor("handler.php?type=log")).c_str());
					curl_easy_setopt(c_url, CURLOPT_USERAGENT, user_agent.c_str());

					curl_easy_setopt(c_url, CURLOPT_NOPROXY, c_xor("cauth.me"));
					curl_easy_setopt(c_url, CURLOPT_SSL_VERIFYPEER, 0);

					curl_easy_setopt(c_url, CURLOPT_PINNEDPUBLICKEY, pub_key());

					std::string values =
						c_xor("username=") + c_encryption::encrypt(c_userdata::username, enc_key, iv_key) +
						c_xor("&message=") + c_encryption::encrypt(c_message, enc_key, iv_key) +
						c_xor("&sessid=") + c_encryption::hex_encode(session_id);

					curl_easy_setopt(c_url, CURLOPT_POSTFIELDSIZE, values.size());
					curl_easy_setopt(c_url, CURLOPT_POSTFIELDS, values.c_str());

					curl_easy_setopt(c_url, CURLOPT_WRITEFUNCTION, write_callback);
					curl_easy_setopt(c_url, CURLOPT_WRITEDATA, &result);

					code = curl_easy_perform(c_url);

					curl_easy_cleanup(c_url);
				}
			}
			catch (std::exception x) {
				MessageBoxA(0, x.what(), "cAuth", MB_ICONERROR);
				exit(0);
			}
		}
	}
}

#endif