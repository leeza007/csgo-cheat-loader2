#pragma once

namespace form_defs {
	inline char username[255];
	inline char email[255];
	inline char password[255];
	inline char token[255];

	inline void clear() { //clear the char arrays
		ZeroMemory(username, sizeof(username));
		ZeroMemory(email, sizeof(email));
		ZeroMemory(password, sizeof(password));
		ZeroMemory(token, sizeof(token));
	}
}
