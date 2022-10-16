#include "Janus.h"

#pragma comment(lib, "Ws2_32.lib")

int wmain(int argc, wchar_t* argv[]) {
	
	JANUS lpText[] = "The Remorse";
	JANUS lpCaption[] = "Drake";
	MessageBoxA(NULL, Deobfuscate(lpText), Deobfuscate(lpCaption), MB_OK);
	free(decrypted);

	return 0;
}