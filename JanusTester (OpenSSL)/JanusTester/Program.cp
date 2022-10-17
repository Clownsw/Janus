#include "Janus.h"

int wmain(int argc, wchar_t* argv[]) {
	
	JANUS lpText[] = "i trust u";
	JANUS lpCaption[] = "Rxseboy";
	MessageBoxA(NULL, Deobfuscate(lpText), Deobfuscate(lpCaption), MB_OK);
	free(decrypted);

	return 0;
}