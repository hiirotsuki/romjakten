//#define _DEBUG 1
#include <windows.h>

#ifdef _DEBUG
HANDLE hConsole;

#define TRACE(...) do { \
	char buffer[1024]; \
	wsprintfA(buffer, __VA_ARGS__); \
	WriteConsoleA(hConsole, buffer, lstrlenA(buffer), NULL, NULL); \
} while(0)
#else
#define TRACE(...)
#endif

void *hook_IAT(HMODULE hModule, const char *dllName, const char *funcName, void *hook_function)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE *)hModule + dosHeader->e_lfanew);

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)hModule + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (importDesc->Name)
    {
        const char *importDllName = (const char *)((BYTE *)hModule + importDesc->Name);
        if (lstrcmpiA(importDllName, dllName) == 0)
        {
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE *)hModule + importDesc->FirstThunk);
            PIMAGE_THUNK_DATA originalThunk = (PIMAGE_THUNK_DATA)((BYTE *)hModule + importDesc->OriginalFirstThunk);

            while (originalThunk->u1.Function)
            {
                // Skip ordinal imports
                if (originalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                {
                    originalThunk++;
                    thunk++;
                    continue;
                }

                PIMAGE_IMPORT_BY_NAME func = (PIMAGE_IMPORT_BY_NAME)((BYTE *)hModule + originalThunk->u1.AddressOfData);

                if (lstrcmpiA((const char *)func->Name, funcName) == 0)
                {
					void *originalAddress = (void *)thunk->u1.Function;
                    TRACE("Original function address: %p\n", originalAddress);

                    DWORD oldProtect;
                    if (!VirtualProtect(&thunk->u1.Function, sizeof(void *), PAGE_READWRITE, &oldProtect)) {
                        TRACE("VirtualProtect failed: %lu\n", GetLastError());
                        return NULL;
                    }

                    thunk->u1.Function = (uintptr_t)hook_function;
					TRACE("hook function address: %p\n", hook_function);

                    VirtualProtect(&thunk->u1.Function, sizeof(void *), oldProtect, &oldProtect);

                    TRACE("Hooked function %s in %s\n", funcName, dllName);
                    return originalAddress;
                }

                originalThunk++;
                thunk++;
            }
        }
        importDesc++;
    }

    TRACE("Function not found: %s in %s\n", funcName, dllName);
    return NULL;
}

typedef HWND (WINAPI *CreateWindowExA_t)(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, \
											DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, \
											HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam);

typedef int (WINAPI *GetSystemMetrics_t)(int nIndex);
typedef BOOL (WINAPI *ShowWindow_t)(HWND hWnd, int nCmdShow);

CreateWindowExA_t pCreateWindowExA = NULL;
GetSystemMetrics_t pGetSystemMetrics = NULL;
ShowWindow_t pShowWindow = NULL;

HWND WINAPI CreateWindowExA_hook(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, \
							DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, \
							HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam)
{
	TRACE("CreateWindowExA called! X = %d, Y = %d, width = %d, height = %d, style = %X, exStyle = %d\n", X, Y, nWidth, nHeight, dwStyle, dwExStyle);
	DWORD new_style = WS_OVERLAPPEDWINDOW;
	/* the background window normally covers the entire screen with a borderless window */
	/* change only the background one based on style, */
	/* update the style and force the size to 640x480 */
	if(dwStyle == 0x82000000)
	{
		TRACE("fixing up CreateWindowExA, SIGH.\n");
		return pCreateWindowExA(dwExStyle, lpClassName, lpWindowName, new_style, X, Y, 640, 480, hWndParent, hMenu, hInstance, lpParam);
	}
	else
	{
		return pCreateWindowExA(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
	}
}

int WINAPI GetSystemMetrics_hook(int nIndex)
{
	/* force the screen size to be 640x480 */
	/* the inner window calculates the center of the screen */
	/* to render the game window */
	switch(nIndex)
	{
		case SM_CXSCREEN: return 640;
		case SM_CYSCREEN: return 480;
		default: return pGetSystemMetrics(nIndex);
	}
}

BOOL WINAPI ShowWindow_hook(HWND hWnd, int nCmdShow)
{
	/* sigh... */
	/* for some reason the game calls maximize repeatedly, */
	/* just eat all the calls */
	TRACE("ShowWindow hook called! fixing maximize...\n");
	if(nCmdShow == SW_MAXIMIZE)
	{
		nCmdShow = SW_SHOWNORMAL;
	}

	return pShowWindow(hWnd, nCmdShow);
}

#if 0
BOOL APIENTRY DllMain(HMODULE module, DWORD ul_reason, LPVOID lpReserved)
#else
void __stdcall DllMainCRTStartup(HMODULE module, DWORD ul_reason, LPVOID reserved)
#endif
{
	(void)reserved;
	if(ul_reason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(module);
#ifdef _DEBUG
		AllocConsole();
		hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
#endif

		pShowWindow = hook_IAT(GetModuleHandle(NULL), "user32.dll", "ShowWindow", ShowWindow_hook);
		pGetSystemMetrics = hook_IAT(GetModuleHandle(NULL), "user32.dll", "GetSystemMetrics", GetSystemMetrics_hook);
		pCreateWindowExA = hook_IAT(GetModuleHandle(NULL), "user32.dll", "CreateWindowExA", CreateWindowExA_hook);
	}
#if 0
	return TRUE;
#endif
}
