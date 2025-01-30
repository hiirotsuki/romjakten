# Romjakten Window Fix

Makes Romjakten behave in a normal window instead of a broken "fullscreen" mode.

## How it works
Hooks the game's Import Address Table (IAT) to intercept Windows API calls:

- `CreateWindowExA`: Hook and redirect the background window to be 640x480.
- `GetSystemMetrics`: The game centers its 640x480 drawing area based on screen size, force the screen size to 640x480.
- `ShowWindow`: Normalize maximize window calls.

## Usage
1. Compile with your favorite C compiler targeting win32 or download from releases tab.
2. Inject into romjakt.exe with your favorite DLL injector like https://github.com/hiirotsuki/simpleloader/
3. Enjoy!
