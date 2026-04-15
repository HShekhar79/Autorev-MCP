#include <winsock2.h>     // MUST be before windows.h
#include <windows.h>
#include <tlhelp32.h>     // 🔥 FIX (required for process enumeration)
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")

void command_exec() {
    system("cmd.exe /c echo malware_test");
}

void network_activity() {
    WSADATA wsa;
    SOCKET s;
    struct sockaddr_in server;

    WSAStartup(MAKEWORD(2,2), &wsa);

    s = socket(AF_INET, SOCK_STREAM, 0);
    server.sin_addr.s_addr = inet_addr("8.8.8.8");
    server.sin_family = AF_INET;
    server.sin_port = htons(80);

    connect(s, (struct sockaddr*)&server, sizeof(server));
    closesocket(s);
    WSACleanup();
}

void file_operations() {
    HANDLE hFile = CreateFile("test.txt", GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
        char data[] = "malware simulation";
        DWORD written;
        WriteFile(hFile, data, sizeof(data), &written, NULL);
        CloseHandle(hFile);
    }
}

void registry_persistence() {
    HKEY hKey;
    RegCreateKey(HKEY_CURRENT_USER,
                 "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                 &hKey);

    RegSetValueEx(hKey, "TestMalware", 0, REG_SZ,
                  (BYTE*)"C:\\malware.exe", 15);

    RegCloseKey(hKey);
}

void process_injection_sim() {
    LPVOID mem = VirtualAlloc(NULL, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (mem) {
        memset(mem, 0x90, 1024);
        VirtualFree(mem, 0, MEM_RELEASE);
    }
}

void dynamic_api_loading() {
    HMODULE h = LoadLibrary("kernel32.dll");
    if (h) {
        FARPROC addr = GetProcAddress(h, "CreateFileA");
        FreeLibrary(h);
    }
}

void anti_debug() {
    if (IsDebuggerPresent()) {
        ExitProcess(0);
    }
}

void system_discovery() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    char computerName[MAX_PATH];
    DWORD size = MAX_PATH;
    GetComputerName(computerName, &size);
}

void process_enum() {
    CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
}

int main() {
    command_exec();
    network_activity();
    file_operations();
    registry_persistence();
    process_injection_sim();
    dynamic_api_loading();
    anti_debug();
    system_discovery();
    process_enum();
    return 0;
}