#include <stdio.h>
#include <windows.h>

// Target Dll and Function
char TargetDLL[] = "USER32.dll";
char TargetFunction[] = "MessageBoxW";

// The Function That Will Run Insted The Target Function
int WINAPI Evil(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType){
    MessageBox(NULL, TEXT("Looks Like You Got Hooked ^-^"), TEXT("Oosp"), MB_OK);
    return 0;
}

// Rewrite The IAT Entry
bool WriteIAT(PIMAGE_THUNK_DATA PThunk, void* newFunc) {
    DWORD temp;
    DWORD CurrentProtect;

    VirtualProtect(PThunk, 4096, PAGE_READWRITE, &CurrentProtect);
    #ifdef _X86_ 
        PThunk->u1.Function = (DWORD)Evil;
    #endif
    #ifdef _WIN64
        PThunk->u1.Function = (SIZE_T)Evil;
    #endif
    VirtualProtect(PThunk, 4096, CurrentProtect, &temp);
    return true;
}

// Get The Import Address Table
PIMAGE_IMPORT_DESCRIPTOR getImportTable(HMODULE hmod) {

    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeader;
    IMAGE_OPTIONAL_HEADER optionalHeader;
    IMAGE_DATA_DIRECTORY dataDirectory;

    dosHeader = (PIMAGE_DOS_HEADER)hmod;
    ntHeader = (PIMAGE_NT_HEADERS)((PBYTE)dosHeader + dosHeader->e_lfanew);
    optionalHeader = (IMAGE_OPTIONAL_HEADER)(ntHeader->OptionalHeader);
    dataDirectory = (IMAGE_DATA_DIRECTORY)(optionalHeader.DataDirectory[1]);

    return (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)hmod + dataDirectory.VirtualAddress);
}

int HOOK() {

    HMODULE Hmodule;
    PIMAGE_IMPORT_DESCRIPTOR importTable;
    PIMAGE_THUNK_DATA PFirstThunk, POriginalFirstThunk;
    PIMAGE_IMPORT_BY_NAME PFunctionData;

    Hmodule = GetModuleHandleA(NULL);
    importTable = getImportTable(Hmodule);

    // Iterate Over Every Dll
    while (*(WORD*)importTable != 0) {

        printf("\nModule: %s\n",(char*)((PBYTE)Hmodule+importTable->Name));

        PFirstThunk = (PIMAGE_THUNK_DATA)((PBYTE)Hmodule + importTable->FirstThunk);
        POriginalFirstThunk = (PIMAGE_THUNK_DATA)((PBYTE)Hmodule + importTable->OriginalFirstThunk);
        PFunctionData = (PIMAGE_IMPORT_BY_NAME)((PBYTE)Hmodule + POriginalFirstThunk->u1.AddressOfData);

        // Iterate Over Every Entry In The IDT & IAT
        while (*(WORD*)PFirstThunk != 0 && *(WORD*)POriginalFirstThunk != 0) {
            printf("Address: %llX Function: %s \n", PFirstThunk->u1.Function, PFunctionData->Name);
            
            // Compare The Name Of The Target Function And The Target Dll To The Name In the IDT
            if (strcmp(TargetFunction, (char*)PFunctionData->Name) == 0 && strcmp(TargetDLL, (char*)((PBYTE)Hmodule + importTable->Name)) == 0) {
                printf("\nFound the '%s' function. Hooking...", TargetFunction);
                
                // Rewrite The IAT
                if (WriteIAT(PFirstThunk,(PVOID)Evil)) {
                    printf("\nThe Hooking Was Successfull XD\n");
                }
            }

            // Step To The Next Enry In The IAT & IDT
            POriginalFirstThunk++;
            PFunctionData = (PIMAGE_IMPORT_BY_NAME)((PBYTE)Hmodule + POriginalFirstThunk->u1.AddressOfData);
            PFirstThunk++;
        }

        // Go To The Next Dll
        importTable++;
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved){
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        HOOK();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
