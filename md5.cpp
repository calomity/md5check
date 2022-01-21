#include <iostream>
#include <stdio.h>
#include <windows.h>
#include <Wincrypt.h>
#include <winhttp.h>
#include <string>
#pragma comment(lib, "winhttp.lib")
#define BUFSIZE 1024
#define MD5LEN  16

DWORD errretval()
{
    DWORD errcode = GetLastError();
    printf("ERROR CODE: %d\n",errcode);
    return errcode;
}

static const DWORD httpreq(LPCWSTR linkwithoutslash, LPCWSTR fulllink, const std::string recieve)
{
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL,
    hConnect = NULL,
    hRequest = NULL;
    hSession = WinHttpOpen(L"BASIC WINHTTP REQUEST BY CALO",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    if (hSession)
        hConnect = WinHttpConnect(hSession, linkwithoutslash,
            INTERNET_DEFAULT_HTTPS_PORT, 0);

    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", fulllink,
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0, WINHTTP_NO_REQUEST_DATA, 0,
            0, 0);

    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);

    if (bResults)
    {
        do
        {
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
            {
                printf("Error %u in WinHttpQueryDataAvailable.\n",
                    GetLastError());
                break;
            }

            if (!dwSize)
                break;

            pszOutBuffer = new char[dwSize + 1];
            if (!pszOutBuffer)
            {
                printf("Out of memory\n");
                break;
            }

            ZeroMemory(pszOutBuffer, dwSize + 1);

            if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
                dwSize, &dwDownloaded))
            {
                printf("Error %u in WinHttpReadData.\n", GetLastError());
            }
            else
            {
                printf("%s", pszOutBuffer);
                std::string outbufferstring(pszOutBuffer);
                if (outbufferstring.find(recieve) != std::string::npos)
                {
                    printf("\nbuldum bea\n");
                    return TRUE;
                    break;
                }
                else 
                { 
                    printf("\nyarrak\n"); 
                    return FALSE; 
                    break;
                }
            }
            delete[] pszOutBuffer;
            if (!dwDownloaded)
                break;

        } while (dwSize > 0);
    }
    else
    {
        printf("Error %d has occurred.\n", GetLastError());
    }

    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
}


const DWORD md5(LPCWSTR filename)
{
    BOOL bResult = FALSE;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = NULL;
    BYTE rgbFile[BUFSIZE];
    DWORD cbRead = 0;
    BYTE rgbHash[MD5LEN];
    DWORD cbHash = 0;
    CHAR rgbDigits[] = "0123456789abcdef";

    hFile = CreateFile(filename,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        NULL);

    if (INVALID_HANDLE_VALUE == hFile)
    {
        errretval();
        return FALSE;
    }

    if (!CryptAcquireContext(&hProv,
        NULL,
        NULL,
        PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT))
    {
        errretval();
        return FALSE;
        CloseHandle(hFile);
    }

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
    {
        errretval();
        return FALSE;
        CloseHandle(hFile);
        CryptReleaseContext(hProv, 0);
    }

    while (bResult = ReadFile(hFile, rgbFile, BUFSIZE,
        &cbRead, NULL))
    {
        if (0 == cbRead)
        {
            break;
        }

        if (!CryptHashData(hHash, rgbFile, cbRead, 0))
        {
            errretval();
            return FALSE;
            CryptReleaseContext(hProv, 0);
            CryptDestroyHash(hHash);
            CloseHandle(hFile);
        }
    }

    if (!bResult)
    {
        errretval();
        return FALSE;
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CloseHandle(hFile);
    }
    cbHash = MD5LEN;
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {
        CHAR YARRAK;
        CHAR YARRAK2;
        const char UPUZUNYARRAK[MAXCHAR] = " ";
        for (DWORD i = 0; i < cbHash; i++)
        {
            YARRAK = rgbDigits[rgbHash[i] >> 4];
            YARRAK2 = rgbDigits[rgbHash[i] & 0xf];
            sprintf((char*)UPUZUNYARRAK, "%c%c", YARRAK, YARRAK2);
            std::cout << UPUZUNYARRAK;
        }
        std::cout << "\n";
        if (httpreq(L"raw.githubusercontent.com", L"/calomity/md5/main/md5", UPUZUNYARRAK) == TRUE)
        {
            std::cout << "control yapiom bea sus bea!!!";
            return TRUE;
        }
        else
        {
            return FALSE;
        }
    }
    else
    {
        errretval();
        return FALSE;
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
}

void main()
{
    LPCWSTR filename = L"filename.txt";;
    DWORD md5control = md5(filename);
    if (md5control == TRUE)
    {
    }
    else
    {
        std::cout << "yarrak girersin got!" << "\n";
    }
}