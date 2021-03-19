#include <windows.h>
#include <cstdio>
#include <iostream>
#include <bcrypt.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define RSA_KEY_SIZE   2048
#define RSA_BLOCK_SIZE 128

BYTE* privateKey;
BYTE* publicKey;
BYTE* encryptedBuffer;
DWORD privateKeySize = 0;
DWORD publicKeySize  = 0;
DWORD encryptedBufferSize = 0;
std::string rawInput;

void decryptData();
void encryptData();
void generateKeyPair();

void printMemory(void* addr, int len){
    for(int i=0;i<len;++i){
        printf("%02x ", ((BYTE*)addr)[i]);
    }
    printf("\n");
}

int main(int argc, char* argv[]){
    std::cout << "Enter your message to encrypt:\n";
    std::getline(std::cin, rawInput);
    generateKeyPair();
    encryptData();
    if(encryptedBuffer){
        decryptData();
    }
    if(privateKey){ delete [] privateKey; }
    if(publicKey){  delete [] publicKey; }
    if(encryptedBuffer){ delete [] encryptedBuffer; }
    return 0;
}

void decryptData(){
    BCRYPT_ALG_HANDLE hAlgo = NULL;
    BCRYPT_KEY_HANDLE hKey  = NULL;
    DWORD decryptedBufferSize = 0, result;
    BYTE* decryptedBuffer;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlgo, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if(!NT_SUCCESS(status)){
        printf("Failed to open bcrypt algorithm: 0x%x\n", status);
        goto Ldecrypt_cleanup;
    }

    status = BCryptImportKeyPair(hAlgo, NULL, BCRYPT_RSAPRIVATE_BLOB,
                                 &hKey, privateKey, privateKeySize, BCRYPT_NO_KEY_VALIDATION);
    if(!NT_SUCCESS(status)){
        printf("Failed to import private key (0x%x)\n", status);
        goto Ldecrypt_cleanup;
    }
    status = BCryptDecrypt(hKey, encryptedBuffer, encryptedBufferSize,
                           NULL, NULL, 0, NULL, 0, &decryptedBufferSize, BCRYPT_PAD_PKCS1);
    if(!NT_SUCCESS(status)){
        printf("Failed to get required buffer size for decryption (0x%x)\n", status);
        goto Ldecrypt_cleanup;
    }

    decryptedBuffer = new BYTE [decryptedBufferSize];
    if(decryptedBuffer == NULL){
        printf("Failed to allocate memory for decrypted data (0x%x)\n", GetLastError());
        goto Ldecrypt_cleanup;
    }

    status = BCryptDecrypt(hKey, encryptedBuffer, encryptedBufferSize, NULL, NULL, 0,
                           decryptedBuffer, decryptedBufferSize, &result, BCRYPT_PAD_PKCS1);
    if(!NT_SUCCESS(status)){
        printf("Failed to decrypt buffer (0x%x)\n", status);
        goto Ldecrypt_cleanup;
    }

    printf("Decrypted buffer:\n==== START ====\n");
    printMemory(decryptedBuffer, decryptedBufferSize);
    printf("==== EOF ====\n");
    printf("Done; %d bytes decrypted\n\n");

Ldecrypt_cleanup:
    if(decryptedBuffer){ delete [] decryptedBuffer; }
    if(hKey){  BCryptDestroyKey(hKey); }
    if(hAlgo){ BCryptCloseAlgorithmProvider(hAlgo, 0); }
}

void encryptData(){
    BCRYPT_ALG_HANDLE hAlgo  = NULL;
    BCRYPT_KEY_HANDLE hKey   = NULL;
    BYTE* inputData;
    ULONG inputSize = 0, result;
    NTSTATUS status;

    int slen  = rawInput.length();
    inputSize = slen;
    inputData = new BYTE [inputSize];
    for(int i=0;i<slen;++i){ inputData[i] = rawInput[i]; }

    printf("Raw Data:\n==== Start ====\n");
    printMemory(inputData, inputSize);
    printf("==== EOF ====\n\n");

    status = BCryptOpenAlgorithmProvider(&hAlgo, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if(!NT_SUCCESS(status)){
        printf("Failed to get algorithm provider (0x%x)\n", status);
        goto Lencrypt_cleanup;
    }
    printf("Algo handle: 0x%x\n", hAlgo);
    status = BCryptImportKeyPair(hAlgo, NULL, BCRYPT_RSAPUBLIC_BLOB,
                                 &hKey, publicKey, publicKeySize, BCRYPT_NO_KEY_VALIDATION);
    if(!NT_SUCCESS(status)){
        printf("Failed to import public key (0x%x)\n", status);
        goto Lencrypt_cleanup;
    }
    status = BCryptEncrypt(hKey, inputData, inputSize, NULL, NULL,
                           0, NULL, 0, &encryptedBufferSize, BCRYPT_PAD_PKCS1);
    if(!NT_SUCCESS(status)){
        printf("Failed to get required size for encryption buffer (0x%x)\n", status);
        goto Lencrypt_cleanup;
    }

    encryptedBuffer = new BYTE [encryptedBufferSize];
    status = BCryptEncrypt(hKey, inputData, inputSize, NULL, NULL, 0,
                           encryptedBuffer, encryptedBufferSize, &result, BCRYPT_PAD_PKCS1);
    if(!NT_SUCCESS(status)){
        printf("Failed to encrypt data (0x%x)\n", status);
        goto Lencrypt_cleanup;
    }
    printf("Encrypted Data:\n==== Start ====\n");
    printMemory(encryptedBuffer, encryptedBufferSize);
    printf("==== EOF ====\n");
    printf("Done; %d bytes encrypted\n\n");

Lencrypt_cleanup:
    if(inputData){ delete [] inputData; }
    if(hKey){  BCryptDestroyKey(hKey); }
    if(hAlgo){ BCryptCloseAlgorithmProvider(hAlgo, 0); }
}

void generateKeyPair(){
    BCRYPT_ALG_HANDLE hAlgo  = NULL;
    BCRYPT_KEY_HANDLE hKey   = NULL;
    NTSTATUS status;

    BYTE *buffer = NULL, *buffer2 = NULL;
    ULONG bufferSize = 0, bufferSize2 = 0, result = 0;

    status = BCryptOpenAlgorithmProvider(&hAlgo, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if(!NT_SUCCESS(status)){
        printf("Failed to get algorithm provider (0x%x)\n", status);
        goto Lgenerate_cleanup;
    }

    status = BCryptGenerateKeyPair(hAlgo, &hKey, RSA_KEY_SIZE, 0);
    if(!NT_SUCCESS(status)){
        printf("Failed to generate key pair (0x%x)\n", status);
        goto Lgenerate_cleanup;
    }
    printf("Key handle: 0x%x\n", hKey);

    status = BCryptFinalizeKeyPair(hKey, 0);
    if(!NT_SUCCESS(status)){
        printf("Failed to finalized key pair (0x%x)\n", status);
        goto Lgenerate_cleanup;
    }

    // Export private key
    status = BCryptExportKey(hKey, NULL, BCRYPT_RSAPRIVATE_BLOB,
                             NULL, 0, &bufferSize, 0);
    if(!NT_SUCCESS(status)){
        printf("Failed to get required buffer size for private key (0x%x)\n", status);
        goto Lgenerate_cleanup;
    }

    buffer = new BYTE [bufferSize];
    status = BCryptExportKey(hKey, NULL, BCRYPT_RSAPRIVATE_BLOB,
                             buffer, bufferSize, &result, 0);
    if(!NT_SUCCESS(status)){
        printf("Failed to export private key (0x%x)\n", status);
        goto Lgenerate_cleanup;
    }
    printf("==== BEGIN PRIVATE KEY ====\n");
    printMemory(buffer, bufferSize);
    printf("==== END PRIVATE KEY ====\n");
    printf("Done; %d bytes copied\n\n", result);

    // Export private key
    status = BCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB,
                             NULL, 0, &bufferSize2, 0);
    if(!NT_SUCCESS(status)){
        printf("Failed to get required buffer size for public key (0x%x)\n", status);
        goto Lgenerate_cleanup;
    }

    buffer2 = new BYTE [bufferSize2];
    status = BCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB,
                             buffer2, bufferSize2, &result, 0);
    if(!NT_SUCCESS(status)){
        printf("Failed to export public key (0x%x)\n", status);
        goto Lgenerate_cleanup;
    }
    printf("==== BEGIN PUBLIC KEY ====\n");
    printMemory(buffer2, bufferSize2);
    printf("==== END PUBLIC KEY ====\n");
    printf("Done; %d bytes copied\n\n", result);

    privateKey = new BYTE [bufferSize];
    publicKey  = new BYTE [bufferSize2];
    privateKeySize = bufferSize;
    publicKeySize  = bufferSize2;
    memcpy(privateKey, buffer, bufferSize);
    memcpy(publicKey, buffer2, bufferSize2);
Lgenerate_cleanup:
    if(buffer){ delete [] buffer; }
    if(buffer2){ delete [] buffer2; }
    if(hKey){  BCryptDestroyKey(hKey); }
    if(hAlgo){ BCryptCloseAlgorithmProvider(hAlgo, 0); }
}
