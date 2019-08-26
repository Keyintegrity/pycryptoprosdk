#include <string.h>
#include <string>
#include <stdio.h>
#include <WinCryptEx.h>
#include <cades.h>
#include <stdlib.h>

#define MY_ENCODING_TYPE (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define CERT_NAME_STR_TYPE (CERT_X500_NAME_STR | CERT_NAME_STR_CRLF_FLAG)


typedef struct {
    char subject[1024];
    char issuer[1024];
    char notValidBefore[19];
    char notValidAfter[19];
    char thumbprint[41];
    char altName[1024];
} CERTIFICATE_INFO;

typedef struct {
    int verificationStatus;
    char error[1024];
    CERTIFICATE_INFO certInfo;
} VERIFICATION_INFO;


void HandleError(const char *errorMsg)
{
    DWORD err = GetLastError();
    printf("%s; Error number: 0x%x\n", errorMsg, err);
}

void FileTimeToString(FILETIME *fileTime, char *stBuffer)
{
    SYSTEMTIME systemTime;
    FileTimeToSystemTime(fileTime, &systemTime);

    sprintf(
        stBuffer,
        "%d-%02d-%02d %02d:%02d:%02d",
        systemTime.wYear,
        systemTime.wMonth,
        systemTime.wDay,
        systemTime.wHour,
        systemTime.wMinute,
        systemTime.wSecond
    );
}

ALG_ID GetAlgId(const char *algString){
    std::string str(algString);

    if ("CALG_GR3411" == str) {
        return CALG_GR3411;
    }

    if ("CALG_GR3411_2012_256" == str) {
        return CALG_GR3411_2012_256;
    }

    if ("CALG_GR3411_2012_512" == str) {
        return CALG_GR3411_2012_512;
    }

    printf("GetAlgId failed: unexpected algorithm '%s'\n", str.c_str());
    exit(1);
}

CERTIFICATE_INFO GetCertInfo(PCCERT_CONTEXT pCertContext){
    CERTIFICATE_INFO certInfo;

    CertNameToStr(
        X509_ASN_ENCODING,
        &pCertContext->pCertInfo->Subject,
        CERT_NAME_STR_TYPE,
        certInfo.subject,
        1024
    );

    CertNameToStr(
        X509_ASN_ENCODING,
        &pCertContext->pCertInfo->Issuer,
        CERT_NAME_STR_TYPE,
        certInfo.issuer,
        1024
    );

    FileTimeToString(
        &pCertContext->pCertInfo->NotBefore,
        certInfo.notValidBefore
    );

    FileTimeToString(
        &pCertContext->pCertInfo->NotAfter,
        certInfo.notValidAfter
    );

    DWORD dataSize;
    CertGetCertificateContextProperty(
        pCertContext,
        CERT_HASH_PROP_ID,
        NULL,
        &dataSize
    );

    BYTE hash[dataSize];
    CertGetCertificateContextProperty(
        pCertContext,
        CERT_HASH_PROP_ID,
        hash,
        &dataSize
    );

    DWORD hashStringSize;
    CryptBinaryToString(
        hash,
        dataSize,
        CRYPT_STRING_HEX,
        NULL,
        &hashStringSize
    );

    CryptBinaryToString(hash, dataSize, CRYPT_STRING_HEX, certInfo.thumbprint, &hashStringSize);

    PCERT_EXTENSION pExtension;

    pExtension = CertFindExtension(
        szOID_SUBJECT_ALT_NAME2,
        pCertContext->pCertInfo->cExtension,
        pCertContext->pCertInfo->rgExtension
    );

    if (pExtension){
        LPVOID pvStructInfo;
        CERT_ALT_NAME_INFO *pAltNameInfo;
        DWORD cbStructInfo;
        CERT_NAME_BLOB directoryName;

        CryptDecodeObject(
            X509_ASN_ENCODING,
            szOID_SUBJECT_ALT_NAME2,
            pExtension->Value.pbData,
            pExtension->Value.cbData,
            0,
            0,
            &cbStructInfo
        );

        pvStructInfo = LocalAlloc(LMEM_FIXED, cbStructInfo);

        CryptDecodeObject(
            X509_ASN_ENCODING,
            szOID_SUBJECT_ALT_NAME2,
            pExtension->Value.pbData,
            pExtension->Value.cbData,
            0,
            pvStructInfo,
            &cbStructInfo
        );

        pAltNameInfo = (CERT_ALT_NAME_INFO *)pvStructInfo;

        for (DWORD i = 0;  i < pAltNameInfo->cAltEntry; i++) {
            const CERT_ALT_NAME_ENTRY& entry = pAltNameInfo->rgAltEntry[i];

            if (entry.dwAltNameChoice == CERT_ALT_NAME_DIRECTORY_NAME) {
                directoryName = entry._empty_union_.DirectoryName;
                CertNameToStr(
                    X509_ASN_ENCODING,
                    &directoryName,
                    CERT_NAME_STR_TYPE,
                    certInfo.altName,
                    1024
                );
                break;
            }
        }

        LocalFree(pvStructInfo);
    }

    return certInfo;
}

extern "C" {
    bool CreateHash(const char *message, unsigned int length, const char *algString, char *hashArray){
        HCRYPTPROV hProv;
        HCRYPTHASH hHash = 0;
        DWORD cbHash = 0;

        if (!CryptAcquireContext(
            &hProv,
            NULL,
            NULL,
            PROV_GOST_2012_256,
            CRYPT_VERIFYCONTEXT
        )){
            HandleError("CryptAcquireContext failed");
            return false;
        }

        ALG_ID algId = GetAlgId(algString);

        if (!CryptCreateHash(hProv, algId, 0, 0, &hHash)){
            CryptReleaseContext(hProv, 0);
            HandleError("CryptCreateHash failed");
            return false;
        }

        BYTE *pbData = (BYTE*)message;

        if (!CryptHashData(hHash, pbData, length, 0)){
            CryptReleaseContext(hProv, 0);
            CryptDestroyHash(hHash);
            HandleError("CryptHashData failed");
        }

        cbHash = 64;
        BYTE rgbHash[cbHash];

        if (!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)){
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            HandleError("CryptGetHashParam failed");
            return false;
        }

        DWORD i;

        for (i = 0 ; i < cbHash ; i++){
           sprintf(&hashArray[2*i], "%02x ", rgbHash[i]);
        }

        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);

        return true;
    }

    bool GetCertBySubject(const char *storeName, const char *subject, CERTIFICATE_INFO &certInfo){
        HCERTSTORE hStoreHandle;
        PCCERT_CONTEXT pCertContext = NULL;

        hStoreHandle = CertOpenSystemStore(0, storeName);

        pCertContext = CertFindCertificateInStore(
            hStoreHandle,
            PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_STR,
            subject,
            NULL
        );

        if (!pCertContext) {
            printf("Could not find the desired certificate.\n");
            return false;
        }

        certInfo = GetCertInfo(pCertContext);

        CertFreeCertificateContext(pCertContext);

        CertCloseStore(
            hStoreHandle,
            CERT_CLOSE_STORE_CHECK_FLAG
        );

        return true;
    }

    bool GetCertByThumbprint(const char *storeName, const char *thumbprint, CERTIFICATE_INFO &certInfo){
        HCERTSTORE hStoreHandle;
        PCCERT_CONTEXT pCertContext = NULL;

        BYTE pDest[20];
        DWORD nOutLen = 20;

        if(!CryptStringToBinary(thumbprint, 40, CRYPT_STRING_HEX, pDest, &nOutLen, 0, 0)){
            return false;
        }

        CRYPT_HASH_BLOB para;
        para.pbData = pDest;
        para.cbData = nOutLen;

        hStoreHandle = CertOpenSystemStore(0, storeName);

        pCertContext = CertFindCertificateInStore(
            hStoreHandle,
            PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
            0,
            CERT_FIND_HASH,
            &para,
            NULL
        );

        if (!pCertContext) {
            CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG);
            return false;
        }

        certInfo = GetCertInfo(pCertContext);

        CertFreeCertificateContext(pCertContext);

        CertCloseStore(
            hStoreHandle,
            CERT_CLOSE_STORE_CHECK_FLAG
        );

        return true;
    }

    bool InstallCertificate(const char *storeName, const char *certData){
        //certData - строка в base64

        DWORD nDestinationSize = 0;
        if (!CryptStringToBinary(
            certData,
            strlen(certData),
            CRYPT_STRING_BASE64,
            NULL,
            &nDestinationSize,
            0,
            0
        )){
            HandleError("CryptStringToBinary_first failed");
            return false;
        }

        BYTE pDecodedCertData[nDestinationSize];
        if(!CryptStringToBinary(
            certData,
            strlen(certData),
            CRYPT_STRING_BASE64,
            pDecodedCertData,
            &nDestinationSize,
            0,
            0
        )){
            HandleError("CryptStringToBinary_last failed");
            return false;
        };

        PCCERT_CONTEXT pCertContext;

        pCertContext = CertCreateCertificateContext(
            X509_ASN_ENCODING,
            pDecodedCertData,
            nDestinationSize
        );

        if (!pCertContext){
            HandleError("InstallCertificate - can't create cert context");
            return false;
        }

        HCERTSTORE hStore;
        hStore = CertOpenSystemStore(0, storeName);
        if (!hStore){
            HandleError("InstallCertificate - CertOpenSystemStore failed");
            return false;
        }

        if (!CertAddCertificateContextToStore(
                hStore,
                pCertContext,
                CERT_STORE_ADD_USE_EXISTING,
                NULL
            )
        )
        {
            HandleError("InstallCertificate - CertAddCertificateContextToStore failed");
            return false;
        }


        CertFreeCertificateContext(pCertContext);
        CertCloseStore(hStore, 0);

        return true;
    }

    bool DeleteCertificate(const char *storeName, const char *thumbprint){
        HCERTSTORE hStore;
        PCCERT_CONTEXT pCertContext = NULL;

        BYTE pDest[20];
        DWORD nOutLen = 20;

        if(!CryptStringToBinary(thumbprint, 40, CRYPT_STRING_HEX, pDest, &nOutLen, 0, 0)){
            return false;
        }

        CRYPT_HASH_BLOB para;
        para.pbData = pDest;
        para.cbData = nOutLen;

        hStore = CertOpenSystemStore(0, storeName);

        pCertContext = CertFindCertificateInStore(
            hStore,
            PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
            0,
            CERT_FIND_HASH,
            &para,
            NULL
        );

        if (!pCertContext) {
            printf("Could not find the desired certificate.\n");
            return false;
        };

        if (!CertDeleteCertificateFromStore(pCertContext)){
            HandleError("DeleteCertificate - CertDeleteCertificateFromStore failed");
            return false;
        }

        CertFreeCertificateContext(pCertContext);
        CertCloseStore(hStore, 0);

        return true;
    }

    VERIFICATION_INFO VerifyDetached(const char *base64FileContent, const char *base64SignContent){
        VERIFICATION_INFO res;
        res.verificationStatus = -1;
        strcpy(res.error, "");

        //декодируем контент файла
        DWORD nDestinationFileSize = 0;
        if (!CryptStringToBinary(
            base64FileContent,
            strlen(base64FileContent),
            CRYPT_STRING_BASE64,
            NULL,
            &nDestinationFileSize,
            0,
            0
        )){
            HandleError("CryptStringToBinary_file_first failed");
            sprintf(res.error, "0x%x", GetLastError());
            return res;
        }

        BYTE* pDecodedFileContent;
        pDecodedFileContent = (BYTE *) malloc(nDestinationFileSize);

        if(!CryptStringToBinary(
            base64FileContent,
            strlen(base64FileContent),
            CRYPT_STRING_BASE64,
            pDecodedFileContent,
            &nDestinationFileSize,
            0,
            0
        )){
            HandleError("CryptStringToBinary_file_last failed");
            sprintf(res.error, "0x%x", GetLastError());
            return res;
        };

        //декодируем контент подписи
        DWORD nDestinationSignSize = 0;
        if (!CryptStringToBinary(
            base64SignContent,
            strlen(base64SignContent),
            CRYPT_STRING_BASE64,
            NULL,
            &nDestinationSignSize,
            0,
            0
        )){
            HandleError("CryptStringToBinary_sign_first failed");
            sprintf(res.error, "0x%x", GetLastError());
            return res;
        }

        BYTE* pDecodedSignContent;
        pDecodedSignContent = (BYTE *) malloc(nDestinationSignSize);

        if(!CryptStringToBinary(
            base64SignContent,
            strlen(base64SignContent),
            CRYPT_STRING_BASE64,
            pDecodedSignContent,
            &nDestinationSignSize,
            0,
            0
        )){
            HandleError("CryptStringToBinary_sign_last failed");
            sprintf(res.error, "0x%x", GetLastError());
            return res;
        };

        const BYTE *MessageArray[1];
        DWORD MessageSizeArray[1];

        BYTE *pbToBeSigned = (BYTE*)pDecodedFileContent;

        MessageArray[0] = pbToBeSigned;
        MessageSizeArray[0] = nDestinationFileSize;

        CRYPT_VERIFY_MESSAGE_PARA cryptVerifyPara = { sizeof(cryptVerifyPara) };
        cryptVerifyPara.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;

        CADES_VERIFICATION_PARA cadesVerifyPara = { sizeof(cadesVerifyPara) };
        cadesVerifyPara.dwCadesType = CADES_BES;

        CADES_VERIFY_MESSAGE_PARA verifyPara = { sizeof(verifyPara) };

        verifyPara.pVerifyMessagePara = &cryptVerifyPara;
        verifyPara.pCadesVerifyPara = &cadesVerifyPara;

        PCADES_VERIFICATION_INFO pVerifyInfo;

        if (!CadesVerifyDetachedMessage(
            &verifyPara,
            0,
            pDecodedSignContent,
            nDestinationSignSize,
            1,
            MessageArray,
            MessageSizeArray,
            &pVerifyInfo
        )) {
            sprintf(res.error, "0x%x", GetLastError());
        }

        if (pVerifyInfo) {
            res.verificationStatus = pVerifyInfo->dwStatus;
            res.certInfo = GetCertInfo(pVerifyInfo->pSignerCert);

            CadesFreeVerificationInfo(pVerifyInfo);
        }

        if (pDecodedFileContent)
            free(pDecodedFileContent);

        if(pDecodedSignContent)
            free(pDecodedSignContent);

        return res;
    }

    bool GetSignerCertFromSignature(const char *base64SignContent, CERTIFICATE_INFO &certInfo){
        DWORD nDestinationSignSize = 0;

        if (!CryptStringToBinary(
            base64SignContent,
            strlen(base64SignContent),
            CRYPT_STRING_BASE64,
            NULL,
            &nDestinationSignSize,
            0,
            0
        )){
            HandleError("GetSignerCertFromSignature_sign_first failed");
            return false;
        }

        BYTE pDecodedSignContent[nDestinationSignSize];
        if(!CryptStringToBinary(
            base64SignContent,
            strlen(base64SignContent),
            CRYPT_STRING_BASE64,
            pDecodedSignContent,
            &nDestinationSignSize,
            0,
            0
        )){
            HandleError("GetSignerCertFromSignature_sign_last failed");
            return false;
        };

        HCRYPTMSG hMsg;

        hMsg = CryptMsgOpenToDecode(
            MY_ENCODING_TYPE,
            0,
            0,
            0,
            0,
            0
        );

        if (!hMsg){
            HandleError("OpenToDecode failed");
            return false;
        }

        if(!(CryptMsgUpdate(
            hMsg,
            pDecodedSignContent,
            nDestinationSignSize,
            FALSE)))
        {
            HandleError("MsgUpdate failed");
            return false;
        }

        DWORD cbSignerCertInfo;

        if(!CryptMsgGetParam(
            hMsg,
            CMSG_SIGNER_CERT_INFO_PARAM,
            0,
            NULL,
            &cbSignerCertInfo))
        {
            HandleError("Verify SIGNER_CERT_INFO #1 failed.");
            return false;
        }

        PCERT_INFO pSignerCertInfo;
        if(!(pSignerCertInfo = (PCERT_INFO) malloc(cbSignerCertInfo)))
        {
            HandleError("Verify memory allocation failed.");
            return false;
        }

        if(!(CryptMsgGetParam(
            hMsg,
            CMSG_SIGNER_CERT_INFO_PARAM,
            0,
            pSignerCertInfo,
            &cbSignerCertInfo)))
        {
            HandleError("Verify SIGNER_CERT_INFO #2 failed");
            return false;
        }

        HCERTSTORE hStoreHandle;

        hStoreHandle = CertOpenStore(
            CERT_STORE_PROV_MSG,
            MY_ENCODING_TYPE,
            0,
            0,
            hMsg
        );
        if (!hStoreHandle){
            HandleError("Verify open store failed");
            return false;
        }

        PCCERT_CONTEXT pSignerCertContext;
        pSignerCertContext = CertGetSubjectCertificateFromStore(
            hStoreHandle,
            MY_ENCODING_TYPE,
            pSignerCertInfo
        );
        if (!pSignerCertContext){
            HandleError("CertGetSubjectCertificateFromStore failed");
            return false;
        }

        if (pSignerCertInfo)
            free(pSignerCertInfo);

        certInfo = GetCertInfo(pSignerCertContext);
        CertFreeCertificateContext(pSignerCertContext);
        CryptMsgClose(hMsg);

        return true;
    }
}