#include <stdio.h>
#include <WinCryptEx.h>
#include <cades.h>
#include <string.h>
#include <stdlib.h>

#define GR3411LEN  64
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)


typedef struct {
    char subject[1024];
    char issuer[1024];
    char notValidBefore[19];
    char notValidAfter[19];
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

CERTIFICATE_INFO GetCertInfo(PCERT_INFO pCertInfo){
    CERTIFICATE_INFO certInfo;

    CertNameToStr(
        X509_ASN_ENCODING,
        &pCertInfo->Subject,
        CERT_X500_NAME_STR,
        certInfo.subject,
        1024
    );

    CertNameToStr(
        X509_ASN_ENCODING,
        &pCertInfo->Issuer,
        CERT_X500_NAME_STR,
        certInfo.issuer,
        1024
    );

    FileTimeToString(
        &pCertInfo->NotBefore,
        certInfo.notValidBefore
    );

    FileTimeToString(
        &pCertInfo->NotAfter,
        certInfo.notValidAfter
    );

    return certInfo;
}

extern "C" {
    bool CreateHash(const char *message, unsigned int length, char *hashArray){
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

        if (!CryptCreateHash(hProv, CALG_GR3411, 0, 0, &hHash)){
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

        BYTE rgbHash[GR3411LEN];
        cbHash = GR3411LEN;

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

        certInfo = GetCertInfo(pCertContext->pCertInfo);

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

        certInfo = GetCertInfo(pCertContext->pCertInfo);

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

        BYTE pDecodedFileContent[nDestinationFileSize];
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
            res.certInfo = GetCertInfo(pVerifyInfo->pSignerCert->pCertInfo);

            CadesFreeVerificationInfo(pVerifyInfo);
        }

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
            NULL,
            NULL,
            NULL
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
            NULL,
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

        certInfo = GetCertInfo(pSignerCertContext->pCertInfo);
        CertFreeCertificateContext(pSignerCertContext);
        CryptMsgClose(hMsg);

        return true;
    }
}