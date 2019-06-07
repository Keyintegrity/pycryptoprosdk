#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include <datetime.h>

#include <string.h>
#include <string>
#include <WinCryptEx.h>
#include <cades.h>

#include "helpers.h"

#define MY_ENCODING_TYPE (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

// start helpers -------------------------------------------------------------------------------------------------------

ALG_ID GetAlgId(const char *algString)
{
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

    return 0;
}

PyObject * FileTimeToPyDateTime(FILETIME *fileTime)
{
    PyDateTime_IMPORT;

    SYSTEMTIME systemTime;
    FileTimeToSystemTime(fileTime, &systemTime);

    return PyDateTime_FromDateAndTime(
        systemTime.wYear,
        systemTime.wMonth,
        systemTime.wDay,
        systemTime.wHour,
        systemTime.wMinute,
        systemTime.wSecond,
        0
    );
}

PyObject * GetCertName(CERT_NAME_BLOB name)
{
    DWORD cbSize = CertNameToStr(
        X509_ASN_ENCODING, // pCertContext->dwCertEncodingType,
        &name,
        CERT_X500_NAME_STR,
        NULL,
        0
    );

    char subject[cbSize];
    CertNameToStr(
        X509_ASN_ENCODING,
        &name,
        CERT_X500_NAME_STR,
        subject,
        cbSize
    );

    return PyUnicode_FromString(subject);
}

PyObject * GetThumbprint(PCCERT_CONTEXT pCertContext)
{
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

    char thumbprint[hashStringSize];

    CryptBinaryToString(
        hash,
        dataSize,
        CRYPT_STRING_HEX,
        thumbprint,
        &hashStringSize
    );

    return PyUnicode_FromString(thumbprint);
}

PyObject * GetCertAltName(PCCERT_CONTEXT pCertContext)
{
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

                DWORD cbSize = CertNameToStr(
                    X509_ASN_ENCODING,
                    &directoryName,
                    CERT_X500_NAME_STR,
                    NULL,
                    0
                );

                char certAltName[cbSize];
                CertNameToStr(
                    X509_ASN_ENCODING,
                    &directoryName,
                    CERT_X500_NAME_STR,
                    certAltName,
                    cbSize
                );

                LocalFree(pvStructInfo);

                return PyUnicode_FromString(certAltName);
            }
        }

        LocalFree(pvStructInfo);
    }

    return Py_None;
}

PyObject * GetCertInfo(PCCERT_CONTEXT pCertContext){
    PyObject * certInfo = PyDict_New();

    PyDict_SetItemString(certInfo, "subject", GetCertName(pCertContext->pCertInfo->Subject));
    PyDict_SetItemString(certInfo, "issuer", GetCertName(pCertContext->pCertInfo->Issuer));
    PyDict_SetItemString(certInfo, "notValidBefore", FileTimeToPyDateTime(&pCertContext->pCertInfo->NotBefore));
    PyDict_SetItemString(certInfo, "notValidAfter", FileTimeToPyDateTime(&pCertContext->pCertInfo->NotAfter));
    PyDict_SetItemString(certInfo, "thumbprint", GetThumbprint(pCertContext));
    PyDict_SetItemString(certInfo, "altName", GetCertAltName(pCertContext));

    return certInfo;
}

// end helpers ---------------------------------------------------------------------------------------------------------

static PyObject * CreateHash(PyObject *self, PyObject *args)
{
    const char *message;
    const char *algString;

    if (!PyArg_ParseTuple(args, "s*s", &message, &algString))
        return NULL;

    HCRYPTPROV hProv;
    HCRYPTHASH hHash = 0;
    DWORD cbHash = 0;

    ALG_ID algId = GetAlgId(algString);
    if (!algId){
        PyErr_Format(PyExc_ValueError, "Unexpected algorithm: %s", algString);
        return NULL;
    }

    if (!CryptAcquireContext(
        &hProv,
        NULL,
        NULL,
        PROV_GOST_2012_256,
        CRYPT_VERIFYCONTEXT
    )){
        PyErr_SetString(PyExc_Exception, "CryptAcquireContext failed");
        return NULL;
    }

    if (!CryptCreateHash(hProv, algId, 0, 0, &hHash)){
        CryptReleaseContext(hProv, 0);
        PyErr_SetString(PyExc_Exception, "CryptCreateHash failed");
        return NULL;
    }

    BYTE *pbData = (BYTE*)message;

    if (!CryptHashData(hHash, pbData, strlen(message), 0)){
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);

        PyErr_SetString(PyExc_Exception, "CryptHashData failed");
        return NULL;
    }

    cbHash = 64;
    BYTE rgbHash[cbHash];

    if (!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)){
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);

        PyErr_SetString(PyExc_Exception, "CryptGetHashParam failed");
        return NULL;
    }

    DWORD hashStringSize;
    CryptBinaryToString(
        rgbHash,
        cbHash,
        CRYPT_STRING_HEX,
        NULL,
        &hashStringSize
    );

    char hashString[hashStringSize];
    CryptBinaryToString(
        rgbHash,
        cbHash,
        CRYPT_STRING_HEX,
        hashString,
        &hashStringSize
    );

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return PyUnicode_FromString(hashString);
}

static PyObject * GetCertBySubject(PyObject *self, PyObject *args)
{
    const char *storeName;
    const char *subject;

    if (!PyArg_ParseTuple(args, "ss", &storeName, &subject))
        return NULL;

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
        PyErr_SetString(PyExc_Exception, "Could not find the desired certificate.");
        return NULL;
    }

    PyObject * certInfo = GetCertInfo(pCertContext);

    CertFreeCertificateContext(pCertContext);

    CertCloseStore(
        hStoreHandle,
        CERT_CLOSE_STORE_CHECK_FLAG
    );

    return certInfo;
}

static PyObject * GetCertByThumbprint(PyObject *self, PyObject *args)
{
    const char *storeName;
    const char *thumbprint;

    if (!PyArg_ParseTuple(args, "ss", &storeName, &thumbprint))
        return NULL;

    HCERTSTORE hStoreHandle;
    PCCERT_CONTEXT pCertContext = NULL;

    BYTE pDest[20];
    DWORD nOutLen = 20;

    if(!CryptStringToBinary(thumbprint, 40, CRYPT_STRING_HEX, pDest, &nOutLen, 0, 0)){
        PyErr_SetString(PyExc_Exception, "CryptStringToBinary failed.");
        return NULL;
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
        PyErr_SetString(PyExc_Exception, "Could not find the desired certificate.");
        return NULL;
    }

    PyObject * certInfo = GetCertInfo(pCertContext);

    CertFreeCertificateContext(pCertContext);

    CertCloseStore(
        hStoreHandle,
        CERT_CLOSE_STORE_CHECK_FLAG
    );

    return certInfo;
}

static PyObject * GetSignerCertFromSignature(PyObject *self, PyObject *args)
{
    const char *base64SignContent;

    if (!PyArg_ParseTuple(args, "s", &base64SignContent))
        return NULL;

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
        PyErr_SetString(PyExc_Exception, "CryptStringToBinary_first failed");
        return NULL;
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
        PyErr_SetString(PyExc_Exception, "CryptStringToBinary_last failed");
        return NULL;
    };

    HCRYPTMSG hMsg;

    hMsg = CryptMsgOpenToDecode(MY_ENCODING_TYPE, 0, 0, 0, 0, 0);

    if (!hMsg){
        PyErr_SetString(PyExc_Exception, "CryptMsgOpenToDecode failed");
        return NULL;
    }

    if(!(CryptMsgUpdate(
        hMsg,
        pDecodedSignContent,
        nDestinationSignSize,
        FALSE)))
    {
        PyErr_SetString(PyExc_Exception, "CryptMsgUpdate failed");
        return NULL;
    }

    DWORD cbSignerCertInfo;

    if(!CryptMsgGetParam(
        hMsg,
        CMSG_SIGNER_CERT_INFO_PARAM,
        0,
        NULL,
        &cbSignerCertInfo))
    {
        PyErr_SetString(PyExc_Exception, "CryptMsgGetParam #1 failed.");
        return NULL;
    }

    PCERT_INFO pSignerCertInfo;
    if (!(pSignerCertInfo = (PCERT_INFO) malloc(cbSignerCertInfo)))
    {
        PyErr_SetString(PyExc_Exception, "Verify memory allocation failed.");
        return NULL;
    }

    if (!(CryptMsgGetParam(
            hMsg,
            CMSG_SIGNER_CERT_INFO_PARAM,
            0,
            pSignerCertInfo,
            &cbSignerCertInfo
        )))
    {
        PyErr_SetString(PyExc_Exception, "CryptMsgGetParam #2 failed.");
        return NULL;
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
        PyErr_SetString(PyExc_Exception, "CertOpenStore failed.");
        return NULL;
    }

    PCCERT_CONTEXT pSignerCertContext;
    pSignerCertContext = CertGetSubjectCertificateFromStore(
        hStoreHandle,
        MY_ENCODING_TYPE,
        pSignerCertInfo
    );
    if (!pSignerCertContext){
        PyErr_SetString(PyExc_Exception, "CertGetSubjectCertificateFromStore failed");
        return NULL;
    }

    if (pSignerCertInfo)
        free(pSignerCertInfo);

    PyObject * certInfo = GetCertInfo(pSignerCertContext);

    CertFreeCertificateContext(pSignerCertContext);
    CryptMsgClose(hMsg);

    return certInfo;
}

static PyObject * InstallCertificate(PyObject *self, PyObject *args)
{
    const char *storeName;
    const char *certData; // строка в base64

    if (!PyArg_ParseTuple(args, "ss", &storeName, &certData))
        return NULL;

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
        PyErr_SetString(PyExc_Exception, "CryptStringToBinary #1 failed");
        return NULL;
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
        PyErr_SetString(PyExc_Exception, "CryptStringToBinary #2 failed");
        return NULL;
    };

    PCCERT_CONTEXT pCertContext;
    pCertContext = CertCreateCertificateContext(
        X509_ASN_ENCODING,
        pDecodedCertData,
        nDestinationSize
    );

    if (!pCertContext){
        PyErr_SetString(PyExc_Exception, "Can't create cert context");
        return NULL;
    }

    HCERTSTORE hStore;
    hStore = CertOpenSystemStore(0, storeName);
    if (!hStore){
        PyErr_SetString(PyExc_Exception, "CertOpenSystemStore failed");
        return NULL;
    }

    if (!CertAddCertificateContextToStore(
            hStore,
            pCertContext,
            CERT_STORE_ADD_USE_EXISTING,
            NULL
        )
    )
    {
        PyErr_SetString(PyExc_Exception, "CertAddCertificateContextToStore failed");
        return NULL;
    }

    PyObject * certInfo = GetCertInfo(pCertContext);

    CertFreeCertificateContext(pCertContext);
    CertCloseStore(hStore, 0);

    return certInfo;
}

static PyObject * DeleteCertificate(PyObject *self, PyObject *args)
{
    const char *storeName;
    const char *thumbprint;

    if (!PyArg_ParseTuple(args, "ss", &storeName, &thumbprint))
        return NULL;

    HCERTSTORE hStore;
    PCCERT_CONTEXT pCertContext = NULL;

    BYTE pDest[20];
    DWORD nOutLen = 20;

    if(!CryptStringToBinary(thumbprint, 40, CRYPT_STRING_HEX, pDest, &nOutLen, 0, 0)){
        PyErr_SetString(PyExc_Exception, "CryptStringToBinary failed");
        return NULL;
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
        PyErr_SetString(PyExc_Exception, "Could not find the desired certificate.");
        return NULL;
    };

    if (!CertDeleteCertificateFromStore(pCertContext)){
        PyErr_SetString(PyExc_Exception, "CertDeleteCertificateFromStore failed");
        return NULL;
    }

    CertFreeCertificateContext(pCertContext);
    CertCloseStore(hStore, 0);

    return Py_None;
}

static PyObject * VerifyDetached(PyObject *self, PyObject *args)
{
    const char *base64FileContent;
    const char *base64SignContent;

    if (!PyArg_ParseTuple(args, "ss", &base64FileContent, &base64SignContent))
        return NULL;

    PyObject * res = PyDict_New();
    PyObject * error = Py_None;

    PyDict_SetItemString(res, "verificationStatus", PyLong_FromLong(-1));
    PyDict_SetItemString(res, "error", error);

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
        PyErr_Format(PyExc_Exception, "CryptStringToBinary #1 failed (Error: 0x%x).", GetLastError());
        return NULL;
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
        PyErr_Format(PyExc_Exception, "CryptStringToBinary #2 failed (Error: 0x%x).", GetLastError());
        return NULL;
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
        PyErr_Format(PyExc_Exception, "CryptStringToBinary #3 failed (Error: 0x%x).", GetLastError());
        return NULL;
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
        PyErr_Format(PyExc_Exception, "CryptStringToBinary #4 failed (Error: 0x%x).", GetLastError());
        return NULL;
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
        error = PyUnicode_FromFormat("0x%x", GetLastError());
    }

    if (pVerifyInfo) {
        PyDict_SetItemString(res, "error", error);
        PyDict_SetItemString(res, "verificationStatus", PyLong_FromLong(pVerifyInfo->dwStatus));
        PyDict_SetItemString(res, "certInfo", GetCertInfo(pVerifyInfo->pSignerCert));

        CadesFreeVerificationInfo(pVerifyInfo);
    }

    if (pDecodedFileContent)
        free(pDecodedFileContent);

    if(pDecodedSignContent)
        free(pDecodedSignContent);

    return res;
}


static PyMethodDef Methods[] = {
    {"create_hash",  CreateHash, METH_VARARGS},
    {"get_cert_by_subject",  GetCertBySubject, METH_VARARGS},
    {"get_cert_by_thumbprint",  GetCertByThumbprint, METH_VARARGS},
    {"get_signer_cert_from_signature",  GetSignerCertFromSignature, METH_VARARGS},
    {"install_certificate",  InstallCertificate, METH_VARARGS},
    {"delete_certificate",  DeleteCertificate, METH_VARARGS},
    {"verify_detached",  VerifyDetached, METH_VARARGS},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef libpycades = {
    PyModuleDef_HEAD_INIT,
    "libpycades",
    NULL,
    -1,
    Methods
};

PyMODINIT_FUNC PyInit_libpycades(void)
{
    PyObject *m;
    m = PyModule_Create(&libpycades);
    return m;
}
