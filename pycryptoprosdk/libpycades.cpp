#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include <datetime.h>

#include <string.h>
#include <string>
#include <WinCryptEx.h>
#include <cades.h>

#define MY_ENCODING_TYPE (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define CERT_NAME_STR_TYPE (CERT_X500_NAME_STR | CERT_NAME_STR_CRLF_FLAG)

// start helpers -------------------------------------------------------------------------------------------------------

ALG_ID GetAlgId(const char *algString) {
    std::string str(algString);

    if ("CALG_GR3411" == str)
        return CALG_GR3411;

    if ("CALG_GR3411_2012_256" == str)
        return CALG_GR3411_2012_256;

    if ("CALG_GR3411_2012_512" == str)
        return CALG_GR3411_2012_512;

    return 0;
}

char * GetHashOidByKeyOid(IN char *szKeyOid) {
    if (strcmp(szKeyOid, szOID_CP_GOST_R3410EL) == 0) {
	    return szOID_CP_GOST_R3411;
    }
    else if (strcmp(szKeyOid, szOID_CP_GOST_R3410_12_256) == 0) {
	    return szOID_CP_GOST_R3411_12_256;
    }
    else if (strcmp(szKeyOid, szOID_CP_GOST_R3410_12_512) == 0) {
	    return szOID_CP_GOST_R3411_12_512;
    }

    return NULL;
}

PyObject * FileTimeToPyDateTime(FILETIME *fileTime) {
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

PyObject * GetCertName(CERT_NAME_BLOB name) {
    DWORD cbSize = CertNameToStr(MY_ENCODING_TYPE, &name, CERT_NAME_STR_TYPE, NULL, 0);
    char subject[cbSize];

    CertNameToStr(MY_ENCODING_TYPE, &name, CERT_NAME_STR_TYPE, subject, cbSize);

    return PyUnicode_FromString(subject);
}

PyObject * GetThumbprint(PCCERT_CONTEXT pCertContext) {
    DWORD dataSize;
    CertGetCertificateContextProperty(pCertContext, CERT_HASH_PROP_ID, NULL, &dataSize);

    BYTE hash[dataSize];
    CertGetCertificateContextProperty(pCertContext, CERT_HASH_PROP_ID, hash, &dataSize);

    DWORD hashStringSize;
    CryptBinaryToString(hash, dataSize, CRYPT_STRING_HEX, NULL, &hashStringSize);

    char thumbprint[hashStringSize];

    CryptBinaryToString(hash, dataSize, CRYPT_STRING_HEX, thumbprint, &hashStringSize);

    return PyUnicode_FromString(thumbprint);
}

PyObject * GetCertAltName(PCCERT_CONTEXT pCertContext) {
    PCERT_EXTENSION pExtension;

    pExtension = CertFindExtension(
        szOID_SUBJECT_ALT_NAME2,
        pCertContext->pCertInfo->cExtension,
        pCertContext->pCertInfo->rgExtension
    );

    if (pExtension) {
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

                DWORD cbSize = CertNameToStr(X509_ASN_ENCODING, &directoryName, CERT_NAME_STR_TYPE, NULL, 0);

                char certAltName[cbSize];
                CertNameToStr(X509_ASN_ENCODING, &directoryName, CERT_NAME_STR_TYPE, certAltName, cbSize);

                LocalFree(pvStructInfo);

                return PyUnicode_FromString(certAltName);
            }
        }

        LocalFree(pvStructInfo);
    }

    return Py_None;
}

PyObject * GetCertInfo(PCCERT_CONTEXT pCertContext) {
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

static PyObject * CreateHash(PyObject *self, PyObject *args) {
    const char *message;
    Py_ssize_t length;
    const char *algString;

    if (!PyArg_ParseTuple(args, "y#s", &message, &length, &algString))
        return NULL;

    HCRYPTPROV hProv;
    HCRYPTHASH hHash = 0;
    DWORD cbHash = 0;

    ALG_ID algId = GetAlgId(algString);
    if (!algId) {
        PyErr_Format(PyExc_ValueError, "Unexpected algorithm: %s", algString);
        return NULL;
    }

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT)) {
        PyErr_SetString(PyExc_Exception, "CryptAcquireContext failed");
        return NULL;
    }

    if (!CryptCreateHash(hProv, algId, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        PyErr_SetString(PyExc_Exception, "CryptCreateHash failed");
        return NULL;
    }

    BYTE *pbData = (BYTE*)message;

    if (!CryptHashData(hHash, pbData, length, 0)) {
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);

        PyErr_SetString(PyExc_Exception, "CryptHashData failed");
        return NULL;
    }

    cbHash = 64;
    BYTE rgbHash[cbHash];

    if (!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);

        PyErr_SetString(PyExc_Exception, "CryptGetHashParam failed");
        return NULL;
    }

    DWORD hashStringSize;
    CryptBinaryToString(rgbHash, cbHash, CRYPT_STRING_HEX, NULL, &hashStringSize);

    char hashString[hashStringSize];
    CryptBinaryToString(rgbHash, cbHash, CRYPT_STRING_HEX, hashString, &hashStringSize);

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return PyUnicode_FromString(hashString);
}

static PyObject * GetCertBySubject(PyObject *self, PyObject *args) {
    const char *storeName;
    const char *subject;

    if (!PyArg_ParseTuple(args, "ss", &storeName, &subject))
        return NULL;

    HCERTSTORE hStoreHandle;
    PCCERT_CONTEXT pCertContext = NULL;

    hStoreHandle = CertOpenSystemStore(0, storeName);
    pCertContext = CertFindCertificateInStore(hStoreHandle, MY_ENCODING_TYPE, 0, CERT_FIND_SUBJECT_STR, subject, NULL);

    if (!pCertContext) {
        PyErr_SetString(PyExc_Exception, "Could not find the desired certificate.");
        return NULL;
    }

    PyObject * certInfo = GetCertInfo(pCertContext);

    CertFreeCertificateContext(pCertContext);
    CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG);

    return certInfo;
}

static PyObject * GetCertByThumbprint(PyObject *self, PyObject *args) {
    const char *storeName;
    const char *thumbprint;

    if (!PyArg_ParseTuple(args, "ss", &storeName, &thumbprint))
        return NULL;

    HCERTSTORE hStoreHandle;
    PCCERT_CONTEXT pCertContext = NULL;

    BYTE pDest[20];
    DWORD nOutLen = 20;

    if (!CryptStringToBinary(thumbprint, 40, CRYPT_STRING_HEX, pDest, &nOutLen, 0, 0)) {
        PyErr_SetString(PyExc_Exception, "CryptStringToBinary failed.");
        return NULL;
    }

    CRYPT_HASH_BLOB para;
    para.pbData = pDest;
    para.cbData = nOutLen;

    hStoreHandle = CertOpenSystemStore(0, storeName);
    pCertContext = CertFindCertificateInStore(hStoreHandle, MY_ENCODING_TYPE, 0, CERT_FIND_HASH, &para, NULL);

    if (!pCertContext) {
        CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG);
        PyErr_SetString(PyExc_Exception, "Could not find the desired certificate.");
        return NULL;
    }

    PyObject * certInfo = GetCertInfo(pCertContext);

    CertFreeCertificateContext(pCertContext);
    CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG);

    return certInfo;
}

static PyObject * GetSignerCertFromSignature(PyObject *self, PyObject *args) {
    const char *signature;
    Py_ssize_t signatureLength;

    if (!PyArg_ParseTuple(args, "y#", &signature, &signatureLength))
        return NULL;

    BYTE *pDecodedSignContent = (BYTE*)signature;
    HCRYPTMSG hMsg;
    hMsg = CryptMsgOpenToDecode(MY_ENCODING_TYPE, 0, 0, 0, 0, 0);

    if (!hMsg) {
        PyErr_SetString(PyExc_Exception, "CryptMsgOpenToDecode failed.");
        return NULL;
    }

    if (!CryptMsgUpdate(hMsg, pDecodedSignContent, signatureLength, FALSE)) {
        PyErr_SetString(PyExc_Exception, "CryptMsgUpdate failed.");
        return NULL;
    }

    DWORD cbSignerCertInfo;

    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_CERT_INFO_PARAM, 0, NULL, &cbSignerCertInfo)) {
        PyErr_SetString(PyExc_Exception, "CryptMsgGetParam #1 failed.");
        return NULL;
    }

    PCERT_INFO pSignerCertInfo;
    if (!(pSignerCertInfo = (PCERT_INFO) malloc(cbSignerCertInfo)))
    {
        PyErr_SetString(PyExc_Exception, "Memory allocation failed.");
        return NULL;
    }

    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_CERT_INFO_PARAM, 0, pSignerCertInfo, &cbSignerCertInfo)) {
        PyErr_SetString(PyExc_Exception, "CryptMsgGetParam #2 failed.");
        return NULL;
    }

    HCERTSTORE hStoreHandle;

    hStoreHandle = CertOpenStore(CERT_STORE_PROV_MSG, MY_ENCODING_TYPE, 0, 0, hMsg);
    if (!hStoreHandle) {
        PyErr_SetString(PyExc_Exception, "CertOpenStore failed.");
        return NULL;
    }

    PCCERT_CONTEXT pSignerCertContext;
    pSignerCertContext = CertGetSubjectCertificateFromStore(hStoreHandle, MY_ENCODING_TYPE, pSignerCertInfo);
    if (!pSignerCertContext) {
        PyErr_SetString(PyExc_Exception, "CertGetSubjectCertificateFromStore failed.");
        return NULL;
    }

    if (pSignerCertInfo)
        free(pSignerCertInfo);

    PyObject * certInfo = GetCertInfo(pSignerCertContext);

    CertFreeCertificateContext(pSignerCertContext);
    CryptMsgClose(hMsg);

    return certInfo;
}

static PyObject * InstallCertificate(PyObject *self, PyObject *args) {
    const char *storeName;
    const char *certData;
    Py_ssize_t certDataLength;

    if (!PyArg_ParseTuple(args, "sy#", &storeName, &certData, &certDataLength))
        return NULL;

    BYTE *pDecodedCertData = (BYTE*)certData;
    PCCERT_CONTEXT pCertContext;
    pCertContext = CertCreateCertificateContext(MY_ENCODING_TYPE, pDecodedCertData, certDataLength);

    if (!pCertContext) {
        PyErr_SetString(PyExc_Exception, "Can't create cert context.");
        return NULL;
    }

    HCERTSTORE hStore;
    hStore = CertOpenSystemStore(0, storeName);
    if (!hStore) {
        PyErr_SetString(PyExc_Exception, "CertOpenSystemStore failed.");
        return NULL;
    }

    if (!CertAddCertificateContextToStore(hStore, pCertContext, CERT_STORE_ADD_USE_EXISTING, NULL)) {
        PyErr_SetString(PyExc_Exception, "CertAddCertificateContextToStore failed.");
        return NULL;
    }

    PyObject * certInfo = GetCertInfo(pCertContext);

    CertFreeCertificateContext(pCertContext);
    CertCloseStore(hStore, 0);

    return certInfo;
}

static PyObject * DeleteCertificate(PyObject *self, PyObject *args) {
    const char *storeName;
    const char *thumbprint;

    if (!PyArg_ParseTuple(args, "ss", &storeName, &thumbprint))
        return NULL;

    HCERTSTORE hStore;
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

    hStore = CertOpenSystemStore(0, storeName);

    pCertContext = CertFindCertificateInStore(hStore, MY_ENCODING_TYPE, 0, CERT_FIND_HASH, &para, NULL);

    if (!pCertContext) {
        PyErr_SetString(PyExc_Exception, "Could not find the desired certificate.");
        return NULL;
    };

    if (!CertDeleteCertificateFromStore(pCertContext)){
        PyErr_SetString(PyExc_Exception, "CertDeleteCertificateFromStore failed.");
        return NULL;
    }

    CertFreeCertificateContext(pCertContext);
    CertCloseStore(hStore, 0);

    return Py_None;
}

static PyObject * Verify(PyObject *self, PyObject *args) {
    const char *signature;
    Py_ssize_t signatureLength;

    if (!PyArg_ParseTuple(args, "y#", &signature, &signatureLength))
        return NULL;

    PyObject * res = PyDict_New();

    PyDict_SetItemString(res, "verificationStatus", PyLong_FromLong(-1));
    PyDict_SetItemString(res, "message", Py_None);
    PyDict_SetItemString(res, "error", Py_None);


    CRYPT_VERIFY_MESSAGE_PARA cryptVerifyPara = { sizeof(cryptVerifyPara) };
    cryptVerifyPara.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;

    CADES_VERIFICATION_PARA cadesVerifyPara = { sizeof(cadesVerifyPara) };
    cadesVerifyPara.dwCadesType = CADES_BES;

    CADES_VERIFY_MESSAGE_PARA verifyPara = { sizeof(verifyPara) };

    verifyPara.pVerifyMessagePara = &cryptVerifyPara;
    verifyPara.pCadesVerifyPara = &cadesVerifyPara;

    BYTE *pbSignature = (BYTE*)signature;

    PCADES_VERIFICATION_INFO pVerifyInfo;
    PCRYPT_DATA_BLOB pContent = 0;

    if (!CadesVerifyMessage(&verifyPara, 0, pbSignature, signatureLength, &pContent, &pVerifyInfo)) {
        PyDict_SetItemString(res, "error", PyUnicode_FromFormat("0x%x", GetLastError()));
    }

    if (pVerifyInfo) {
        PyDict_SetItemString(res, "verificationStatus", PyLong_FromLong(pVerifyInfo->dwStatus));
        PyDict_SetItemString(res, "certInfo", GetCertInfo(pVerifyInfo->pSignerCert));

        if (pVerifyInfo->dwStatus == 0) {
            DWORD contentLength = 0;

            if(!CryptBinaryToString(pContent->pbData, pContent->cbData, CRYPT_STRING_BASE64, NULL, &contentLength)) {
                CadesFreeVerificationInfo(pVerifyInfo);
                PyErr_Format(PyExc_ValueError, "CryptBinaryToString #1 failed (error 0x%x).", GetLastError());
                return NULL;
            }

            char base64Content[contentLength+1];

            if(!CryptBinaryToString(pContent->pbData, pContent->cbData, CRYPT_STRING_BASE64, base64Content, &contentLength)) {
                CadesFreeVerificationInfo(pVerifyInfo);
                PyErr_Format(PyExc_ValueError, "CryptBinaryToString #2 failed (error 0x%x).", GetLastError());
                return NULL;
            }

            PyDict_SetItemString(res, "message", PyUnicode_FromString(base64Content));
        }

        CadesFreeVerificationInfo(pVerifyInfo);
    }

    return res;
}

static PyObject * VerifyDetached(PyObject *self, PyObject *args)
{
    const char *message;
    Py_ssize_t messageLength;
    const char *signature;
    Py_ssize_t signatureLength;

    if (!PyArg_ParseTuple(args, "y#y#", &message, &messageLength, &signature, &signatureLength))
        return NULL;

    PyObject * res = PyDict_New();

    PyDict_SetItemString(res, "verificationStatus", PyLong_FromLong(-1));
    PyDict_SetItemString(res, "error", Py_None);

    const BYTE *MessageArray[1];
    DWORD MessageSizeArray[1];

    BYTE *pbToBeSigned = (BYTE*)message;

    MessageArray[0] = pbToBeSigned;
    MessageSizeArray[0] = messageLength;

    CRYPT_VERIFY_MESSAGE_PARA cryptVerifyPara = { sizeof(cryptVerifyPara) };
    cryptVerifyPara.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;

    CADES_VERIFICATION_PARA cadesVerifyPara = { sizeof(cadesVerifyPara) };
    cadesVerifyPara.dwCadesType = CADES_BES;

    CADES_VERIFY_MESSAGE_PARA verifyPara = { sizeof(verifyPara) };

    verifyPara.pVerifyMessagePara = &cryptVerifyPara;
    verifyPara.pCadesVerifyPara = &cadesVerifyPara;

    PCADES_VERIFICATION_INFO pVerifyInfo;

    BYTE *pbSignature = (BYTE*)signature;

    if (!CadesVerifyDetachedMessage(&verifyPara, 0, pbSignature, signatureLength, 1, MessageArray, MessageSizeArray, &pVerifyInfo)) {
        PyDict_SetItemString(res, "error", PyUnicode_FromFormat("0x%x", GetLastError()));
    }

    if (pVerifyInfo) {
        PyDict_SetItemString(res, "verificationStatus", PyLong_FromLong(pVerifyInfo->dwStatus));
        PyDict_SetItemString(res, "certInfo", GetCertInfo(pVerifyInfo->pSignerCert));

        CadesFreeVerificationInfo(pVerifyInfo);
    }

    return res;
}

static PyObject * Sign(PyObject *self, PyObject *args) {
    const char *message;
    Py_ssize_t length;
    const char *thumbprint;
    const char *storeName;
    int detached;

    if (!PyArg_ParseTuple(args, "y#ssi", &message, &length, &thumbprint, &storeName, &detached))
        return NULL;

    HCERTSTORE hStoreHandle;
    PCCERT_CONTEXT pCertContext = NULL;

    BYTE pDest[20];
    DWORD nOutLen = 20;

    if(!CryptStringToBinary(thumbprint, 40, CRYPT_STRING_HEX, pDest, &nOutLen, 0, 0)){
        PyErr_Format(PyExc_ValueError, "CryptStringToBinary #1 failed (error 0x%x).", GetLastError());
        return NULL;
    }

    CRYPT_HASH_BLOB para;
    para.pbData = pDest;
    para.cbData = nOutLen;

    hStoreHandle = CertOpenSystemStore(0, storeName);

    pCertContext = CertFindCertificateInStore(hStoreHandle, MY_ENCODING_TYPE, 0, CERT_FIND_HASH, &para, NULL);

    if (!pCertContext) {
        PyErr_Format(PyExc_ValueError, "CertFindCertificateInStore failed (error 0x%x).", GetLastError());
        return NULL;
    }

    CRYPT_SIGN_MESSAGE_PARA signPara = { sizeof(signPara) };
    signPara.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    signPara.pSigningCert = pCertContext;
    signPara.HashAlgorithm.pszObjId = GetHashOidByKeyOid(pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId);
    signPara.rgpMsgCert = &pCertContext;
    signPara.cMsgCert = 1;

    CADES_SIGN_PARA cadesSignPara = { sizeof(cadesSignPara) };
    cadesSignPara.dwCadesType = CADES_BES;

    CADES_SIGN_MESSAGE_PARA messagePara = { sizeof(messagePara) };
    messagePara.pSignMessagePara = &signPara;
    messagePara.pCadesSignPara = &cadesSignPara;

    PCRYPT_DATA_BLOB pSignedMessage = 0;

    const BYTE *MessageArray[1];
    DWORD MessageSizeArray[1];

    BYTE *pbToBeSigned = (BYTE*)message;

    MessageArray[0] = pbToBeSigned;
    MessageSizeArray[0] = length;

    if(!CadesSignMessage(&messagePara, detached, 1, MessageArray, MessageSizeArray, &pSignedMessage)) {
        PyErr_Format(PyExc_ValueError, "CadesSignMessage failed (error 0x%x).", GetLastError());
        return NULL;
    }

    DWORD base64SignSize = 0;

    if(!CryptBinaryToString( pSignedMessage->pbData, pSignedMessage->cbData, CRYPT_STRING_BASE64, NULL, &base64SignSize)) {
        PyErr_Format(PyExc_ValueError, "CryptBinaryToString #1 failed (error 0x%x).", GetLastError());
        return NULL;
    }

    char base64SignValue[base64SignSize+1];

    if(!CryptBinaryToString(pSignedMessage->pbData, pSignedMessage->cbData, CRYPT_STRING_BASE64, base64SignValue, &base64SignSize)) {
        PyErr_Format(PyExc_ValueError, "CryptBinaryToString #2 failed (error 0x%x).", GetLastError());
        return NULL;
    }

    CertFreeCertificateContext(pCertContext);

    CertCloseStore(
        hStoreHandle,
        CERT_CLOSE_STORE_CHECK_FLAG
    );

    return PyUnicode_FromString(base64SignValue);
}


static PyMethodDef Methods[] = {
    {"create_hash", CreateHash, METH_VARARGS},
    {"get_cert_by_subject", GetCertBySubject, METH_VARARGS},
    {"get_cert_by_thumbprint", GetCertByThumbprint, METH_VARARGS},
    {"get_signer_cert_from_signature", GetSignerCertFromSignature, METH_VARARGS},
    {"install_certificate", InstallCertificate, METH_VARARGS},
    {"delete_certificate", DeleteCertificate, METH_VARARGS},
    {"verify", Verify, METH_VARARGS},
    {"verify_detached", VerifyDetached, METH_VARARGS},
    {"sign", Sign, METH_VARARGS},
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
