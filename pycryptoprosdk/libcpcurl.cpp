#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include <string>
#include <curl/curl.h>


static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

void SetHeaders(CURL *curl, PyObject *headers) {
    if (headers != Py_None) {
        struct curl_slist *chunk = NULL;
        PyObject *headerItem;
        char *headerName;
        char *headerValue;
        int i;

        for (i = 0; i < PyList_Size(headers); i++) {
            headerItem = PyList_GetItem(headers, i);
            headerName = PyBytes_AsString(PyList_GetItem(headerItem, 0));
            headerValue = PyBytes_AsString(PyList_GetItem(headerItem, 1));

            std::string s = "";
            s += headerName;
            s += ": ";
            s += headerValue;

            chunk = curl_slist_append(chunk, s.c_str());
        }

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
    };
}

static PyObject * Request(PyObject *self, PyObject *args) {
    const char *method;
    const char *url;
    PyObject *data;
    PyObject *files;
    PyObject *headers;
    int verbose;

    if (!PyArg_ParseTuple(args, "ssOOOi", &method, &url, &data, &files, &headers, &verbose))
        return NULL;

    struct curl_httppost* post = NULL;
    struct curl_httppost* last = NULL;

    CURL *curl = curl_easy_init();

    if (!curl) {
        PyErr_SetString(PyExc_Exception, "curl_easy_init failed");
        return NULL;
    }

    if (verbose)
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);

    std::string readBuffer;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

    SetHeaders(curl, headers);

    if (std::string("POST") == method) {
        Py_ssize_t i, fileSize;
        PyObject *dataItem;
        PyObject *fileItem;

        char *fieldName;
        char *value;
        char *fileName;
        char *fileContent;

        if (data != Py_None) {
            if (PyList_Check(data)) {
                for (i = 0; i < PyList_Size(data); i++) {
                    dataItem = PyList_GetItem(data, i);
                    fieldName = PyBytes_AsString(PyList_GetItem(dataItem, 0));
                    value = PyBytes_AsString(PyList_GetItem(dataItem, 1));

                    curl_formadd(&post, &last, CURLFORM_COPYNAME, fieldName, CURLFORM_COPYCONTENTS, value,CURLFORM_END);
                }
                curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);
            } else if (PyBytes_Check(data)) {
                char *queryString = PyBytes_AsString(data);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, queryString);
            } else {
                PyErr_SetString(PyExc_Exception, "The argument 'data' must be of type 'list' or 'bytes'");
                return NULL;
            }
        }

        if (files != Py_None) {
            if (!PyList_Check(files)) {
                PyErr_SetString(PyExc_Exception, "The argument 'files' must be of type 'list'");
                return NULL;
            }
            for (i = 0; i < PyList_Size(files); i++) {
                fileItem = PyList_GetItem(files, i);
                fieldName = PyBytes_AsString(PyList_GetItem(fileItem, 0));
                fileName = PyBytes_AsString(PyList_GetItem(fileItem, 1));
                fileContent = PyBytes_AsString(PyList_GetItem(fileItem, 2));
                fileSize = PyBytes_Size(PyList_GetItem(fileItem, 2));

                if (PyList_Size(fileItem) == 4){
                    curl_formadd(
                        &post, &last,
                        CURLFORM_COPYNAME, fieldName,
                        CURLFORM_BUFFER, fileName,
                        CURLFORM_BUFFERPTR, fileContent,
                        CURLFORM_BUFFERLENGTH, fileSize,
                        CURLFORM_CONTENTTYPE, PyBytes_AsString(PyList_GetItem(fileItem, 3)),
                        CURLFORM_END
                    );
                } else {
                    curl_formadd(
                        &post, &last,
                        CURLFORM_COPYNAME, fieldName,
                        CURLFORM_BUFFER, fileName,
                        CURLFORM_BUFFERPTR, fileContent,
                        CURLFORM_BUFFERLENGTH, fileSize,
                        CURLFORM_END
                    );
                }
            }
            curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);
        }
    }

    CURLcode performCode = curl_easy_perform(curl);

    long response_code;
    PyObject * result = PyDict_New();

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    PyDict_SetItemString(result, "status_code", PyLong_FromLong(response_code));
    PyDict_SetItemString(result, "perform_code", PyLong_FromLong(performCode));
    PyDict_SetItemString(result, "content", PyUnicode_FromString(readBuffer.c_str()));

    curl_easy_cleanup(curl);

    if (post)
        curl_formfree(post);

    return result;
}

static PyMethodDef Methods[] = {
    {"request", Request, METH_VARARGS},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef libcpcurl = {
    PyModuleDef_HEAD_INIT,
    "libcpcurl",
    NULL,
    -1,
    Methods
};

PyMODINIT_FUNC PyInit_libcpcurl(void)
{
    PyObject *m;
    m = PyModule_Create(&libcpcurl);
    return m;
}
