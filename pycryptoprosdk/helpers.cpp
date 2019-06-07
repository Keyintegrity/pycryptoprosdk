//#include "helpers.h"
//
//ALG_ID GetAlgId(const char *algString)
//{
//    std::string str(algString);
//
//    if ("CALG_GR3411" == str) {
//        return CALG_GR3411;
//    }
//
//    if ("CALG_GR3411_2012_256" == str) {
//        return CALG_GR3411_2012_256;
//    }
//
//    if ("CALG_GR3411_2012_512" == str) {
//        return CALG_GR3411_2012_512;
//    }
//
//    return 0;
//}
//
//PyObject * FileTimeToPyDateTime(FILETIME *fileTime)
//{
//    PyDateTime_IMPORT;
//
//    SYSTEMTIME systemTime;
//    FileTimeToSystemTime(fileTime, &systemTime);
//
//    return PyDateTime_FromDateAndTime(
//        systemTime.wYear,
//        systemTime.wMonth,
//        systemTime.wDay,
//        systemTime.wHour,
//        systemTime.wMinute,
//        systemTime.wSecond,
//        0
//    );
//}