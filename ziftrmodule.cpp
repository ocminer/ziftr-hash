#include <Python.h>

#include <stdlib.h>
#include <string.h>
#include "uint256.h"

#include "sha3/sph_blake.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"

#include <vector>

#ifdef GLOBALDEFINED
#define GLOBAL
#else
#define GLOBAL extern
#endif

GLOBAL sph_blake512_context    z_blake;
GLOBAL sph_groestl512_context  z_groestl;
GLOBAL sph_jh512_context       z_jh;
GLOBAL sph_keccak512_context   z_keccak;
GLOBAL sph_skein512_context    z_skein;

#define fillz() do { \
    sph_blake512_init(&z_blake); \
    sph_groestl512_init(&z_groestl); \
    sph_jh512_init(&z_jh); \
    sph_keccak512_init(&z_keccak); \
    sph_skein512_init(&z_skein); \
} while (0)

#define ZBLAKE   (memcpy(&ctx_blake,    &z_blake,    sizeof(z_blake)))
#define ZGROESTL (memcpy(&ctx_groestl,  &z_groestl,  sizeof(z_groestl)))
#define ZJH      (memcpy(&ctx_jh,       &z_jh,       sizeof(z_jh)))
#define ZKECCAK  (memcpy(&ctx_keccak,   &z_keccak,   sizeof(z_keccak)))
#define ZSKEIN   (memcpy(&ctx_skein,    &z_skein,    sizeof(z_skein)))

#define ARRAYLEN(array)     (sizeof(array)/sizeof((array)[0]))

//static const int KECCAK  = -1;
static const int BLAKE   = 0;
static const int GROESTL = 1;
static const int JH      = 2;
static const int SKEIN   = 3;

template<typename T1>
inline uint512 HashZR5(const T1 pbegin, const T1 pend)
{
    static unsigned char pblank[1];
    pblank[0] = 0;

    // Pre-computed table of permutations
    static const int arrOrder[][4] = 
    {
        {0, 1, 2, 3},
        {0, 1, 3, 2},
        {0, 2, 1, 3},
        {0, 2, 3, 1},
        {0, 3, 1, 2},
        {0, 3, 2, 1},
        {1, 0, 2, 3},
        {1, 0, 3, 2},
        {1, 2, 0, 3},
        {1, 2, 3, 0},
        {1, 3, 0, 2},
        {1, 3, 2, 0},
        {2, 0, 1, 3},
        {2, 0, 3, 1},
        {2, 1, 0, 3},
        {2, 1, 3, 0},
        {2, 3, 0, 1},
        {2, 3, 1, 0},
        {3, 0, 1, 2},
        {3, 0, 2, 1},
        {3, 1, 0, 2},
        {3, 1, 2, 0},
        {3, 2, 0, 1},
        {3, 2, 1, 0}
    };

    uint512 hash[5];

    sph_blake512_context   ctx_blake;
    sph_groestl512_context ctx_groestl;
    sph_jh512_context      ctx_jh;
    sph_keccak512_context  ctx_keccak;
    sph_skein512_context   ctx_skein;

    const void * pStart = (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0]));
    size_t nSize        = (pend - pbegin) * sizeof(pbegin[0]);
    void * pPutResult   = static_cast<void*>(&hash[0]);

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, pStart, nSize);
    sph_keccak512_close(&ctx_keccak, pPutResult);

    unsigned int nOrder = hash[0].getinnerint(0) % ARRAYLEN(arrOrder);
    
    for (unsigned int i = 0; i < 4; i++)
    {
        pStart     = static_cast<const void*>(&hash[i]);
        nSize      = 64;
        pPutResult = static_cast<void*>(&hash[i+1]);

        switch (arrOrder[nOrder][i])
        {
        case BLAKE:
            sph_blake512_init(&ctx_blake);
            sph_blake512 (&ctx_blake, pStart, nSize);
            sph_blake512_close(&ctx_blake, pPutResult);
            break;
        case GROESTL: 
            sph_groestl512_init(&ctx_groestl);
            sph_groestl512 (&ctx_groestl, pStart, nSize);
            sph_groestl512_close(&ctx_groestl, pPutResult);
            break;
        case JH: 
            sph_jh512_init(&ctx_jh);
            sph_jh512 (&ctx_jh, pStart, nSize);
            sph_jh512_close(&ctx_jh, pPutResult);
            break;
        case SKEIN:
            sph_skein512_init(&ctx_skein);
            sph_skein512 (&ctx_skein, pStart, nSize);
            sph_skein512_close(&ctx_skein, pPutResult);
            break;
        default:
            break;
        }
    }

    return hash[4];
}

static void ziftr_hash(const unsigned char *input, int len , char *output)
{
    uint512 hash = HashZR5(input, input + len);
    memcpy(output, &hash, 64);
}

static PyObject *ziftr_getpowhash(PyObject *self, PyObject *args)
{
    char *output;
    PyObject *value;
#if PY_MAJOR_VERSION >= 3
    PyBytesObject *input;
#else
    PyStringObject *input;
#endif
    if (!PyArg_ParseTuple(args, "S", &input))
        return NULL;
    Py_INCREF(input);
    output = (char *)PyMem_Malloc(64);

#if PY_MAJOR_VERSION >= 3
    ziftr_hash((unsigned char *)PyBytes_AsString((PyObject*) input), Py_SIZE((PyObject*) input), output);
#else
    ziftr_hash((unsigned char *)PyString_AsString((PyObject*) input), Py_SIZE((PyObject*) input), output);
#endif
    Py_DECREF(input);
#if PY_MAJOR_VERSION >= 3
    value = Py_BuildValue("y#", output, 64);
#else
    value = Py_BuildValue("s#", output, 64);
#endif
    PyMem_Free(output);
    return value;
}

static PyMethodDef ZiftrMethods[] = {
    { "getPoWHash", ziftr_getpowhash, METH_VARARGS, "Returns the proof of work hash using ziftr hash" },
    { NULL, NULL, 0, NULL }
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef ZiftrModule = {
    PyModuleDef_HEAD_INIT,
    "ziftr_hash",
    "...",
    -1,
    ZiftrMethods
};

PyMODINIT_FUNC PyInit_ziftr_hash(void) {
    return PyModule_Create(&ZiftrModule);
}

#else

PyMODINIT_FUNC initziftr_hash(void) {
    (void) Py_InitModule("ziftr_hash", ZiftrMethods);
}
#endif

