from distutils.core import setup, Extension

ziftr_hash_module = Extension('ziftr_hash',
                               sources = ['ziftrmodule.cpp',
                                          'sha3/blake.c',
                                          'sha3/groestl.c',
                                          'sha3/jh.c',
                                          'sha3/keccak.c',
                                          'sha3/skein.c'],
                               include_dirs=['.', './sha3'])

setup (name = 'ziftr_hashs',
       version = '1.0',
       description = 'Bindings for proof of work/stake used by ziftr',
       ext_modules = [ziftr_hash_module])    
