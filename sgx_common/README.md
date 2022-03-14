## Common SGX

Common glue code shared among several SGX projects

_Under development_

#### enclave helper files
`sgx_cryptoall`
`libc_mock/*`

#### native code helper files
`sgx_initenclave`
`sgx_errlist`
`sgx_cryptoall`
`utils`

Code that supports both must be compiled with `-DENABLE_SGX` for the enclave version. Native crypto stuff depends on `libcrypto++`

