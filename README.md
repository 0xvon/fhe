#### FHE

This is a test impl for Fully Homomorphic Encryption (FHE).
Currently supporting BFV, CKKS.

#### Env

This impl is based on these primitives:

- poly: ...
- crypto: ...

#### Supporting Schemes

- BFV

#### Run

```bash
cargo test test_encryption -- --nocapture
```

#### TODO

- multi-methods
- security analytics (under CCA and CPA)
- benchmark

#### References

- https://inferati.azureedge.net/docs/inferati-fhe-bfv.pdf
- https://github.com/cathieyun/bfv12
- https://github.com/openfheorg/openfhe-python/blob/main/examples/pke/simple-integers.py
