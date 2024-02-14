This is a memo to impl BFV scheme.

The papers are [Brakerski '12](https://eprint.iacr.org/2012/078.pdf) and [Fan, Vercauteren '12](https://eprint.iacr.org/2012/144.pdf).

#### Security Parameter

- t: plain-text modulus
- q: cipher-text moduls
- std_dev: standard deviation for generating the error
- n: degree of polynomial for encoding and encrypting messages

#### Primitives

BFV includes the following primitives:

- ParamGen($\lambda$) -> Params
- KeyGen($Params$) -> {$SK, PK, EK$}
- Encrypt($PK, M$) -> $C$
- Decrypt($SK, C$) -> $M$
- EvalAdd($Params, EK, C_1, C_2$) -> $C_3$
- EvalAddConst($Params, EK, C_1, M$) -> $C_3$
- EvalMul($Params, EK, C_1, C_2$) -> $C_3$
- EvalMulConst($Params, EK, C_1, M$) -> $C_3$
- Relinealize($Params, EK, C'$) -> $C$

#### Function

- EncodePlainText: exchange plaintest integer m to polynomial M
- KeyGen: generate SK, PK1, PK2
- Enc: generate cipher-text C1 and C2 from M, PK1, PK2 using random u, e1 and e2
- Dec: restore plain-text from cipher-text C1, C2, SK
- EvalAdd: calculate C3 = C1 + C2
- EvalMul: calculate C3 = C1 * C2
- Relinearize: resize C into C*