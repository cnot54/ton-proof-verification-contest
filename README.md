# Privacy-preserving Credentials with zkSNARKs:

---



## Current state of privacy



That's a huge step and a real use-case example concept. For example, in the US, every bank member can check all customers' transactions by his Social security number. [1,2]

1. Reference: [FDIC Law, Regulations, Related Acts

> Reference: [FDIC Law, Regulations, Related Acts](https://www.fdic.gov/regulations/laws/rules/8000-1600.html)

2. DISCLOSURE OF SOCIAL SECURITY NUMBERS

> Reference:  [DISCLOSURE OF SOCIAL SECURITY NUMBERS](https://www.justice.gov/opcl/overview-privacy-act-1974-2020-edition/ssn)

###

## Solution

An obvious privacy limitation with current technology doesn't even allow us to verify our age without revealing our passports and other sensitive data.
Let's imagine the situation:
Alice (Creditor) want's to prove to Bob (Bank) that she's eligible to get credit. She has to reveal her's id and whole bank history to Bob to prove that she is over specific age and proof that she's eligible for credit.



## Workflow:

We made unique proof for Alice that checks:
1. Alice is eligible by age
2. Alice has a sufficient salary
3. Bob can verify this proof according to public inputs: `salary_input` and `age_input`

So anyone can validate his private info insecure way to 3-rd parties instances! Woo-hoo!

#### TBD

In a real-world case, proof issuer has to make this proof unique. We can achieve this by sharing secret keys. In this example, we will use stub in the form of SHA256 hash from `age` and `salary`.
But it was tricky to convert and verify values by using `sha256_hash_component`. So in this example, we will check just values.

## Assumptions:

- We must allow users to generate proofs on the third-party issued credentials.
- The verifier must verify that the statement is true concerning the third party-issued credential without knowing the actual credential value.
- The user should have the option to disclose credential values if necessary selectively.
- The prover can make any statement regarding its issued credentials and create proof which asserts that the statement is valid.
- The verifier is an entity that requires the prover to prove the validity of a specific statement.

This point allows us to integrate ZKP into a fully decentralized architecture.

We would change this by generating proof on Alice's side that she is satisfied with specific parameters without revealing sensitive data.

I think the magic of zkSNARKs lets you do this!

With a zkSNARK, you can "prove" that you have some secrets `age` and `amount` (i.e., `R1` and `R2`)
that satisfy some programmable condition (i.e., `SHA(R1)=H1` and `SHA(R2)=H2`, based on public inputs (H1, H2, and X), without revealing
those secrets.

That's pretty safe because if you receive the only preimage for R1, along with instructions in the onion saying ask Bob for
a preimage for R2, and here's X and proof, then either:

## Implementation

This reference implementation is built on top of the blueprint (*which is a fork of libsnark*) library: zkSNARKs are based on verifiable computation schemes.

It seems like there are research-level tools out there that make this practical to try out. I've had a go at implementing this using `blueprint`.


### Verification

It is not necessary for a verifier to directly interact with the prover to verify proof.

### Using it looks like:

- Uasage

`bin/cli/cli --help`

> Output:
```
R1CS Generic Group PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge (https://eprint.iacr.org/2016/260.pdf) CLI Proof Generator:
  -h [ --help ]            Display help message
  --keygen                 Generate keys
  --proof                  Generate proof
  --verify                 Verify proof
  -a [ --age ] arg (=0)
  -s [ --salary ] arg (=0)
```

1. initial setup of proof/verification keys:

`bin/cli/cli --keygen`

> Output:

```
prooving key saved to "prov_key"
verification key saved to "ver_key"
```

2. generate proof using a secret

`bin/cli/cli --proof -a 25 -s 2000`

> Output:

```
Circuit satisfied: 1
proof is saved to "proof"
```

3. Verify the proof:

`bin/cli/cli --verify`

> Output:

```
proof verified 1
```

4. Verify it doesn't report a valid proof with younger age  inputs:

`bin/cli/cli --proof -a 15 -s 2000`

`bin/cli/cli --keygen`


## Tests

Put your tests in a `test` folder.
1. `cd build`
2. Build tests:
`cmake .. -DDBUILD_TESTS=1`
`make circuit_test`
3. Run tests: `test/circuit_test`

---


Some results:

 * Everyone has to trust that nobody has kept the origin
 * al random
   numbers used to generate it.
 * proof/verification key data takes about a minute to generate on a modern laptop.
 * generating the proof data for a given R1, X pair takes about 10
   seconds
 * verifying the proof is quick-ish -- it takes 0.1s on my laptop,

The long proof generation time is probably more of a limitation -- though you could generate them in advance quickly enough and store them until it would be best if you used them, which would avoid lag being a problem at least.

## In the end

zkSNARKs are still pretty new as a concept. And it was hard to figure how to build it.
My proof may not have correctly implemented the approach, but this is a good proof of concept. _So not a great idea to use this to protect real money today._

**But it could be an excellent start for building a private and scalable blockchain, like TON.**

But still, this seems like it's not all that far from being practical, and if the crypto's not fundamentally broken, it looks like it goes a long way to filling in the most significant privacy hole in blockchain today. And I made this first step into this journey.

Thanks.
