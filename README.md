# Keccacheck

Keccacheck - a portmanteau of Keccak and sumcheck - is a GKR-style prover for Keccak hash functions. Our prover uses many rounds of sumcheck internally, hence the name.

The high level idea is to represent a single Keccak-F as layered polynomials. Multiple instances of Keccak-F can be proven together, increasing the number of variables on each layer by only $log_2(instances)$ - making the verifier very efficient for lots of Keccaks at once.

Since these proofs are rather large, we wrap proof verification into another proof system that produces more succint proofs (using gnark).

## Performance
See the performance comparison between our system and Keccak implementation built into Gnark. For sufficiently large batch sizes, our solution offers a 10x speedup, and scales well beyond what's possible with Gnark.

<img width="3204" height="1322" alt="chart" src="https://github.com/user-attachments/assets/ef8738de-f34c-44d4-8513-4f15bad5c248" />

## Read the Paper
For in-depth information about the techniques used, [read the "Keccacheck: towards a SNARK friendly Keccak" paper at IACR Cryptology Archive titled](https://eprint.iacr.org/2025/1764).

[We also published a high-level overview of the system on Reilabs blog](https://reilabs.io/blog/keccacheck-towards-a-snark-friendly-keccak/).

##  Building and Running the Project

### Rust (Static Library)

To compile the Rust portion of the project and generate the static library:

```bash
RUSTFLAGS='-C target-cpu=native' cargo build --profile=optimized
```

### Go (gnark)

When making changes to the Rust static library, it's important to ensure Go does not serve outdated, cached versions of the compiled code. To avoid this issue, use the MakeFile Script:

```bash
make
```

To run the executable, simply run:

```bash
go run .
```

This will compile the main circuit, yield the number of constraints and give the proving times for that circuit.

## Benchmarking

### Non-recursive proof

Run `RUSTFLAGS='-C target-cpu=native' cargo run --profile=optimized -- {num_variables}`.

`num_variables` must be greater than 6 (a single keccak instance). This will prove $2^{numVariables - 6}$ instances of keccak.

**On an M3 Max laptop, the current prove time is 5.3s for 1024 instances of Keccak.** This can probably be further improved to about 4 seconds by smarter parallelizm (not all cores are properly utilized in simpler keccak stages).

```
INFO     prove [ 5.33s | 0.02% / 100.00% ] num_vars: 16
INFO     ┝━ calculate_states [ 114ms | 2.14% ]
INFO     ┕━ prove all rounds [ 5.21s | 93.50% / 97.84% ]
INFO        ┝━ prove_iota [ 9.54ms | 0.18% ]
INFO.       ...
```

#### Proof size

| keccak instances | 1    | 2    | 128   | 1024  | n                  |
|------------------|------|------|-------|-------|--------------------|
| num variables    | 6    | 7    | 13    | 16    | 6 + log₂(n)        |
| proof size (felts) | 6241 | 6793 | 10105 | 11761 | 554 * vars + 2931|
| proof size (bn254, KiB)	| 195	| 212	| 316	| 368 | ((552 * vars + 2929) *32)/1024 |
|recursive proof size (bn254, groth16, bytes)|356|388|580|676|


### Recursive proof

Build as per above instructions, then in the `gnark` directory, run `go run .`. The number of instances can be modified in the `main.go` file.

| keccak instances | 1    | 8  | 128   | 1024  | 
|------------------|------|------|-------|-------|
| No. Constraints   | 638682   | 791,597   | 1,379,176  | 4,614,574   |
| Proving time | 1.434881s | 1.75688025s| 3.311138583s| 11.785925375s |

# Credits

* Marcin Kostrzewa - the idea for GKR-style prover with a linear combination of keccak state and dropping the usual layering constraint.
* Grzegorz Świrski, Matthew Klein - implementation
* Ara Adkins - original research into using GKR for keccak proving
* [ProveKit team](https://github.com/worldfnd/ProveKit) team - poseidon2 & transcript implementation, ideas for a very fast multi-threaded sumcheck implementation
