# Keccacheck

Keccacheck - a play on words keccak and sumcheck - is a GKR prover for Keccak hash functions. GKR uses lots of rounds of sumcheck internally, hence the name.

The high level idea is to represent a single Keccak-F as a GKR layered circuit. Multiple instances of Keccak-F can be proven together, increasing the number of variables on each layer by only $log_2(instances)$ - making the verifier very efficient for lots of Keccaks at once.

Since GKR proofs are rather large, the idea is to wrap GKR proof verification into another proof system that produces more succint proofs (using gnark).

## Read before you code

Seriously. Save yourself hours of head-scratching why things are they way they are, or why your indices don't work, by reading this document first. This README does not explain GKR or sumcheck. There are lots of materials online on the topic. Instead, it focuses on the subtleties of this particular implementation.

## Variables - name, endianness, degree

Different sources use different conventions. In this projects:
- `z` - output label. `z0` is the least significant bit of the output label. `z` is a vector of variables $z_0..z_k$. $2^k$ is the number of output nodes on the current layer.
  `c` - circuit instance label. E.g. if we prove 8 Keccaks at once, there are $8 = 2^{|c|}$ instances => `c` is a vector of 3 variables.
- `c'` - a copy of the circuit instance label (`c`) - we need to keep `c` linear.
- `a` - left input labels (gate's first argument). $a_0$ is the least significant bit/variable.
- `b` - right input labels (gate's second argument). $b_0$ is the least significant bit/variable.

With the above definitions, our GKR assignment is this (`n` is the current layer, `n+1` are the inputs. $W_0$ are Keccak outputs).

$$W_n(z, c) = \sum_{a, b, c'} wiring(z, c, c', a, b) * g(W_{n+1}(a, c'), W_{n+1}(b, c'))$$

**The order of variables above is really important. It matches the order of variables in the code!**. It may look like `wiring` is a function of 5 arguments, but if input and output labels all have 12 vars, and we have 8 vars for instance id (256 instances), `wiring` is really a function of 52 arguments. The only way to know which bit position represents what is to remember that the `|z|` least significant bits are the output position within a single instance, followed by `|c|` bits of the instance number, followed by the same `|c'|` bits of the instance number, followed by the left input, followed by the right input.

`W_n` definitions naturally match how multiple instances of Keccak values would be stored in the array (bits from the first Keccak first, followed by bits from the second Keccak etc... from this perspective it makes sense that `c` is on more significant bits than `z` or `a` or `b`. It also makes sense that `z` and `c` are on lower bits than everything else, because we fix them to random values at the beginning of each GKR round.

## Wiring and layer definitions

Todo.

## Patterns in layers

Todo.

## Prover - proof format

Todo.

## Prover - GKR recursion

Todo.

## Prover - GKRFunction

Todo.

## Prover - linear sumcheck

Todo.

## Verifier

Todo.

## Benchmarking

Run `RUSTFLAGS='-C target-cpu=native' cargo run --profile=optimized --features parallel -- {num_instances}`. `num_instances` must be a power of two.
