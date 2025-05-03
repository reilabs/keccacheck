# Keccacheck

Keccacheck - a play on words keccak and sumcheck - is a GKR prover for Keccak hash functions. GKR uses lots of rounds of sumcheck internally, hence the name.

The high level idea is to represent a single Keccak-F as a GKR layered circuit. Multiple instances of Keccak-F can be proven together, increasing the number of variables on each layer by only $log_2(instances)$ - making the verifier very efficient for lots of Keccaks at once.

Since GKR proofs are rather large, the idea is to wrap GKR proof verification into another proof system that produces more succint proofs (using gnark).

## Read before you code

Seriously. Save yourself hours of head-scratching why things are they way they are, or why your indices don't work, by reading this document first. This README does not explain GKR or sumcheck. There are lots of materials online on the topic. Instead, it focuses on the subtleties of this particular implementation.

## Variables - name, endianness, degree

Different sources use different conventions. In this projects:
- `z` - output label. `z0` is the least significant bit of the output label. `z` is a vector of variables $z_0..z_k$. $2^k$ is the number of output nodes on the current layer.
- `c` - circuit instance label. E.g. if we prove 8 Keccaks at once, there are $8 = 2^{|c|}$ instances => `c` is a vector of 3 variables.
- `c'` - a copy of the circuit instance label (`c`) - we need to keep `c` linear.
- `a` - left input labels (gate's first argument). $a_0$ is the least significant bit/variable.
- `b` - right input labels (gate's second argument). $b_0$ is the least significant bit/variable.

With the above definitions, our GKR assignment is this (`n` is the current layer, `n+1` are the inputs. $W_0$ are Keccak outputs).

$$W_n(z, c) = \sum_{a, b, c'} wiring(z, c, c', a, b) \cdot g(W_{n+1}(a, c'), W_{n+1}(b, c'))$$

**The order of variables above is really important. It matches the order of variables in the code!**. It may look like `wiring` is a function of 5 arguments, but if input and output labels all have 12 vars, and we have 8 vars for instance id (256 instances), `wiring` is really a function of 52 arguments. The only way to know which bit position represents what is to remember that the `|z|` least significant bits are the output position within a single instance, followed by `|c|` bits of the instance number, followed by the same `|c'|` bits of the instance number, followed by the left input, followed by the right input.

`W_n` definitions naturally match how multiple instances of Keccak values would be stored in the array (bits from the first Keccak first, followed by bits from the second Keccak etc... from this perspective it makes sense that `c` is on more significant bits than `z` or `a` or `b`. It also makes sense that `z` and `c` are on lower bits than everything else, because we fix them to random values at the beginning of each GKR round.

## Wiring and layer definitions

For simplicity, examples in this section will ignore instance number and will only use `z`, `a`, `b` variables (no `c` or `c'`).

GKR graphs consist of layers where each node represents a value. These values are calculated by applying an arithmetic gate (id, add, multiply, xor etc) to at most 2 values from the lower layer (except for the fixed input layer). One any given layer, we might want to apply multiple gate types (e.g. `id` to copy values from the previous layer, and `xor` to xor some auxilary values). The way it's done in GKR is by defining _wiring polynomials_ or _predicates_ (that return 1 if `z` is connected to `a` and `b`, 0 otherwise). In the literature, there are usually two gate types, _add_ and _mul_. In our implementation, there are more gate types, and each one of them can have their own _wiring polynomial_.

To simplify the implementation, all gate types take 2 arguments. Because of this, we'll use `left` instead of `id` - it returns the first argument and ignores the second. Example:

$$W_n(z) = \sum_{a, b} wiring_{id}(z, a, b) \cdot left(W_{n+1}(a), W_{n+1}(b)) + wiring_{xor}(z, a, b) \cdot xor(W_{n+1}(a), W_{n+1}(b))$$

Note that with the definition above, each $outputLabel \times gateType$ contains exactly 0 or 2 arguments (as opposed to each $outputLabel$ in literature).

**In order to make both the prover and the verifier efficient, we enforce  _wiring preficates_ to be multilinear (i.e. each variable's max degree is 1). No $x_i$ can be multiplied by itsef.** To achieve this, we have three basic building blocks:
* $eq(x_i, x_j, ..., x_k, [const])$ - returns 1 if all variables $x_i, x_j, ... x_k$ have the same value (0 or 1). Additionaly, a constant can be provided to check if all of these variables have a specific value. Note that our `eq` can have an arbitrary arity, as opposed to the typical 2 found in literature. This significantly helps with keeping things multilinear.
* $cmpLeq([x_0, x_1, x_2, ...], [y_0, y_1, y_2, ...], ... , [const_0, const_1, const_2, ...])$ returns if all vectors $[x_0, x_1, ...], [y_0, y_1, ...]$ are equal and also that they are all $\leq [const_0, const_1, const_2, ...]$ (consts are also provided with the least significant bit first).
* For anything else, use multilinear polynomials of at most 3 * 6 variables expressed in a sparse evaluation form. At most 64 ($2^6$) values can be non-zero. In other words, these values represent how each output gate (of which there are at most 64 if represented by 6 variables) is connected to two input gates (each is 6 variables)

Warning: when writing predicates, make sure that each input variable a, b is connected to some output variable z. Otherwise the circuit will return incorrect results.

## Wiring predicate representations

Keccacheck provides a small DSL for defining circuits: `eq`, `cmp` and `sparse` functions that can be added and multiplied together. These allow you to compose predicates in a relatively human-friendly way, while at the same time ensuring the entire expression stays multilinear.

There are three main ways predicates are represented:
- `PredicateExpr` - an AST of smaller predicates. Created manually to define the circuit.
- `SparseMultilinearPolynomial` - an evaluation representation of a sparse multilinear polynomial (sparse because at most $|z|$ points are non-zero) that is used throughout the GKR protocol.
- `EvaluationGraph` - a list of graph edges to quickly calculate values on each GKR layer before proving starts.

When composing predicates, you build an abstract syntax tree (AST) of add, mul and base operations (represented by `PredicateExpr` type). This predicate expression form is human and verifier friendly. The verifier needs to walk the tree once, perform a small calculation for each variable (of which we have only $log_2(circuitSize)$ and done.

However, arbitrary ASTs are difficult for the prover, so it converts `PredicateExpr` to **a sum** of `SparseMultilinearPolynomial`s. In order to do so, it calculates a DNF (disjunctive normal form) of the entire predicate. Each DNF term constraints all variables, but now you have $2^{numberOfAdditions}$ terms. Because of this, avoid doing things like $[eq(a, b) + eq(c, d)] \cdot [eq(e, f) + eq(g, h)] \cdot [eq(e, f) + eq(g, h)]$ if possible. It makes prover perform 8 times more work than if the addition wasn't present.

Finally, using these sparse polynomials is not convenient to quickly traverse the GKR graph and assign values, so the prover is also provided an `EvaluationGraph` to effortlessly assign values on each layer before proving.

Both `SparseMultilinearPolynomial` and `EvaluationGraph` representations are automatically compiled from the `PredicateExpr` representation and can be stored in a serialized form (so we don't need to perform the compilation step before proving).

## Patterns in layers

Wiring for each Keccak instance is exactly the same, they are just shifted by the size of each Keccak. In other words, we define the circuit for a single instance of Keccak, and circuits for multiple instances of Keccaks are compiled automatically.

In order to do so, two additional vectors `c` and `c'` are inserted between `z` and `a`. Together `(z, c)` uniquely represent the output label (instance `c`, label `z` within that instance), and `(a, c')` and `(b, c')` uniquely represent input labels (instance `c'`, label `a` or `b` within that instance).

We need two copies of the same thing (`c` and `c'`) because for GKR correctness `c` must stay multilinear (it's the output), and we will want to multiply $wiring_{zc}(c', a, b) \cdot W_n(a, c') \cdot W_n(b, c')$. We can do this legally, because all `c', a, b` appear under the sum, and so from the protocol perspective they are just constants.

The only issue is that now the variable `c'` can appear in degree 3 (everything else will be degree 2), but it is a small price to pay for the reduction  of the total number of variables (see https://github.com/reilabs/keccacheck/issues/4 for a more detailed analysis and ideas how to further leverage this technique).


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
