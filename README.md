# Keccacheck

Keccacheck - a play on words keccak and sumcheck - is a GKR-style prover for Keccak hash functions. Our prover uses lots of rounds of sumcheck internally, hence the name.

The high level idea is to represent a single Keccak-F as layered polynomials. Multiple instances of Keccak-F can be proven together, increasing the number of variables on each layer by only $log_2(instances)$ - making the verifier very efficient for lots of Keccaks at once.

Since these proofs are rather large, the idea is to wrap proof verification into another proof system that produces more succint proofs (using gnark).

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

### Proof size

| keccak instances | 1    | 2    | 128   | 1024  | n                  |
|------------------|------|------|-------|-------|--------------------|
| num variables    | 6    | 7    | 13    | 16    | 6 + log₂(n)        |
| proof size (felts) | 6241 | 6793 | 10105 | 11761 | 552 * vars + 2929 |
| proof size (bn254, KiB)	| 195	| 212	| 316	| 368 | ((552 * vars + 2929) *32)/1024 |
|recursive proof size (bn254, groth16, bytes)|356|388|580|676|


## Keccak definition

```
Keccak-f(A) {
  for i in 0…n-1
    A = Round[b](A, RC[i])
  return A
}

Round(A,RC) {
  # θ step
  C[x] = A[x,0] xor A[x,1] xor A[x,2] xor A[x,3] xor A[x,4],   for x in 0…4
  D[x] = C[x-1] xor rot(C[x+1],1),                             for x in 0…4
  A[x,y] = A[x,y] xor D[x],                           for (x,y) in (0…4,0…4)

  # ρ and π steps
  B[y,2*x+3*y] = rot(A[x,y], r[x,y]),                 for (x,y) in (0…4,0…4)

  # χ step
  A[x,y] = B[x,y] xor ((not B[x+1,y]) and B[x+2,y]),  for (x,y) in (0…4,0…4)

  # ι step
  A[0,0] = A[0,0] xor RC

  return A
}
```

## Grand structure
Call the output $\iota_{ij}$, each of 6 vars, $i$ and $j$ ranging from 0 to 4, MLEs of the state.
The verifier will sample a random $\alpha_0$ and ask the verifier to evaluate $\iota_{ij}(\alpha)$ for each $i$, $j$ pair, GKR-style and verify independently that the answer is correct (these are easy for the verifier to evaluate,
given it needs to know the inputs and outputs anyway).
To make this faster, the verifier samples 25 random values $\beta_{ij}$ 
and computes

$$ \sum_{i,j} \beta_{ij}\iota_{ij}(\alpha). $$

(As an aside, it is possible to generate $\beta_{ij}$ as successive powers of one value. This results in approximately 150k fewer constraints, regardless of batch size, and an 11 bit security loss.)

I will try to go through a whole round of keccak GKR style, to reduce this problem to computing an
analogous sum of the outputs of the previous round and then we can loop until we reach the initial state.

## Conventions

I will denote the `A` polynomial after each step by the step name in the pseudocode above, $A$ will stand for
the input state and $B$, $C$ and $D$ follow their pseudocode definitions.

I'm also very liberal with reusing the symbol $\beta$ for random linear combination coefficients
it should be clear context when new $\beta\text{s}$ should be chosen, so I keep reusing this letter.

Also define $a \oplus b := a + b - 2ab$.

## Iota

Note that by definition we have:

$$
  \sum_{i,j} \beta_{ij}\iota_{ij}(\alpha) =
  \sum_{i,j} \sum_{k} \beta_{ij}eq(\alpha, k)\iota_{ij}(k) =
  \sum_{k}eq(\alpha, k)\bigg(\beta_{00}\big(\chi_{00}(k)\oplus RC(k)\big) + \sum_{i, j \ne (0,0)}\beta_{ij}\chi_{ij}(k)\bigg).
$$

We could sumcheck over this! At the end of sumcheck we need to evaluate
$\sum_{i,j\ne(0,0)}\beta_{ij}\chi_{ij}(\alpha')$ and $\beta_{00}\chi_{00}(\alpha')$.
Verifier samples some randomness to do a random linear combination of these two claims, at which point
we end up with the goal of convincing them about the value of $\sum_{i,j}\beta_{ij}'\chi_{ij}(\alpha')$
for some easily computable values of $\beta'$. We strip off the primes and we're back at the original form, but a step further!

## Chi

By definition:

$$
  \sum_{i,j}\beta_{ij}\chi_{ij}(\alpha) =
  \sum_{i,j}\sum_{k}\beta_{ij}eq(\alpha,k)\chi_{ij}(k) =
  \sum_{k}eq(\alpha,k)\bigg(\sum_{i,j}\beta_{ij}\Big(\pi_{ij}(k)\oplus \Big(\big(1-\pi_{(i+1)j}(k)\big)\pi_{(i+2)j}(k)\Big) \Big)\bigg)
$$

Again, this can be sumchecked. Note that the $\pi$ polynomials are all
mentioned multiple times, but the folds can be reused. In the final step the
prover sends the claimed evaluations of all 25 $\pi \text{s}$, the verifier
checks the equation, samples 25 new $\beta\text{s}$ and we move on to the next
step.

## Pi

This is just a relabeling of our polys – we relabel them, rename to $\rho$ and
move on unbothered.

## Rho

By definition:

$$
  \sum_{i,j}\beta_{ij}\rho_{ij}(\alpha) =
  \sum_{i,j}\sum_{k}\beta_{ij}rot_{r(i,j)}(\alpha,k)\theta_{ij}(k) =
  \sum_{k}\sum_{i,j}\beta_{ij}rot_{\tt{ROT(i,j)}}(\alpha,k)\theta_{ij}(k)
$$

Unsurprisingly, we sumcheck this. The $rot_k$ polynomial is such that
$rot_k(a,b) = 1$ iff $ a = (b + k)\mod 64 $,
where the bitvectors are interpreted as binary integers.
Computing them will be painful, particularly for the verifier + this is a
sumcheck over 50 different polys: oof. OTOH, it's _just_ a sum, so this thing
will parallelize like there's no tomorrow (i.e. we can just spawn a thread for
each summand and call it done).
For the verifier, computing all $rot\text{s}$ will take ~2k constraints (256 for
$eq$ precomputation and then each rot requires 64 multiplications, so the total is
256 + 1600), making this probably the most expensive step for the verifier. OTOH
this is roughly equivalent to 10 permutations of poseidon, which means there
isn't much room to be smart. Anyway, we're now left with the same task as before,
but for $\theta$.

## Theta

First, we change basis. Instead of mapping bits to $0$ and $1$, we map them to
$1$ and $-1$ respectively. Note that with this representation, $\oplus$ becomes
standard multiplication, which fact we will abuse for some optimization.
Also note that given $W$ in the standard basis, we can easily define $\hat{W}$
in the shifted basis by $\hat{W} = 1 - 2W$.

We shift the thetas to get:

$$
  \sum_{i,j}\beta_{ij}\hat{\theta}\_{ij}(\alpha) =
  \sum_{k}eq(\alpha,k)\sum_{i,j}\beta_{ij}\hat{A}\_{ij}(k) \hat{D}\_i(k) =
  \sum_{k}eq(\alpha,k)\sum_i\hat{D}\_i(k)\Big(\sum_j\beta_{ij}\hat{A}_{ij}(k)\Big)
$$

Another day, another sumcheck, and this time there's only 11 polynomials. This
is because we can precompute the innermost sums before folding steps.
We're left with evaluation claims for $\hat{A}_{ij}(\alpha_0)$ and $\hat{D}_i
(\alpha_0)$. Let's punt the $\hat{A}\text{s}$ for now and keep working on
evaluating $\hat{D}\text{s}$.
The verifier samples some randomness $\beta_i$ and sumchecks:

$$
  \sum_{i}\beta_i\hat{D}\_i(\alpha_0) = \sum_k\sum_i\beta_ieq(\alpha_0, k)\hat{C}\_{i-1}(k)rot(\hat{C}_{i-1}, 1)(k)
$$

This yields 2 more evaluation obligations: $C_i(\alpha_1)$ and $rot(C_i,1)(\alpha_1)$.
We sample $\beta_i$ and $\beta'_i$ and combine both:

$$
\begin{align*}
\sum_i\beta_i\hat{C}\_i(\alpha_1) + \beta'\_irot(\hat{C}\_i,1)(\alpha_1) =\\\\=
\sum_k\sum_i\Big(\beta_ieq(\alpha_1,k)\prod_j\hat{A}\_{ij}(k) + \beta'\_irot_1(\alpha_1, k)\prod_j\hat{A}\_{ij}(k)\Big) =\\\\=
\sum_k\sum_i\Big(\beta\_ieq(\alpha\_1,k) + \beta'\_irot_1(\alpha_1, k)\Big)\prod_j\hat{A}_{ij}(k)
\end{align*}
$$

Once again, this can be sumchecked, requiring us to evaluate $A_{ij}(\alpha_2)$. We can
combine with the long-forgotten claim on $A_{ij}(\alpha_0)$:

$$
\begin{align*}
\sum_{i,j}\beta_{ij}\hat{A}\_{ij}(\alpha_0) + \beta'\_{ij}\hat{A}\_{ij}(\alpha_2) =\\\\=
\sum_k\sum_{i,j}\beta_{ij}eq(\alpha_0,k)\hat{A}\_{ij}(k) + \beta'\_{ij}eq(\alpha_2, k)\hat{A}\_{ij}(k) =\\\\=
\sum_k\sum_{i,j}\big(\beta_{ij}eq(\alpha_0,k) + \beta'\_{ij}eq(\alpha_2, k)\big)\hat{A}\_{ij}(k)
\end{align*}
$$

This can be sumchecked one last time to reduce the problem to a single
opening of all $\hat{A}\\text{s}$.

We need to change the base back to $A$ and can proceed to the next round.

$$
A = \frac{1}{2} ( 1 - \hat{A})
$$

# Notes on implementing sumcheck

When sumchecking

$$
\sum_{k_1,\dots,k_n} f(k_1,\dots,k_n)
$$

the prover will first compute and send a function $f$ defined by:

$$
r(X) = \sum_{k_2,\dots,k_n} f(X, k_2,\dots,k_n)
$$

Note that we represent $f$ as a composition of an arbitrary (low degree)
polynomial with a vector of multilinear polynomials given in evaluation form.
That is:

$$
f(x_1,\dots,x_n) = g(p_1(x_1,\dots,x_n),\dots,p_m(x_1,\dots,x_n))
$$

Where $g$ is an arbitrary low-degree polynomial given by an efficiently
computable formula, and $p_1\dots p_n$ are given by arrays $P_1, \dots, P_n$,
each of length $2^n$ and the functions are defined as:

$$
p_i(x_1,\dots,x_n) = \sum_k eq(x_1,\dots,x_n,k)P_i[k]
$$

We now plug all this back into the definition of $r$ (we use the overline to
signify a binary number obtained by concatenating the digits):

$$
\begin{align*}
r(X) = \sum\_{k\_2,\dots,k\_n} f(X, k\_2,\dots,k\_n) =\\\\=
\sum\_{k\_2,\dots,k\_n} g(p\_1(X,k\_2\dots,k\_n),\dots,p\_m(X,k\_2\dots,k\_n)) =\\\\=
\sum\_{k\_2,\dots,k\_n} g( \sum\_{k'\_1\dots k'\_n} eq(X,k\_2\dots,k\_n,k'\_1,\dots,k'\_n)P\_1[\overline{k'\_1\dots k'\_n}],\dots, \sum\_{k'\_1\dots k'\_n} eq(X,k\_2\dots,k\_n,k'\_1,\dots,k'\_n)P\_m[\overline{k'\_1\dots k'\_n}])
\end{align*}
$$

Working on the inner sums, we notice that it forces equality between $k\text{s}$
and $k'\text{s}$ almost everywhere, obviating the need for sums. That is:

$$
\begin{align*}
\sum_{k'\_1\dots k'\_n} eq(X,k\_2\dots,k\_n,k'\_1,\dots,k'\_n)P_i[\overline{k'_1\dots k'_n}] =\\\\=
\sum\_{k'\_1\dots k'\_n} eq(X, k\_1)eq(k\_2\dots,k\_n,k'\_2,\dots,k'\_n)P\_i[\overline{k'\_1\dots k'\_n}] =\\\\=
\sum\_{k'\_1}eq(X,k'\_1)P\_i[\overline{k'\_1,k\_2,\dots,k\_n}] =\\\\=
eq(X, 0)P\_i[\overline{0,k\_2,\dots,k\_n}] + eq(X,1)P\_i[\overline{1,k\_2,\dots,k\_n}] =\\\\=
(1-X)P\_i[\overline{0,k\_2,\dots,k\_n}] + XP\_i[\overline{1,k\_2,\dots,k\_n}]
\end{align*}
$$

Plugging this back into the last equation (and simplifying indices), we get

$$
r(x) = \sum\_{k}g((1-X)P\_1[\overline{0,k}] + XP\_1[\overline{1,k}], \dots, (1-X)P\_m[\overline{0,k}] + XP\_m[\overline{1,k}])
$$

So the plan is simple: fold $P\text{s}$ in half, compute the function under the
sum for each $k$ (this is highly parallelizable!) and sum all these functions.

## How to compute the function under sum?

Computing the coefficients of this function would be pretty expensive, so instead
we carefully select a bunch of points to evaluate it on, then sum these
evaluations. Then, at the very end, we're going to transform them into
coefficients, making it very cheap. The degree of this polynomial can be
predicted (it is equal to the total degree of $g$). To uniquely reconstruct the
coefficients we need to obtain $deg(r) + 1$ independent values of the function.
Throughout this section we'll be using $g(a,b,c,d) = a(bc - d)$ (used in
spartan) as an example.
So the equation for $r$ (skipping the $k$ suffixes in array indices, because
I'm tired of them by now) becomes:

$$
r(X) = \big((1-X)A[0]+XA[1]\big)\Big(\big((1-X)B[0]+XB[1]\big)\big((1-X)C[0]+XC[1]\big)-\big((1-X)D[0]+XD[1]\big)\Big)
$$

This is degree 3, so we need to obtain 4 "pieces of independent information".

### Choosing the points
First of all, note that we have access to the claimed sum of this polynomial.
Which is to say, we have access to $y_{sum} = r(0) + r(1)$ – that's one free
piece of information – we only need 3 more!

Evaluating at $0$ is an obvious choice, where we find that:
$r(0) = g(P_1[0,k],\dots,P_m[0,k])$

$r(1)$ would also be good, but notice that we can compute that from $y_{sum}$
so that is not independent information.

We choose $r(-1)$ instead, which is equal to:

$$
r(-1) = g(2P\_1[0,k]-P\_1[1,k],\dots,2P\_m[0,k]-P\_m[1,k])
$$

Note that $2P$ should never be computed through a multiplication, but rather
as $P+P$, that's much cheaper!

Another one is tricky, and the credit here goes to Remco Bloemen, as far as I
know. We will use what is called an evaluation at infinity and essentially
boils down to computing the highest degree coefficient. In our example, that
highest coefficient (which is going to be the coefficient next to $X^3$)
can be checked to be:

$$
r(\infty) = (A[1]-A[0])(B[1]-B[0])(C[1]-C[0])
$$

This is pretty awesome, because we didn't even have to touch $D$!

### Reconstructing the coefficients

If we assume $r(x) = a_3x^3+a_2x^2+a_1x+a_0$, we can see that:

$$
\begin{align*}
r(0) = a_0\\\\
r(\infty) = a_3\\\\
y_{sum} = r(1) + r(0) = a_3 + a_2 + a_1 + 2a_0\\\\
r(-1) = -a_3 + a_2 -a_1+a_0
\end{align*}
$$

From which we recover $a_0$ and $a_3$ trivially and note that:

$$
a_2 = \frac{y_{sum} + r(-1) - 3r(0)}{2}
$$

and

$$
a_1 = y_{sum} - a_3 - a_2 - 2a_0
$$

### Higher degrees

The highest degree sumcheck in our keccak circuit is degree 6, so we need 6
points (7, but again, we get one for free from the claimed sum).
Good points to try: $0$, $\infty$, $-1$, $2$.
Values for points $-2$ and $3$ can be obtained easily from $-1$, $2$ without any need
for multiplication.

For any choice of points, you can derive the coefficient equations: it's going
to be a system of linear equations, which can easily be solved, even if the
solution is going to be way uglier than in the degree-3 case and then this
solution can just be hardcoded in the implementation.

# Credits

* Marcin Kostrzewa - the idea for GKR-style prover with a linear combination of keccak state and dropping the usual layering constraint.
* Grzegorz Świrski, Matthew Klein - implementation
* Ara Adkins - original research into using GKR for keccak proving
* [ProveKit team](https://github.com/worldfnd/ProveKit) team - poseidon2 & transcript implementation, ideas for a very fast multi-threaded sumcheck implementation
