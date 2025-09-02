# Security notes

Completeness is straightforward by the perfect completeness of the sum-check protocol. 

At first glance we can have one of three problems. Our random linear combination may mean that the dishonest claim is congruent to the honest claim. 

We also have the standard sum-check soundness.

We also have the MLE problem, in that the randomness of the MLE is congruent to the cheating value with probability $\frac{1}{\mathbb{F}}$.

Our protocol has a fixed depth. So we are able to come to a very concrete analysis with 2 variables. Being the size of the Field and the number of hashes/ number of variables.

## Round by round

Let’s go through round by round:

Let us denote the number of hashes by $h$. Let us denote the number of variables in the polynomials as $n = \text{log} (h) + 6$. Let us abuse notation such that $\mathbb{F}$ is the size of the field. 

### First evaluation point

The verifier produces a random point $\alpha$, and asks the prover to evaluate the combination output-polynomials at that random point.
When taking the linear combination we introduce a factor of $\frac{1}{\mathbb{F}}$.
We also have the chance that we have a cheating $\sum\limits_{i,j}\beta_{ij}\tilde{\iota}_{ij}(\alpha)$ that evaluates to the same as the honest $\sum\limits_{i,j}\beta_{ij}\iota_{ij}(\alpha)$.
This happens with probability $\frac{n}{\mathbb{F}}$. 

### Prove Iota

We start with a claim on $\sum\limits_{i,j} \beta_{ij}\tilde{\iota}_{ij}(\alpha)$, which we then reduce by means of the sum-check protocol to $eq(\alpha, r_{\iota})\bigg(\beta_{00}\big(\tilde{\chi}_{00}(r_{\iota})\oplus \tilde{RC}(r_{\iota})\big) + \sum_{i, j \ne (0,0)}\beta_{ij}\tilde{\chi}_{ij}(r_{\iota})\bigg)$. This introduces a soundness factor of $\frac{3 \cdot n}{\mathbb{F}}$.  We are then left with two claims, $\tilde{\chi}_{00}(r_{\iota})$ and $\sum\limits_{i, j \ne (0,0)}\beta_{ij}\tilde{\chi}_{ij}(r_{\iota})$. 

In order to combine these, we produce two random linear factors and combine to one claim, which incurs a soundness factor of $\frac{1}{\mathbb{F}}$. Let the two factors be $\kappa$ and $\lambda$. We are left with a claim about $\kappa \cdot \beta_{00} \tilde{\chi}_{00}(r_{\iota}) + \sum\limits_{i, j \ne (0,0)}\lambda \cdot \beta_{ij}\tilde{\chi}_{ij}(r_{\iota})$ .

### Prove Chi

We start with a claim on $\kappa \cdot \beta_{00} \tilde{\chi}_{00}(r_{\iota}) + \sum\limits_{i, j \ne (0,0)}\lambda \cdot \beta_{ij}\tilde{\chi}_{ij}(r_{\iota})$ . We use the sum-check protocol to reduce this to $eq(r_\iota,r_{\chi})\bigg(\sum_{i,j}\beta_{ij}\Big(\pi_{ij}(r_{\chi})\oplus \Big(\big(1-\pi_{(i+1)j}(r_{\chi})\big)\pi_{(i+2)j}(r_{\chi})\Big) \Big)\bigg)$. (in this formulation $\beta_{00}$ is implicitly multiplied by $\kappa$ and each $\beta_{i, j \neq (0,0)}$by $\lambda$). This incurs the standard sum-check soundness factor of $\frac{4 \cdot n}{\mathbb{F}}$. The prover sends each $\tilde{\pi}_{i, j}(r_{\chi})$ in the clear, which the verifier checks for congruence with the above equation. We make a new linear combination of the $\tilde{\pi}_{i, j}(r_{\chi})$.  This incurs a soundness factor of $\frac{1}{\mathbb{F}}$.

### Prove Rho/Pi

We start with a claim on $\sum\limits_{i,j} \beta_{i,j} \cdot \tilde{\pi}_{i, j}(r_{\chi})$. (betas were freshly drawn at the end of prove chi stage). We sum-check to reduce to $\sum\limits_{i,j}\beta_{i,j} \cdot \tilde{rot}_{\tt{ROT(i,j)}}(r_\chi,r_\rho)\tilde{\theta}_{i,j}(r_\rho)$. We have the standard sum-check soundness factor of $\frac{2 \cdot n}{\mathbb{F}}$.

### Prove Theta

At the beginning of the theta round, we have $\tilde{\theta}_{i, j}(\alpha)$, we then change basis and take a linear combination, which adds in a factor of $\frac{1}{\mathbb{F}}$ of soundness error. We then perform a sum-check protocol to reduce the claims  to $eq(a, \alpha_0) \cdot \sum\limits_i \hat{D}_i (\alpha_0) \sum\limits_j \hat{\beta}_{i, j} \cdot \hat{A}_{i, j} (\alpha_0)$ which adds in a factor of $\frac{3 \cdot n}{\mathbb{F}}$.

We now have claims for $\hat{D}_i (\alpha_0)$, we take a linear combination on these claims, introducing soundness error factor of $\frac{1}{\mathbb{F}}$. We perform a sum-check to reduce to $\sum_i\beta_i \cdot eq(\alpha_0, \alpha_1)\hat{C}_{i-1}(\alpha_1)rot(\hat{C}_{i-1}, 1)(\alpha_1)$ which adds in a factor of $\frac{3 \cdot n}{\mathbb{F}}$.

We now have claims for $\hat{C}_{i-1}(\alpha_1)$ and $rot(\hat{C}_{i-1}, 1)(\alpha_1)$. We combine these claims, adding a $\frac{1}{\mathbb{F}}$ soundness error factor. We can then perform a sum check to reduce $\sum\limits_i\Big(\beta_i \cdot eq(\alpha_1,\alpha_2) + \beta'\_irot_1(\alpha_1, \alpha_2)\Big)\prod_j\hat{A}_{ij}(\alpha_2)$, which adds in a factor of $\frac{6 \cdot n}{\mathbb{F}}$.

We now have two claims on $\hat{A}_{i,j}$ being $\hat{A}_{ij}(\alpha_0)$ from the first theta sum-check and $\hat{A}_{ij}(\alpha_2)$

We take a linear combination, introducing $\frac{1}{\mathbb{F}}$ soundness error factor, then reduce via sum-check to $\sum\limits_{i,j}(\beta_{i,j}eq(\alpha_0,\alpha_a) + \beta'_{i,j} \cdot eq(\alpha_2, \alpha_a)))\hat{A}\_{ij}(\alpha_a))$, which introduces soundness factor $\frac{2 \cdot n}{\mathbb{F}}$. 

### Final Claims

In total this gives us a total soundness error of $\frac{ 145+ 505 \cdot n}{\mathbb{F}}$. Let $h = 2^{10}$, so $n =16$, then the error soundness will be $\frac{8225}{\mathbb{F}}$. 

## Fiat Shamir security

Our protocol exhibits RBR soundness, which implies that it is sound even when the Fiat-Shamir paradigm is applied. (Canetti et al 2018).

To see this, let’s go through the 3 conditions of RBR soundness and see that there exists a $\textsf{State}$ function for our protocol that satisfies the three conditions. Our state function acts as a hash function that runs for as many rounds as is needed to catch up with the transcript, it can then take MLEs and evaluate as appropriate with the values in the transcript to see if we are in an accepting or rejecting state. 

1. If $x \notin L$, then $\textsf{State} (x, \emptyset) = \textsf{reject}$) , where $\emptyset$ denotes the empty transcript. Let’s look at $x$ as containing the i/o of the keccak hash function, $\textsf{State}$ can simply calculate the hashes on its own and realise that they are incorrect.
2. This can be shown as above, with a partial transcript, the chance of moving from a cheating state to an honest state, is negligible in each state. 
3. In the third case, $\textsf{State}$ acts the same as the prover. 

Our round-by-round soundness is at most $\frac{25 \cdot n}{\mathbb{F}}$, which is negligible in all $n$ that are reasonably computable (up to 20).

Let’s discuss the Theta stage in greater detail. 

At the beginning of the $\theta$ round. Let’s say the cheating prover has been trying to claim a false hash and ‘honestly’ works backwards till the make claims about $\tilde{\theta}_{ij}(\alpha) \neq \theta_{ij}(\alpha)$. The aim of the cheating prover here is to get to a state of $\tilde{A}_{i,j}(\alpha_{\alpha}) = A_{i,j}(\alpha_{\alpha})$, at which point, he can prove honestly until he gets to the real inputs. We need to prove that the probability of such a transition is negligible. 

The prover will be able to lie about $\hat{A}_{ij}$ and $\hat{D}_{ij}$ in order satisfy the equations, the prover will then be able to adaptively lie about $\hat{C}_{ij}$. This further reduces to a claim on $A_{ij} (\alpha_2)$. We combine the claims on $A_{ij}(a_0)$ and $A_{ij}(a_2)$ for a value $T$.

We have constructed $T$ from $\sum\limits_{ij} \beta_{ij}\tilde{A}_{ij}(a_0) +  \beta'_{ij}\tilde{A}_{ij}(a_2)$, but we wish to show that $T = \sum\limits_k \sum\limits_{i,j} \big( \beta_{ij} \cdot eq(\alpha_0, k) +  \beta'_{ij} \cdot eq(\alpha_2, k)\big) \hat{A}_{ij}(k)$. 

Let $\Gamma_{ij}(k) =\beta_{ij} \cdot eq(a_0, k) + \beta'_{ij} \cdot eq(a_2, k)$

$T = \sum\limits_k\sum\limits_{ij} \Gamma_{ij}(k)\hat{A}_{ij}(k)$

We define the difference P

$$
P = \sum\limits_k \sum\limits_{i,j} \Gamma_{ij}(k) \cdot \hat{A}_{ij}(k) -  T \\ = \sum\limits_k \sum\limits_{i,j} \Gamma_{ij}(k)  \cdot \big( \hat{A}_{ij} - \tilde{A}_{ij} \big) \\ \sum\limits_k \sum\limits_{i,j} \Gamma_{ij}(k)  \cdot E_{ij} (k)
$$

If $\hat{A}_{ij} \equiv \tilde{A}_ij$, $P$ is always 0. 

However, if we have cheated about $A_{ij}$, then $E_{ij}(r)$ will not be 0 with very high probability and the prover will be caught out. 

This is despite being able to choose $\tilde{A}$ adaptively on both ‘branches’ of the protocol. With very high probability, the prover will not be able to manipulate the transcript to grind itself a satisfying challenge to the above constraints.
