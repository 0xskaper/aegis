#align(center)[
  #text(size: 24pt, weight: "bold")[Aegis Security Analysis: Classical vs. Quantum Computing]
]

= Security Estimates for Encryption Technologies

#align(center)[
  #table(
    columns: (auto, auto, auto),
    inset: 10pt,
    align: center,
    table.header(
      [*Method*], [*Classical Computer*], [*Quantum Computer*],
    ),
    [RSA-2048 (current standard)], [~1 trillion years], [~8 hours with sufficient qubits],
    [ECC-256 (current standard)], [~10 billion years], [~9 hours with sufficient qubits],
    [*Kyber-768* (used in Aegis)], [~$2^164$ operations (millions of years)], [~$2^82$ operations (millions of years)],
    [*SPHINCS+-128f* (used in Aegis)], [~$2^128$ operations (billions of years)], [~$2^64$ operations (thousands of years)],
  )
]

= Breaking Aegis Security

== With Classical Computers:

- *Kyber-768*: Would require approximately 2^164 operations, which is far beyond what's achievable with current or projected classical computing technology. Even if every computer on Earth worked together, it would take millions of years.

- *SPHINCS+*: Would require approximately 2^128 operations for a hash function collision, which remains computationally infeasible with classical computers. This is comparable to or stronger than AES-128, which is still considered secure for classical computing.

== With Quantum Computers:

- *Kyber-768*: Security drops to approximately 2^82 operations due to Grover's algorithm, but this still represents thousands of years of computation even with advanced quantum computers.

- *SPHINCS+*: Security level reduces to approximately 2^64 operations, which while significantly lower than its classical security, would still require thousands of years with projected quantum computing power.

= Security Reduction Factors

#align(center)[
  #table(
    columns: (auto, auto, auto, auto),
    inset: 10pt,
    align: center,
    table.header(
      [*Algorithm*], [*Classical Attack*], [*Quantum Attack*], [*Security Reduction*],
    ),
    [RSA-2048], [~1 trillion years], [~8 hours], [~$10^15$],
    [ECC-256], [~10 billion years], [~9 hours], [~$10^14$],
    [Kyber-768], [millions of years], [millions of years], [~$10^3$],
    [SPHINCS+-128f], [billions of years], [thousands of years], [~$10^6$],
  )
]

= Practical Implications

- *Current cryptographic standards* (RSA, ECC) will be essentially *broken immediately* once sufficiently powerful quantum computers are developed
  
- *Aegis's algorithms* (Kyber and SPHINCS+) would still require *thousands to millions of years* to break even with quantum computers

- This makes Aegis suitable for protecting data that requires long-term security, including:
  - Government classified information
  - Healthcare records
  - Financial systems
  - Critical infrastructure
  - Long-term digital archives

= Key Size and Performance Trade-offs

#align(center)[
  #table(
    columns: (auto, auto, auto, auto),
    inset: 10pt,
    align: center,
    table.header(
      [*Algorithm*], [*Security Level*], [*Key Size*], [*Speed*],
    ),
    [RSA-2048], [112 bits (classical)], [2048 bits], [Fast],
    [ECC-256], [128 bits (classical)], [256 bits], [Very fast],
    [Kyber-768], [164 bits (classical) / 82 bits (quantum)], [1184 bytes], [Fast],
    [SPHINCS+-128f], [128 bits (classical) / 64 bits (quantum)], [32 bytes], [Slower (especially for signing)],
  )
]

#align(center)[
  #text(style: "italic")[
    The Aegis implementation demonstrates that post-quantum security is achievable with reasonable performance trade-offs
    and remains secure against both classical and quantum computing attacks for the foreseeable future.
  ]
]
