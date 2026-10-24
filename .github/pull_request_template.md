**What and why.**

**Kind.** Format (SPEC.md; the issue where it was agreed: #) / implementation
/ port / docs.

**Checklist**
- [ ] All tests pass (CONTRIBUTING.md, "Before a pull request").
- [ ] New tests show the change (or: why none are needed).
- [ ] A format change updates SPEC.md, the Python reference, the vectors,
      and the C and JavaScript implementations together.
- [ ] Test seeds and testnet PSBTs only.
- [ ] C library: still C99, no malloc, no floating point by default, no
      mutable globals; a new option says what it costs in RAM.
