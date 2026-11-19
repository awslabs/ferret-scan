### ⚡ Performance

- **redaction (completeness sweep):** the pass that removes every remaining copy of a reported value
  after a text file is redacted, and the check that no reported value survives in a written copy, now
  look for all values in one pass over the document instead of one pass per value, so their cost
  grows with the number of distinct values instead of with values times file size
  ([#1005](https://github.com/awslabs/ferret-scan/issues/1005)). On a synthetic file with one distinct
  email per finding the sweep took 0.10 / 0.20 / 0.70 / 2.76 s at 4,000 / 8,000 / 16,000 / 32,000
  values and takes a fraction of that now. The redacted text, the list of swept values, the order
  replacements are generated in and every error message are unchanged.
