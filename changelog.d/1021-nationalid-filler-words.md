### 🐛 Bug Fixes

- **nationalid:** up to two filler words (`is`, `es`, `é`, `number`, `no.`, `nº`) may stand between a
  label and its value, so "Our Social Insurance Number is" and "Employee SIN number is:" followed by a
  valid number are read; before, they reported nothing and the value stayed in clear in a redacted
  copy. At most two words: a longer clause between the label and the digits is still not read.
  ([#1021](https://github.com/awslabs/ferret-scan/issues/1021))
