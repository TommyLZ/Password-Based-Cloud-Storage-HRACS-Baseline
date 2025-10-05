# Password-Based-Cloud-Storage (PBCS)

This repository contains C++ implementations of several representative PBCS schemes, including [CCS](https://eprint.iacr.org/2024/989.pdf),  [PHE](https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-lai.pdf), and [PBCS](https://www.usenix.org/system/files/sec22-chen-long.pdf).

## How to run

### Dependencies

- Crypto++ 8.6.0
- PBC 0.5.14

### Running the repo

Clone this repo. Make sure `g++` and `cmake` have been installed. (Linux)
Build and run the experiment locally.

```
cd Build
cmake ..
make
./build < ../Param/a.param
```