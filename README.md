# CipherShield
CipherShield is a console-based C application for encrypting, decrypting, and viewing text files. It provides a simple login screen and supports several classical and educational encryption algorithms.
> **Important:** This project is intended for learning and demonstration. The built-in RSA uses small fixed primes, DES is represented by a simple XOR-based routine, and credentials are hard-coded. Do not use it to protect sensitive or production data.
## Features
- Encrypt and decrypt files from an interactive menu
- View the contents of a file
- Six selectable algorithms:
  - XOR encryption
  - Caesar cipher
  - Substitution cipher
  - RSA encryption
  - DES-style block processing
  - Playfair cipher
- Colored terminal output where ANSI escape codes are supported
- Windows console support for enabling ANSI escape codes
## Requirements
- A C compiler such as GCC
- A terminal capable of running console applications
- Code::Blocks (optional; `CipherShield.cbp` is included)
## Build
From the project directory, compile with GCC:
```bash
gcc -Wall -O2 main.c -o CipherShield
```
On Linux or macOS, run:
```bash
./CipherShield
```
On Windows with MinGW:
```powershell
gcc -Wall -O2 main.c -o CipherShield.exe
.\CipherShield.exe
```
You can also open `CipherShield.cbp` in Code::Blocks and build the Debug or Release target.
## Usage
1. Start the application.
2. Log in with the default credentials:
   - **Username:** `admin`
   - **Password:** `password`
3. Choose an action:
   - Encrypt a file
   - Decrypt a file
   - View a file's content
   - Exit
4. For encryption or decryption, select an algorithm and provide the input filename, output filename, and password.
Example files are included in the repository:
```text
input.txt
output.txt
out.txt
```
## Algorithm notes
- **XOR:** Uses the first character of the password as the XOR key.
- **Caesar:** Uses the first password character to derive the alphabetic shift.
- **Substitution:** Uses the fixed `QWERTYUIOPASDFGHJKLZXCVBNM` substitution table.
- **RSA:** Generates a fixed demonstration key from the primes `199` and `211`.
- **DES:** Processes eight-byte blocks with a password-derived XOR key; this is not a real DES implementation.
- **Playfair:** Builds a 5×5 key matrix, treats `J` as `I`, removes non-letters, and adds `X` padding when needed.
The application processes text files and may change formatting or non-alphabetic characters depending on the selected algorithm.
## Project structure
```text
main.c              Application source code
CipherShield.cbp    Code::Blocks project file
input.txt           Sample input file
output.txt          Sample output file
out.txt             Sample transformed output
```
## License
No license has been specified for this project.
