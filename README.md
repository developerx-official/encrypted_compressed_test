# Encrypted Compressed Test
An example project to demonstrate basic encryption, compression, and other introductionary concepts written entirely in Rust

Inside src/main.rs you'll find the main method and helper methods.
The app:
- Compresses, encrypts, then writes from the input file.
- Decrypts to a temp file, decompresses that file, then deletes the temp file.
- Writes the decompressed output to a final file that should match the input file.
