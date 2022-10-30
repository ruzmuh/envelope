# go-envelope
# About the project
It's kind a envelope encryption implementation written on go. The project includes a package and cmd application implementation. 
# Getting Started
## Installation
Install a package:
```
go get github.com/ruzmuh/envelope
```
Install a cmd tool:
```
go install github.com/ruzmuh/envelope/cmd/envelope
```
## Usage

In order to encrypt and decrypt files, you need suitable keys fo phase1. For example, if you're going to use AES_128_CBC phase1, you must pass 128bit (16bytes) key in base64 format. To generate such key:
```
dd if=/dev/urandom bs=16 count=1 status=none | base64
```
Encrypt a file:
```
envelope -i file1.txt -o encrypted -k 4e3mwkQyQnwVMpd27Tt7dg=
```
Decrypt a file:
```
envelope -i encrypted -o decrypted.txt -d -k 4e3mwkQyQnwVMpd27Tt7dg=
```
## 