# COMPE 560 Homework 1: UDP-based Secured Chat Application

**Date:** May 05, 2025  
**Author:** Krishna Vardhan Nagaraja (132711056)  
**Email:** knagaraja3869@sdsu.edu  

## Overview
This project implements a **UDP-based secured chat application** using **RSA**, **AES**, and **HMAC** for encryption and authentication. The goal of this homework is to design a secure communication system with robust cryptographic protocols.

## Files
The zip folder contains the following files:

1. **client.py**: The main script to start the client application.
2. **server.py**: The main script to start the server application.
3. **crypto_utls.py**: Contains six different cryptographic utilities used for encryption and authentication.
4. **README.md**: This file.
5. **hw1report_132711056.pdf**: The report file.

## Requirements
Install the necessary Python packages:

```bash
pip install PySide6 pycryptodome

HOW TO RUN:

1. SERVER : python server.py
2. CLIENT : python client.py

Sphinx Documentation

To generate a sphinx document

navigate to docs folder

cd docs

and run 

make html 

#which generates a html document

#for accessing document you can run

open docs/_build/html/index.html 