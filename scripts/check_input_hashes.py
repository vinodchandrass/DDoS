#!/usr/bin/env python3
"""Read-only SHA-256 verification for locally authorized research inputs."""
import argparse
import hashlib
from pathlib import Path

def sha256(path):
    digest=hashlib.sha256()
    with open(path,"rb") as stream:
        for chunk in iter(lambda:stream.read(8*1024*1024),b""):
            digest.update(chunk)
    return digest.hexdigest()

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("file",type=Path)
    parser.add_argument("--expected",help="Expected SHA-256 hexadecimal digest")
    args=parser.parse_args()
    actual=sha256(args.file)
    print(f"SHA256 {actual}  {args.file.name}")
    if args.expected:
        expected=args.expected.lower().strip()
        if actual!=expected:
            raise SystemExit("FAIL: input hash mismatch")
        print("PASS: frozen input hash matched")

if __name__=="__main__":
    main()
