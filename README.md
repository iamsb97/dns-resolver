# DNS Resolver

A simple DNS resolver implemented in C for educational purposes. This project demonstrates how the Domain Name System (DNS) works at a low level by sending and parsing raw DNS packets.

## About

This project was built to learn how DNS resolution works without relying on high-level libraries. The resolver:
- Constructs and sends DNS queries using UDP.
- Parses DNS responses manually (A, NS, and CNAME records)
- Handles recursion manually (follows NS records to authoritative servers)
- Provides insight into the DNS resolution process

## Goals

- Understand DNS packet structure (headers, questions, answers)
- Learn how recursive resolution works
- Practice working with raw sockets and bit-level data handling in C
- Build a functional, self-contained CLI DNS resolver

## Build Instructions

```bash
> make
```

## Usage

```bash
> ./dns_resolver www.google.com
Querying 198.41.0.4 for www.google.com
Querying 192.41.162.30 for www.google.com
Querying 216.239.34.10 for www.google.com

'142.250.206.36'
```

## What’s Missing / Future Work

- Support for more record types (AAAA/MX,etc)
- Optimize execution
- Improve error catching and handling