# Decentralized Security Log Integrity System Using Algorand

A tamper-evident security log audit and verification platform built with **Java 17**, **MySQL / SQLite JDBC**, **SHA-256 cryptography**, and the **Algorand Blockchain**.

## Problem Statement & Architecture

In traditional centralized systems, attackers or malicious insiders who gain database privileges can silently edit or delete rows in security log tables to hide unauthorized actions.

**AlgoLogGuard** eliminates silent log tampering using a hybrid **Off-Chain SQL + On-Chain Algorand Anchoring** architecture:

1. **Off-Chain Relational Storage (`MySQL / SQLite JDBC`):** Raw syslog events (`severity`, `source`, `message`) are stored locally in the `security_logs` SQL table via parameterized `PreparedStatement` queries—keeping sensitive IP addresses and usernames private and avoiding high on-chain storage costs.
2. **Cryptographic Fingerprinting (`SHA-256`):** Each log entry is hashed using `java.security.MessageDigest` (`SHA-256`) to generate a deterministic 64-character hexadecimal digest.
3. **Immutable Blockchain Anchoring (`Algorand SDK`):** The SHA-256 digest is embedded into the `note` field (`ALGOLOG|v1|<SEVERITY>|<SOURCE>|<SHA256>`) of a `0-ALGO` transaction signed on the **Algorand TestNet** (~3.3s finality, `0.001 ALGO` fee).
4. **Real-Time Tamper Detection:** During integrity audits, the backend recomputes the SHA-256 hash of every SQL row and compares it against the anchored hash. Modifying even a single character in SQL immediately triggers a **`TAMPER DETECTED`** alert.

## Repository Structure

```text
├── AlgorandLogIntegritySystem.java   # Multi-threaded Java HTTP Server, JDBC SQL Repo, & Algorand SDK Signer
├── index.html                        # Standalone Web UI (Home Overview + Live Audit Console)
├── pom.xml                           # Maven dependencies (algosdk, mysql-connector-j, sqlite-jdbc)
├── .gitignore                        # Excludes compiled binaries, local DBs, and secret env files
└── README.md                         # Setup & deployment documentation
```

## Quick Start (Maven + Java 17)

### 1. Prerequisites
* **Java Development Kit (JDK) 17+**
* **Apache Maven 3.8+**
* **MySQL 8.0+** (or run with embedded SQLite—no database server required)

### 2. Configure MySQL Database
Create the database in MySQL (the Java backend automatically creates the `security_logs` table on startup):
```sql
CREATE DATABASE IF NOT EXISTS algorand_logs;
```

### 3. Set Environment Variables (Optional for Live TestNet Signing)
To broadcast real transactions to the **Algorand TestNet**, fund a free TestNet wallet via the [Algorand TestNet Dispenser](https://bank.testnet.algorand.network/) and set your environment variables:
```bash
export DB_URL="jdbc:mysql://localhost:3306/algorand_logs?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC"
export DB_USER="root"
export DB_PASS="your_mysql_password"
export ALGO_MNEMONIC="your twenty five word algorand testnet mnemonic phrase here"
```
*(Note: If `ALGO_MNEMONIC` is omitted, the system automatically runs in safe simulation mode while still syncing live block rounds from `testnet-api.algonode.cloud`.)*

### 4. Compile & Run
```bash
mvn clean compile exec:java
```
Open your browser at **`http://localhost:8080`**.

## Live Interactive Demo Features
* **Home & Architecture Overview:** Explains the dual SQL + Algorand integrity pipeline.
* **Ingest & Anchor Security Logs:** Create `CRITICAL`, `WARNING`, or `INFO` logs with live SHA-256 preview.
* **Simulate SQL Tamper:** Click **Simulate SQL Tamper** on any verified log to alter its SQL payload and immediately observe the SHA-256 mismatch detection, then click **Restore SQL Row** to revert it.