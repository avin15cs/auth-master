# 🚀 Auth-Master — OAuth2 Authorization & Resource Server

**auth-master** is a complete Java-based implementation of an **OAuth2 Authorization Server** + **Resource Server** with JWT authentication, role-based access control, and best-practice security design.

It serves both **machine-to-machine** and **user/browser login** scenarios using OAuth2 flows such as **Client Credentials** and **Authorization Code**. :contentReference[oaicite:0]{index=0}

---

## 📌 Overview

This project demonstrates how to build a robust authentication and authorization system using:

- Spring Authorization Server  
- JWT (JSON Web Tokens) with RSA asymmetric signing  
- Role-based access control  
- OAuth2 flows: Client Credentials & Authorization Code  
- Resource protection with Spring Security  
- Token validation and JWKS public key endpoints :contentReference[oaicite:1]{index=1}

---

## 🧱 Architecture

```mermaid
graph TD
  User((User/Browser))
  ClientApp((Client App/Script))
  AuthServer[Authorization Server :8443]
  ResourceServer[Resource Server :8080]
  
  User --> AuthServer
  ClientApp --> AuthServer
  AuthServer --> ResourceServer
  User --> ResourceServer
  ClientApp --> ResourceServer
