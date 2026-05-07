# 🛡️ University Security Portal

A secure web application for university management built with Flask.
Demonstrates Authentication, Role-Based Access Control (RBAC), and Encryption.

> 📚 Project for **SWE210 - Software Security** course at **Istinye University**

---

## ✨ Features

### 🔐 Authentication
- User registration and login system
- Secure password hashing using Werkzeug (PBKDF2 with SHA-256)
- Session management with Flask-Login

### 🛡️ Access Control (RBAC)
- Three user roles: **Admin**, **Teacher**, **Student**
- Custom decorator (`@role_required`) for protecting routes
- Each role has its own dashboard with restricted access

### 🔒 Encryption
- Sensitive data encrypted using **Fernet (AES-128 + HMAC-SHA256)**
- Encrypted fields: National ID, Phone Number, Grades
- Automatic encryption on save, decryption on view

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Installation

1. Clone the repository: