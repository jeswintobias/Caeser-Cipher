# Caesar Cipher Secure Messaging System

## 🛡️ Overview
This project implements a **secure messaging system** using the **Caesar cipher** encryption technique. It provides functionalities for user authentication, group messaging with encryption, and administrative controls. The system ensures secure communication through password-protected access and encrypted message exchanges.

---

## ✨ Features

### 👤 User Management
- **Registration**: Users can register with a username and a strong password.
  - Password must include:
    - At least **4 digits**
    - At least **2 letters**
    - At least **1 special character**
- **Login**: Secure login with username and private key.
- **User Roles**: Supports both **Admin** and **Standard** user roles with different privileges.

### 🔐 Encryption & Decryption
- **Caesar Cipher**: Encrypts and decrypts messages using a shift-based Caesar cipher algorithm.
- **Secure Storage**: User credentials and private keys are securely stored and managed.

### 💬 Group Messaging
- **Group Creation**: Admins can create groups with:
  - Unique public keys
  - Referral codes
- **Group Joining**: Users can join groups using valid referral codes.
- **Encrypted Messaging**: Members can send encrypted messages within groups.
- **Message Expiration**: Messages can be set to expire after a specified duration.

### 🛠️ Admin Features
- **View Decrypted Messages**: Admins can view decrypted messages for monitoring.
- **Group Management**: Admins can delete groups or remove members.
- **User Status Monitoring**: Admins can view user online status and activity.


