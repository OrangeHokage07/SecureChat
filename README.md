# Secure File Transfer with Role-Based Encryption

This is a Flask-based secure file sharing system that implements role-based access control and encryption using digital certificates. It ensures secure distribution of files, where access and visibility are determined by the user’s role: Admin, Subscriber, or Regular User.

## Features

- Role-Based Access Control (Admin, Subscriber, Regular User)
- Encrypted file uploads by Admin using OpenSSL
- Decryption of files by Subscribers through private key upload
- Blurred previews for unauthorized users
- Automatic certificate generation on Subscriber registration
- Distinct UI experience for each user role
- Admin dashboard for uploading and managing files

## Technologies Used

- Python (Flask)
- OpenSSL (Encryption and Certificate Generation)
- HTML/CSS (Frontend)
- SQLite (User and File Management Database)
- Werkzeug (Password hashing and security)
