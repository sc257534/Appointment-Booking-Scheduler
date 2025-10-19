# Appointment-Booking-Scheduler
A secure, dual-panel (Admin and User) appointment booking system built with PHP, PDO, and MySQL, featuring role-based access, CSRF protection, and session management.
A secure and robust web-based appointment booking application built with PHP and MySQL. This system provides a clean user dashboard for booking and managing appointments, and a comprehensive admin panel for complete system management, user control, and operational oversight.

The application is built with a strong emphasis on security, implementing measures such as prepared statements (PDO) to prevent SQL injection, CSRF token protection, session inactivity timeouts, and secure password handling.

---

## 📸 Screenshots


Login Page : <img width="1918" height="926" alt="image" src="https://github.com/user-attachments/assets/d98c9afa-9bac-45bf-b501-445601246791" />
Admin Dashboard: <img width="1919" height="925" alt="image" src="https://github.com/user-attachments/assets/afbc9f3a-c008-41d1-9c4b-4aca6a514bb7" />
User Dashboard: <img width="1895" height="929" alt="image" src="https://github.com/user-attachments/assets/ef86260b-aaa2-4218-9baa-4cda0d8ede34" />


-   -   -   
---

## ✨ Key Features

The system is split into two main dashboards, each with its own set of features.

### 👤 User Dashboard (`/user/dashboard.php`)

* **Secure Login:** Users log in through a secure portal.
* **Session Management:** Features a 5-minute inactivity timeout for enhanced security.
* **Book Appointments:** An intuitive interface to select a service, date, and available time slot.
* **Dynamic Slot Loading:** Fetches available slots in real-time based on service duration, existing bookings, and daily breaks.
* **Booking Rules:** Enforces rules such as no bookings on Sundays and a 2-working-day advance booking limit.
* **Manage Appointments:** Users can view, reschedule, and cancel their own upcoming appointments.
* **Change Password:** Users can update their own password.
* **CSRF Protection:** All POST requests (booking, canceling, etc.) are protected with CSRF tokens.

### 👑 Admin Dashboard (`/admin/dashboard.php`)

* **Admin-Specific Login:** Admins are redirected to a separate, more powerful dashboard upon login.
* **Secure Session:** Features a 15-minute inactivity timeout.
* **Appointment Management:** View, edit, reschedule, and cancel appointments for *all* users on any given day.
* **Manual Overbooking:** Admins have the permission to override booking rules and book a slot even if it's already taken (for the current day only).
* **Service Management (CRUD):** Add, edit, and delete services and their categories.
* **Booking Rule Management (CRUD):** Create, edit, and delete service-specific rules (e.g., allowed days, buffer times, max bookings per day).
* **Roster Management:**
    * Block off specific one-time slots (e.g., for meetings).
    * Set recurring daily breaks (e.g., lunch).
* **User Management (CRUD):**
    * Add, edit, and delete users (both admins and regular users).
    * Activate or deactivate user accounts.
    * Reset any user's password.
* **Day-End Reports:** Generate and download PDF reports of all *completed* appointments for a selected day.
* **Audit Logs:** View a log of all significant actions taken within the admin panel for accountability and security monitoring.
* **Log Cleanup:** Automatically purges audit logs older than 15 days to maintain database health.

---

## 🔒 Security Features

Security was a primary focus for this project.

* **SQL Injection Prevention:** Uses **PDO (PHP Data Objects)** with **prepared statements** for all database interactions.
* **Cross-Site Request Forgery (CSRF) Protection:** All state-changing actions (bookings, cancellations, user edits) are protected by unique, session-based CSRF tokens.
* **Secure Password Handling:** Uses `password_hash()` and `password_verify()` for all user passwords.
* **Session Security:**
    * Role-based access control (RBAC) to separate user and admin functionality.
    * Strict session inactivity timeouts (5 mins for users, 15 for admins).
    * Secure logout script that destroys the session, unsets variables, and clears the session cookie.
* **Server Configuration (`.htaccess`):**
    * Enforces **HTTPS** on all traffic.
    * Prevents directory listing (`Options -Indexes`).
    * Blocks web access to sensitive files like `.env`, `db_config.php`, and `.htaccess` itself.
    * Applies security headers (X-Frame-Options, X-Content-Type-Options) to mitigate clickjacking and MIME-sniffing attacks.
* **Secure File Structure:**
    * Database credentials are intended to be stored in a `.env` file outside the web root (though they are hardcoded in `db_config.php` as a fallback).

---

## 💻 Technology Stack

* **Backend:** PHP (v7.4+)
* **Database:** MySQL
* **Database Connection:** PDO (PHP Data Objects)
* **Frontend:** HTML5, CSS3 (with Flexbox/Grid), JavaScript (ES6+)
* **API Format:** Asynchronous RESTful API calls handled by the dashboard files themselves, returning JSON.
* **Server:** Apache (implied by `.htaccess`)

---

## 🚀 Setup and Installation

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/sc257534/Appointment-Booking-Scheduler.git](https://github.com/your-username/Appointment-Booking-Scheduler.git)
    cd Appointment-Booking-Scheduler
    ```

2.  **Database Configuration:**
    * Import the `database.sql` file (not provided, you should create and add this) into your MySQL database (e.g., via phpMyAdmin).
    * Create a `.env` file in the root directory. Copy the contents of the provided `.env` file and update the credentials to match your local database:
        ```ini
        DB_HOST="your_db_host"
        DB_NAME="your_db_name"
        DB_USER="your_db_user"
        DB_PASS="your_db_password"
        DB_CHARSET="utf8mb4"
        DB_TIMEZONE="Asia/Kolkata"
        ```
    * **Alternatively:** You can directly edit the credentials in `db_config.php` if you are not using an environment variable loader.

3.  **Configure Your Web Server (Apache):**
    * Ensure your Apache server has `mod_rewrite` enabled to process the `.htaccess` file.
    * Point your virtual host's document root to the `Appointment-Booking-Scheduler` directory.
    * It is highly recommended to set up an SSL certificate (e.g., via Let's Encrypt) to allow the `Force HTTPS` rule in `.htaccess` to function correctly.

4.  **Create Users:**
    * You will need to manually insert at least one admin and one user into your `users` table to log in.
    * **Admin:**
        ```sql
        INSERT INTO users (username, name, hash, role, isFirstLogin, isActive)
        VALUES ('admin', 'Admin User', '$2y$10$your_password_hash', 'admin', 0, 1);
        ```
    * **User:**
        ```sql
        INSERT INTO users (username, name, hash, role, isFirstLogin, isActive)
        VALUES ('user', 'Test User', '$2y$10$your_password_hash', 'user', 0, 1);
        ```
    * *(Use a PHP script with `password_hash("your_password", PASSWORD_DEFAULT)` to generate the hashes.)*

5.  **Run the Application:**
    * Access the `index.php` file in your browser to log in.

---

## 📁 File Structure
.
├── .env
├── .htaccess
├── db_config.php
├── index.php
├── logout.php
│
├── admin/
│   ├── dashboard.php
│   └── logout.php
│
└── user/
    └── dashboard.php
