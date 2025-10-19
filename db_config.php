<?php
/**
 * Secure Database Configuration and Connection
 *
 * This script establishes a secure PDO connection to the database.
 * The connection uses prepared statements and handles errors gracefully.
 *
 * NOTE: For production, it's highly recommended to use environment variables
 * to store credentials and avoid hardcoding them directly in the file.
 *
 * @return PDO|void Returns the PDO object on success, or exits on failure.
 */

// --- Database Credentials ---
// ⚠️ IMPORTANT: You must replace these placeholder values with your actual
// database credentials from your ezyro.com hosting panel.
// Common issues: 'localhost' is often the correct host, not the domain name.
define('DB_HOST', 'Your_Host_Name'); // <-- Verify this host with your provider.
define('DB_NAME', 'Your_DB_Name'); // <-- Your database name.
define('DB_USER', 'Your_UserName'); // <-- Your database user.
define('DB_PASS', 'Password'); // <-- Your database password.
define('DB_CHARSET', 'utf8mb4');
define('DB_TIMEZONE', '+5:30'); // Indian Standard Time (IST) is UTC+05:30

// --- PDO Connection Logic ---
$dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET;

$options = [
    // Throw an exception on error, which is crucial for secure and reliable code.
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    // Fetch results as associative arrays by default.
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    // Disable emulated prepared statements for security against SQL injection.
    PDO::ATTR_EMULATE_PREPARES   => false,
    // Set the database timezone on connection to ensure time-related functions are consistent.
    PDO::MYSQL_ATTR_INIT_COMMAND => "SET time_zone = '" . DB_TIMEZONE . "'"
];

try {
    // Attempt to create a new PDO instance and return it.
    $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
    return $pdo;
} catch (PDOException $e) {
    // If connection fails, log the detailed error for debugging.
    error_log("Database connection error: " . $e->getMessage());

    // Display a generic, non-informative message to the public.
    http_response_code(500);
    exit(json_encode([
        'success' => false,
        'message' => 'Internal server error: Could not connect to the database. Please contact support.'
    ]));
}
