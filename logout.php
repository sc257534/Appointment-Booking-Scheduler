<?php
// =========================================================================
// This script securely logs out the current user by destroying their session.
// It should be accessed directly via a link or a button.
// =========================================================================

// Start the session to ensure all session variables are available.
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Log the user out and redirect.
if (isset($_SESSION['loggedIn']) && $_SESSION['loggedIn'] === true) {
    // Unset all session variables.
    $_SESSION = [];

    // Destroy the session cookie.
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }

    // Finally, destroy the session.
    session_destroy();
}

// Redirect to the login page regardless of whether a session existed.
header("Location: index.php");
exit;
?>
