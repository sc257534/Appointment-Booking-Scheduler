<?php
// --- START OF PHP LOGIC ---
// This file is the secure login page for the user portal.

require_once 'db_config.php';

// Session Security Configuration
ini_set('session.use_only_cookies', 1);
ini_set('session.cookie_httponly', 1);
// Note: For production, set to 1 for HTTPS
// ini_set('session.cookie_secure', 1);
ini_set('session.cookie_samesite', 'Strict');

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
date_default_timezone_set('Asia/Kolkata');

// The required PDO object is now imported from db_config.php
// The following block of code is removed as it's redundant and faulty.
// try {
//     $options = [
//         PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
//         PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
//         PDO::ATTR_EMULATE_PREPARES => false,
//     ];
//     $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
//     $pdo->exec("SET time_zone = '" . DB_TIMEZONE . "';");
// } catch (PDOException $e) {
//     error_log("Database connection error: " . $e->getMessage());
//     http_response_code(500);
//     exit("Internal server error. Please try again later.");
// }

// Set the timezone for the PDO connection using the constant from the .env file
$pdo->exec("SET time_zone = '+05:30';");
// --- THE CORE SESSION LOGIC ---
if (empty($_SESSION['page_state']) || (isset($_GET['action']) && $_GET['action'] === 'cancel')) {
    session_unset();
    session_destroy();
    session_start();
}

$pageState = 'login';

function getClientIp() {
    foreach (['HTTP_CLIENT_IP','HTTP_X_FORWARDED_FOR','HTTP_X_REAL_IP','REMOTE_ADDR'] as $key) {
        if (!empty($_SERVER[$key])) {
            $ipList = explode(',', $_SERVER[$key]);
            return trim($ipList[0]);
        }
    }
    return 'UNKNOWN';
}

function logLoginAction($pdo, $action, $username = 'N/A', $userId = NULL) {
    $ip = getClientIp();
    $location = 'Unknown';
    $context = stream_context_create(['http' => ['timeout' => 2]]);
    try {
        $geo_response = @file_get_contents("http://ip-api.com/json/{$ip}", false, $context);
        if ($geo_response) {
            $geo_data = json_decode($geo_response, true);
            if ($geo_data && $geo_data['status'] === 'success') {
                $location = implode(', ', array_filter([$geo_data['city'], $geo_data['regionName'], $geo_data['country']]));
            }
        }
    } catch (Exception $e) {
        // Log the error but don't stop the script.
        error_log("Failed to get geolocation for IP: " . $ip . " - " . $e->getMessage());
    }

    $stmt = $pdo->prepare("INSERT INTO audit_logs (timestamp, action, user_id, username, ip, location) VALUES (NOW(), ?, ?, ?, ?, ?)");
    $stmt->execute([$action, $userId, $username, $ip, $location]);
}

$errorMessage = '';
$successMessage = '';
$securityQuestions = [
    "What was your first pet's name?",
    "What is your mother's maiden name?",
    "What city were you born in?"
];

if (isset($_SESSION['page_state'])) {
    $pageState = $_SESSION['page_state'];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? 'login';
    $username = trim($_POST['username'] ?? $_SESSION['reset_username'] ?? '');
    $userFound = null;

    if (!empty($username)) {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $userFound = $stmt->fetch(PDO::FETCH_ASSOC);
    }

    switch ($action) {
        case 'login':
            $password = $_POST['password'] ?? '';
            if (empty($username) || empty($password)) {
                $errorMessage = 'Please enter both username and password.';
                logLoginAction($pdo, 'Failed login (missing credentials)', $username);
            } elseif ($userFound && $userFound['isActive'] && password_verify($password, $userFound['hash'])) {
                if ($userFound['role'] === 'user') {
                    if ($userFound['isFirstLogin']) {
                        $_SESSION['page_state'] = 'first_time_setup';
                        $_SESSION['reset_username'] = $userFound['username'];
                        $pageState = 'first_time_setup';
                        logLoginAction($pdo, 'User logged in for first-time setup', $userFound['username'], $userFound['id']);
                        break;
                    }
                    $lastChanged = new DateTime($userFound['passwordLastChanged'] ?? '1970-01-01');
                    if ($lastChanged->diff(new DateTime())->days > 30) {
                        $_SESSION['page_state'] = 'password_expired';
                        $_SESSION['reset_username'] = $userFound['username'];
                        $pageState = 'password_expired';
                        logLoginAction($pdo, 'User redirected to password reset (expired)', $userFound['username'], $userFound['id']);
                        break;
                    }
                }

                session_regenerate_id(true);
                $_SESSION['loggedin'] = true;
                $_SESSION['username'] = $userFound['username'];
                $_SESSION['role'] = $userFound['role'];

                logLoginAction($pdo, 'Successful login', $userFound['username'], $userFound['id']);

                header('Location: ' . ($userFound['role'] === 'admin' ? 'admin/dashboard.php' : 'user/dashboard.php'));
                exit;
            } else {
                $errorMessage = 'Invalid username or password.';
                logLoginAction($pdo, 'Failed login (incorrect password)', $username);
            }
            break;

        case 'first_time_setup':
            $newPassword = $_POST['new_password'];
            $pin = $_POST['pin'];
            $securityQ = $_POST['security_question'];
            $securityA = trim($_POST['security_answer']);
            if (strlen($newPassword) < 8 || !preg_match('/^\d{4}$/', $pin) || empty($securityA)) {
                $errorMessage = 'Please fill all fields with valid data.';
                $pageState = 'first_time_setup';
            } else {
                $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
                $hashedPin = password_hash($pin, PASSWORD_DEFAULT);
                $hashedAnswer = password_hash(strtolower($securityA), PASSWORD_DEFAULT);

                $stmt = $pdo->prepare("UPDATE users SET hash = ?, pin = ?, security_question = ?, security_answer_hash = ?, isFirstLogin = 0, passwordLastChanged = NOW() WHERE username = ?");
                $stmt->execute([$hashedPassword, $hashedPin, $securityQ, $hashedAnswer, $username]);

                logLoginAction($pdo, 'First-time security setup completed', $username);
                unset($_SESSION['reset_username']);
                unset($_SESSION['page_state']);
                header("Location: index.php?status=setup_success");
                exit;
            }
            break;

        case 'forgot_username':
            if ($userFound && $userFound['role'] === 'user') {
                $_SESSION['reset_username'] = $userFound['username'];
                $_SESSION['page_state'] = 'forgot_pin';
                header("Location: index.php");
                exit;
            } else {
                $errorMessage = "We can't find a user with that account name.";
                $pageState = 'login';
            }
            break;

        case 'forgot_pin':
            if (isset($_SESSION['reset_username']) && !empty($_SESSION['reset_username'])) {
                $stmt = $pdo->prepare("SELECT pin FROM users WHERE username = ?");
                $stmt->execute([$_SESSION['reset_username']]);
                $userFound = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if ($userFound && password_verify($_POST['pin'], $userFound['pin'] ?? '')) {
                    $_SESSION['page_state'] = 'forgot_security_question';
                    header("Location: index.php");
                    exit;
                } else {
                    $errorMessage = 'Invalid PIN.';
                    $pageState = 'forgot_pin';
                }
            } else {
                $errorMessage = 'Session expired or invalid request.';
                $pageState = 'login';
            }
            break;

        case 'forgot_security_question':
            if (isset($_SESSION['reset_username'])) {
                $stmt = $pdo->prepare("SELECT security_answer_hash FROM users WHERE username = ?");
                $stmt->execute([$_SESSION['reset_username']]);
                $userFound = $stmt->fetch(PDO::FETCH_ASSOC);

                if ($userFound && password_verify(strtolower(trim($_POST['security_answer'])), $userFound['security_answer_hash'] ?? '')) {
                    $_SESSION['page_state'] = 'forgot_reset_password';
                    header("Location: index.php");
                    exit;
                } else {
                    $errorMessage = 'Incorrect answer.';
                    $pageState = 'forgot_security_question';
                }
            } else {
                $errorMessage = 'Session expired or invalid request.';
                $pageState = 'login';
            }
            break;

        case 'password_expired':
        case 'forgot_reset_password':
            $newPassword = $_POST['new_password'];
            if (strlen($newPassword) < 8) {
                $errorMessage = 'Password must be at least 8 characters long.';
                $pageState = $_SESSION['page_state'];
            } else {
                $newHashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
                $stmt = $pdo->prepare("UPDATE users SET hash = ?, passwordLastChanged = NOW(), isFirstLogin = 0 WHERE username = ?");
                $stmt->execute([$newHashedPassword, $username]);
                
                logLoginAction($pdo, 'Password successfully reset', $username);
                unset($_SESSION['reset_username']);
                unset($_SESSION['page_state']);
                header("Location: index.php?status=reset_success");
                exit;
            }
            break;
    }
}

if (isset($_GET['status'])) {
    if ($_GET['status'] === 'setup_success') {
        $successMessage = "Security setup complete. Please log in.";
    }
    if ($_GET['status'] === 'reset_success') {
        $successMessage = "Password reset successfully. Please log in.";
    }
}

if (isset($_GET['action'])) {
    if ($_GET['action'] === 'forgot') {
        $_SESSION['page_state'] = 'forgot_username';
        $pageState = 'forgot_username';
    } elseif ($_GET['action'] === 'cancel') {
        session_unset();
        session_destroy();
        session_start();
        $pageState = 'login';
    }
}

if (isset($_SESSION['reset_username'])) {
    $username = $_SESSION['reset_username'];
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $userFound = $stmt->fetch(PDO::FETCH_ASSOC);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Secure Portal Login</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary: #4361ee;
            --primary-dark: #3a56d4;
            --secondary: #6c63ff;
            --dark: #0f172a;
            --dark-light: #1e293b;
            --light: #f8fafc;
            --muted: #94a3b8;
            --success: #10b981;
            --error: #ef4444;
            --border-radius: 16px;
            --box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
            --transition: all 0.3s ease;
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Inter', sans-serif;
        }
        
        body {
            background: linear-gradient(135deg, var(--dark) 0%, #1e293b 100%);
            color: var(--light);
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 1rem;
            position: relative;
            overflow: hidden;
        }
        
        /* 3D Animated Background Elements */
        .bg-shapes {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
            overflow: hidden;
        }
        
        .shape {
            position: absolute;
            border-radius: 50%;
            opacity: 0.1;
            animation: float 15s infinite linear;
        }
        
        .shape:nth-child(1) {
            width: 400px;
            height: 400px;
            background: var(--primary);
            top: -100px;
            left: -100px;
            animation-delay: 0s;
            animation-duration: 25s;
        }
        
        .shape:nth-child(2) {
            width: 300px;
            height: 300px;
            background: var(--secondary);
            bottom: -50px;
            right: -50px;
            animation-delay: -5s;
            animation-duration: 20s;
        }
        
        .shape:nth-child(3) {
            width: 200px;
            height: 200px;
            background: var(--success);
            top: 50%;
            left: 70%;
            animation-delay: -10s;
            animation-duration: 15s;
        }
        
        @keyframes float {
            0% {
                transform: translate(0, 0) rotate(0deg);
            }
            50% {
                transform: translate(20px, 20px) rotate(180deg);
            }
            100% {
                transform: translate(0, 0) rotate(360deg);
            }
        }
        
        .login-container {
            background: rgba(30, 41, 59, 0.85);
            backdrop-filter: blur(10px);
            border-radius: var(--border-radius);
            padding: 2.5rem;
            width: 100%;
            max-width: 450px;
            box-shadow: var(--box-shadow);
            border: 1px solid rgba(255, 255, 255, 0.1);
            transform-style: preserve-3d;
            perspective: 1000px;
            transition: var(--transition);
            position: relative;
            overflow: hidden;
        }
        
        .login-container::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 5px;
            background: linear-gradient(90deg, var(--primary), var(--secondary));
        }
        
        .header {
            text-align: center;
            margin-bottom: 2rem;
            position: relative;
        }
        
        .logo {
            width: 80px;
            height: 80px;
            margin: 0 auto 1rem;
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 10px 20px rgba(67, 97, 238, 0.3);
            transform: translateZ(20px);
            transition: var(--transition);
        }
        
        .logo:hover {
            transform: translateZ(20px) scale(1.05);
        }
        
        .logo i {
            font-size: 2rem;
            color: white;
        }
        
        .header h1 {
            font-size: 1.75rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            background: linear-gradient(90deg, var(--light) 0%, var(--muted) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .header p {
            color: var(--muted);
            font-size: 0.95rem;
        }
        
        .form-group {
            margin-bottom: 1.5rem;
            position: relative;
        }
        
        .form-label {
            display: block;
            margin-bottom: 0.5rem;
            font-size: 0.875rem;
            color: var(--muted);
            font-weight: 500;
        }
        
        .form-control {
            width: 100%;
            padding: 0.875rem 1rem;
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            color: var(--light);
            transition: var(--transition);
            font-size: 1rem;
        }
        
        .form-control:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(67, 97, 238, 0.3);
            transform: translateY(-2px);
        }
        
        .btn {
            width: 100%;
            padding: 1rem 1.25rem;
            border-radius: 10px;
            border: none;
            font-weight: 600;
            cursor: pointer;
            transition: var(--transition);
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            color: white;
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            font-size: 1rem;
            box-shadow: 0 4px 6px rgba(67, 97, 238, 0.2);
            transform: translateY(0);
            position: relative;
            overflow: hidden;
        }
        
        .btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
            transition: 0.5s;
        }
        
        .btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 20px rgba(67, 97, 238, 0.3);
        }
        
        .btn:hover::before {
            left: 100%;
        }
        
        .btn:active {
            transform: translateY(0);
        }
        
        .footer-link {
            text-align: center;
            font-size: 0.875rem;
            color: var(--muted);
            margin-top: 1.5rem;
        }
        
        .footer-link a {
            color: var(--primary);
            text-decoration: none;
            font-weight: 500;
            transition: var(--transition);
            position: relative;
        }
        
        .footer-link a::after {
            content: '';
            position: absolute;
            bottom: -2px;
            left: 0;
            width: 0;
            height: 1px;
            background: var(--primary);
            transition: var(--transition);
        }
        
        .footer-link a:hover::after {
            width: 100%;
        }
        
        .message {
            padding: 1rem;
            margin-bottom: 1.5rem;
            border-radius: 10px;
            font-weight: 500;
            border: 1px solid transparent;
            transition: var(--transition);
            animation: slideIn 0.5s ease;
        }
        
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .error-message {
            background-color: rgba(239, 68, 68, 0.1);
            color: #f87171;
            border-color: rgba(239, 68, 68, 0.2);
        }
        
        .success-message {
            background-color: rgba(16, 185, 129, 0.1);
            color: #34d399;
            border-color: rgba(16, 185, 129, 0.2);
        }
        
        .toggle-password {
            position: absolute;
            right: 1rem;
            top: 70%;
            transform: translateY(-50%);
            cursor: pointer;
            color: var(--muted);
            transition: var(--transition);
        }
        
        .toggle-password:hover {
            color: var(--primary);
        }
        
        /* 3D Card Effect */
        .login-container {
            transform: perspective(1000px) rotateX(0) rotateY(0);
            transition: transform 0.3s ease;
        }
        
        /* Loading animation */
        .btn-loading {
            position: relative;
            color: transparent;
        }
        
        .btn-loading::after {
            content: '';
            position: absolute;
            width: 20px;
            height: 20px;
            border: 2px solid transparent;
            border-top: 2px solid white;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        /* Responsive adjustments */
        @media (max-width: 480px) {
            .login-container {
                padding: 1.5rem;
            }
            
            .logo {
                width: 60px;
                height: 60px;
            }
            
            .logo i {
                font-size: 1.5rem;
            }
            
            .header h1 {
                font-size: 1.5rem;
            }
        }
    </style>
</head>
<body>
    <div class="bg-shapes">
        <div class="shape"></div>
        <div class="shape"></div>
        <div class="shape"></div>
    </div>
    
    <div class="login-container" id="loginCard">
        <?php if (!empty($successMessage)): ?>
            <div class="message success-message">
                <i class="fas fa-check-circle"></i> <?= htmlspecialchars($successMessage) ?>
            </div>
        <?php endif; ?>
        
        <?php if (!empty($errorMessage)): ?>
            <div class="message error-message">
                <i class="fas fa-exclamation-circle"></i> <?= htmlspecialchars($errorMessage) ?>
            </div>
        <?php endif; ?>

        <?php if ($pageState === 'login'): ?>
            <div class="header">
                <div class="logo">
                    <i class="fas fa-lock"></i>
                </div>
                <h1>Secure Portal</h1>
                <p>Sign in to access your account</p>
            </div>
            <form method="POST" id="loginForm">
                <input type="hidden" name="action" value="login">
                <div class="form-group">
                    <label class="form-label">Username</label>
                    <input type="text" name="username" class="form-control" required autocomplete="username">
                </div>
                <div class="form-group">
                    <label class="form-label">Password</label>
                    <input type="password" name="password" id="login-password" class="form-control" required autocomplete="current-password">
                    <i class="fa fa-eye toggle-password" onclick="togglePassword(this, 'login-password')"></i>
                </div>
                <button type="submit" class="btn" id="loginBtn">
                    <i class="fas fa-sign-in-alt"></i> Sign In
                </button>
            </form>
            <p class="footer-link">Forgot your password? <a href="index.php?action=forgot">Reset it here</a></p>
        <?php endif; ?>

        <?php if ($pageState === 'first_time_setup'): ?>
            <div class="header">
                <div class="logo">
                    <i class="fas fa-user-cog"></i>
                </div>
                <h1>Security Setup</h1>
                <p>Welcome, <?= htmlspecialchars($_SESSION['reset_username'] ?? '') ?></p>
            </div>
            <form method="POST" id="setupForm">
                <input type="hidden" name="action" value="first_time_setup">
                <div class="form-group">
                    <label class="form-label">New Password</label>
                    <input type="password" name="new_password" id="setup-password" class="form-control" minlength="8" required>
                    <i class="fa fa-eye toggle-password" onclick="togglePassword(this, 'setup-password')"></i>
                </div>
                <div class="form-group">
                    <label class="form-label">4-Digit PIN</label>
                    <input type="password" name="pin" id="setup-pin" class="form-control" pattern="\d{4}" maxlength="4" required>
                    <i class="fa fa-eye toggle-password" onclick="togglePassword(this, 'setup-pin')"></i>
                </div>
                <div class="form-group">
                    <label class="form-label">Security Question</label>
                    <select name="security_question" class="form-control">
                        <?php foreach($securityQuestions as $q) echo "<option>".htmlspecialchars($q)."</option>"; ?>
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Answer</label>
                    <input type="text" name="security_answer" class="form-control" required>
                </div>
                <button type="submit" class="btn">
                    <i class="fas fa-check"></i> Complete Setup
                </button>
            </form>
        <?php endif; ?>

        <?php if ($pageState === 'password_expired' || $pageState === 'forgot_reset_password'): ?>
            <div class="header">
                <div class="logo">
                    <i class="fas fa-key"></i>
                </div>
                <h1>Set New Password</h1>
                <p>Enter your new password</p>
            </div>
            <form method="POST">
                <input type="hidden" name="action" value="<?= $pageState ?>">
                <div class="form-group">
                    <label class="form-label">New Password</label>
                    <input type="password" name="new_password" id="reset-password" class="form-control" minlength="8" required>
                    <i class="fa fa-eye toggle-password" onclick="togglePassword(this, 'reset-password')"></i>
                </div>
                <button type="submit" class="btn">
                    <i class="fas fa-sync-alt"></i> Update Password
                </button>
            </form>
        <?php endif; ?>

        <?php if ($pageState === 'forgot_username'): ?>
            <div class="header">
                <div class="logo">
                    <i class="fas fa-question-circle"></i>
                </div>
                <h1>Forgot Password</h1>
                <p>Enter your username to begin</p>
            </div>
            <form method="POST">
                <input type="hidden" name="action" value="forgot_username">
                <div class="form-group">
                    <label class="form-label">Username</label>
                    <input type="text" name="username" class="form-control" required>
                </div>
                <button type="submit" class="btn">
                    <i class="fas fa-arrow-right"></i> Continue
                </button>
            </form>
            <p class="footer-link">Remember it? <a href="index.php?action=cancel">Back to Login</a></p>
        <?php endif; ?>

        <?php if ($pageState === 'forgot_pin'): ?>
            <div class="header">
                <div class="logo">
                    <i class="fas fa-lock"></i>
                </div>
                <h1>Verify PIN</h1>
                <p>Enter the 4-digit PIN for <?= htmlspecialchars($_SESSION['reset_username'] ?? '') ?></p>
            </div>
            <form method="POST">
                <input type="hidden" name="action" value="forgot_pin">
                <div class="form-group">
                    <label class="form-label">4-Digit PIN</label>
                    <input type="password" name="pin" id="forgot-pin" class="form-control" pattern="\d{4}" maxlength="4" required>
                    <i class="fa fa-eye toggle-password" onclick="togglePassword(this, 'forgot-pin')"></i>
                </div>
                <button type="submit" class="btn">
                    <i class="fas fa-check"></i> Verify PIN
                </button>
            </form>
            <p class="footer-link">Not your account? <a href="index.php?action=cancel">Back to Login</a></p>
        <?php endif; ?>

        <?php if ($pageState === 'forgot_security_question'): ?>
            <div class="header">
                <div class="logo">
                    <i class="fas fa-shield-alt"></i>
                </div>
                <h1>Security Question</h1>
                <p><?= htmlspecialchars($userFound['security_question'] ?? '') ?></p>
            </div>
            <form method="POST">
                <input type="hidden" name="action" value="forgot_security_question">
                <div class="form-group">
                    <label class="form-label">Your Answer</label>
                    <input type="text" name="security_answer" class="form-control" required>
                </div>
                <button type="submit" class="btn">
                    <i class="fas fa-check"></i> Verify Answer
                </button>
            </form>
            <p class="footer-link">Not your account? <a href="index.php?action=cancel">Back to Login</a></p>
        <?php endif; ?>
    </div>

    <script>
        function togglePassword(el, inputId) {
            const input = document.getElementById(inputId);
            input.type = input.type === "password" ? "text" : "password";
            el.classList.toggle("fa-eye-slash");
        }
        
        // 3D card effect on mouse move
        document.addEventListener('mousemove', function(e) {
            const card = document.getElementById('loginCard');
            if (!card) return;
            
            const x = e.clientX;
            const y = e.clientY;
            const centerX = window.innerWidth / 2;
            const centerY = window.innerHeight / 2;
            
            const rotateX = (y - centerY) / 25;
            const rotateY = (centerX - x) / 25;
            
            card.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg)`;
        });
        
        // Reset card position when mouse leaves
        document.addEventListener('mouseleave', function() {
            const card = document.getElementById('loginCard');
            if (card) {
                card.style.transform = 'perspective(1000px) rotateX(0) rotateY(0)';
            }
        });
        
        // Form submission loading animation
        const forms = document.querySelectorAll('form');
        forms.forEach(form => {
            form.addEventListener('submit', function() {
                const btn = this.querySelector('button[type="submit"]');
                if (btn) {
                    btn.classList.add('btn-loading');
                    btn.disabled = true;
                }
            });
        });
    </script>
</body>
</html>