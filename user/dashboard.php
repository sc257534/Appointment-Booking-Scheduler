<?php
// Start output buffering to prevent "Headers already sent" errors.
ob_start();

// This PHP script serves the user dashboard, handling both the frontend and API requests.
session_start();

// --- START OF INACTIVITY CHECK ---

$timeout_duration = 300; // 5 minutes in seconds

if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > $timeout_duration) {
    // If the session has expired, destroy it.
    session_unset();     // Unset $_SESSION variable for the run-time
    session_destroy();   // Destroy session data in storage
    
    // For API requests, send a JSON error. For page loads, redirect.
    if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
        http_response_code(401); // Unauthorized
        echo json_encode(['success' => false, 'message' => 'Session expired due to inactivity.']);
        exit();
    } else {
        header("Location: ../logout.php?reason=inactive"); // Redirect to logout page
        exit();
    }
}

// Update last activity time stamp on each request
$_SESSION['last_activity'] = time();

// --- END OF INACTIVITY CHECK ---


// --- START OF LOGIN & SECURITY CHECK ---

// Correctly capture the PDO object returned by the config file.
$pdo = require_once '../db_config.php';

// Security check: ensure user is logged in with the correct role.
if (!isset($_SESSION['username']) || $_SESSION['role'] !== 'user') {
    header("Location: ../index.php");
    exit();
}

// Fetch the user ID, name, and permissions from the database using the username stored in the session.
try {
    // Fetch user details without overbook permissions
    $stmt = $pdo->prepare("SELECT id, name, role FROM users WHERE username = ?");
    $stmt->execute([$_SESSION['username']]);
    $user = $stmt->fetch();

    if (!$user) {
        // This case should ideally not happen if login was successful.
        // If it does, log out the user for security.
        session_destroy();
        header("Location: ../index.php");
        exit();
    }

    // Set user data in the session for use in this script and the frontend.
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['user_name'] = $user['name'];

    // Define the user ID for API functions.
    $userId = $_SESSION['user_id'];

} catch (PDOException $e) {
    // Handle database errors gracefully.
    error_log("User lookup error: " . $e->getMessage());
    session_destroy();
    header("Location: ../index.php");
    exit();
}

// --- END OF LOGIN & SECURITY CHECK ---

// --- CSRF Token Generation ---
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

date_default_timezone_set('Asia/Kolkata'); // Set timezone to Kolkata, India

// Function to handle API GET requests
function handleGetRequest($pdo, $userId) {
    header('Content-Type: application/json');

    if (isset($_GET['action']) && $_GET['action'] === 'services') {
        $sql = "SELECT id, name, duration_minutes, icon, category FROM services WHERE category != 'General' ORDER BY category, name ASC";
        $stmt = $pdo->query($sql);
        $services = $stmt->fetchAll();
        $groupedServices = [];
        foreach ($services as $service) {
            $category = $service['category'] ?? 'General';
            if (!isset($groupedServices[$category])) {
                $groupedServices[$category] = [];
            }
            $groupedServices[$category][] = $service;
        }
        echo json_encode(['success' => true, 'services' => $groupedServices]);
    } elseif (isset($_GET['action']) && $_GET['action'] === 'available_slots') {
        $serviceId = intval($_GET['service_id']);
        $date = $_GET['date'];
        
        $sql_rules = "SELECT rule_type, rule_value FROM booking_rules WHERE service_id = ?";
        $stmt_rules = $pdo->prepare($sql_rules);
        $stmt_rules->execute([$serviceId]);
        $rules = $stmt_rules->fetchAll(PDO::FETCH_KEY_PAIR);
        
        $sql_breaks = "SELECT start_time, end_time FROM daily_breaks";
        $stmt_breaks = $pdo->query($sql_breaks);
        $dailyBreaks = $stmt_breaks->fetchAll();

        $dayOfWeek = date('w', strtotime($date));
        $now = time();
        $selectedDateStart = strtotime($date);

        // UPDATED: Compulsory holiday on Sunday
        if ($dayOfWeek == 0) {
            echo json_encode(['success' => false, 'message' => 'Bookings are not available on Sundays.']);
            exit;
        }

        if (isset($rules['ALLOWED_DAYS'])) {
            $allowed_days = explode(',', $rules['ALLOWED_DAYS']);
            if (!in_array($dayOfWeek, $allowed_days)) {
                echo json_encode(['success' => false, 'message' => 'This service is not available on the selected day of the week.']);
                exit;
            }
        }
        
        // UPDATED: Logic for 2 working days booking window
        $currentDate = new DateTime();
        $workingDaysToAdd = 2;
        while ($workingDaysToAdd > 0) {
            $currentDate->modify('+1 day');
            if ((int)$currentDate->format('w') != 0) { // Not Sunday
                $workingDaysToAdd--;
            }
        }
        $maxBookingTimestamp = strtotime($currentDate->format('Y-m-d'));


        if ($selectedDateStart < strtotime(date('Y-m-d', $now))) {
            echo json_encode(['success' => false, 'message' => 'Cannot book appointments in the past.']);
            exit;
        }
        if (strtotime($date) > $maxBookingTimestamp) {
            echo json_encode(['success' => false, 'message' => "Bookings can only be made up to 2 working days in advance."]);
            exit;
        }

        if (isset($rules['MAX_PER_DAY'])) {
            $max_per_day = intval($rules['MAX_PER_DAY']);
            $sql_count = "SELECT COUNT(*) as count FROM appointments WHERE service_id = ? AND DATE(appointment_datetime) = ?";
            $stmt_count = $pdo->prepare($sql_count);
            $stmt_count->execute([$serviceId, $date]);
            $count_result = $stmt_count->fetchColumn();
            if ($count_result >= $max_per_day) {
                echo json_encode(['success' => false, 'message' => 'The maximum number of bookings for this service has been reached for today.']);
                exit;
            }
        }

        $sql_service = "SELECT duration_minutes FROM services WHERE id = ?";
        $stmt_service = $pdo->prepare($sql_service);
        $stmt_service->execute([$serviceId]);
        $service = $stmt_service->fetch();
        if (!$service) {
                echo json_encode(['success' => false, 'message' => 'Service not found.']);
                exit;
        }
        $duration = $service['duration_minutes'];
        $buffer = isset($rules['BUFFER_TIME']) ? intval($rules['BUFFER_TIME']) : 0;

        $officeStart = strtotime($date . ' 10:00:00');
        $officeEnd = ($dayOfWeek == 6) ? strtotime($date . ' 14:00:00') : strtotime($date . ' 16:00:00');
        if(isset($rules['START_TIME'])) $officeStart = strtotime($date . ' ' . $rules['START_TIME']);
        if(isset($rules['END_TIME'])) $officeEnd = strtotime($date . ' ' . $rules['END_TIME']);
        
        $allBusyTimes = [];
        $sqlAppointments = "SELECT a.appointment_datetime, s.duration_minutes, br.rule_value AS buffer_time FROM appointments a JOIN services s ON a.service_id = s.id LEFT JOIN booking_rules br ON s.id = br.service_id AND br.rule_type = 'BUFFER_TIME' WHERE DATE(a.appointment_datetime) = ?";
        $stmtAppointments = $pdo->prepare($sqlAppointments);
        $stmtAppointments->execute([$date]);
        
        while ($row = $stmtAppointments->fetch()) {
            $start = strtotime($row['appointment_datetime']);
            $app_buffer = $row['buffer_time'] ?? 0;
            $end = $start + ($row['duration_minutes'] * 60) + ($app_buffer * 60);
            $allBusyTimes[] = ['start' => $start, 'end' => $end];
        }
        
        $sqlBlocked = "SELECT start_datetime, end_datetime, reason FROM blocked_slots WHERE DATE(start_datetime) = ?";
        $stmtBlocked = $pdo->prepare($sqlBlocked);
        $stmtBlocked->execute([$date]);
        while ($row = $stmtBlocked->fetch()) { $allBusyTimes[] = ['start' => strtotime($row['start_datetime']), 'end' => strtotime($row['end_datetime'])]; }
        
        foreach($dailyBreaks as $dailyBreak) {
            $allBusyTimes[] = ['start' => strtotime($date . ' ' . $dailyBreak['start_time']), 'end' => strtotime($date . ' ' . $dailyBreak['end_time'])];
        }
        
        $availableSlots = [];
        $isToday = date('Y-m-d', $now) === $date;
        $currentTime = $officeStart;
        // Set minimum lead hours for booking (default to 0 if not set in rules)
        $minlead_hours = isset($rules['MIN_LEAD_HOURS']) ? intval($rules['MIN_LEAD_HOURS']) : 0;
        if ($isToday) {
            $earliestBookingTime = $now + ($minlead_hours * 3600);
            $currentTime = ceil($earliestBookingTime / (5 * 60)) * (5 * 60);
            $currentTime = max($officeStart, $currentTime);
        }

        $slotStep = 5 * 60; // 5 minute intervals

        while ($currentTime + ($duration * 60) <= $officeEnd) {
            $isAvailable = true;
            $slotStart = $currentTime;
            $slotEnd = $currentTime + ($duration * 60) + ($buffer * 60);
            
            foreach ($allBusyTimes as $busy) {
                if ($slotStart < $busy['end'] && $slotEnd > $busy['start']) {
                    $isAvailable = false;
                    $currentTime = $busy['end']; 
                    break;
                }
            }
        
            if ($isAvailable) {
                $availableSlots[] = date('H:i', $currentTime);
                $currentTime += $slotStep;
            }
        }
        
        echo json_encode(['success' => true, 'slots' => $availableSlots]);
    } elseif (isset($_GET['action']) && $_GET['action'] === 'view_appointments') {
        $date = isset($_GET['date']) ? $_GET['date'] : date('Y-m-d');
        
        $sql = "SELECT a.id, a.service_id, a.customer_name, a.customer_mobile, a.appointment_datetime, s.name AS service_name, s.duration_minutes, a.is_rescheduled, a.original_appointment_datetime, a.serial_number
                FROM appointments a
                JOIN services s ON a.service_id = s.id
                WHERE DATE(a.appointment_datetime) = ?
                ORDER BY a.appointment_datetime ASC";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([$date]);
        $appointments = $stmt->fetchAll();
        echo json_encode(['success' => true, 'appointments' => $appointments]);
    } elseif (isset($_GET['action']) && $_GET['action'] === 'roster_data') {
        $date = $_GET['date'] ?? date('Y-m-d');
        $blockedSql = "SELECT start_datetime, end_datetime, reason FROM blocked_slots WHERE DATE(start_datetime) = ? ORDER BY start_datetime";
        $blockedStmt = $pdo->prepare($blockedSql);
        $blockedStmt->execute([$date]);
        $blockedSlots = $blockedStmt->fetchAll();
        
        $breaksSql = "SELECT start_time, end_time FROM daily_breaks ORDER BY start_time";
        $breaksStmt = $pdo->query($breaksSql);
        $dailyBreaks = $breaksStmt->fetchAll();

        echo json_encode([
            'success' => true,
            'blocked_slots' => $blockedSlots,
            'daily_breaks' => $dailyBreaks
        ]);
    }
    exit;
}

// Function to handle API POST requests
function handlePostRequest($pdo, $userId) {
    header('Content-Type: application/json');
    $input = json_decode(file_get_contents('php://input'), true);

    // CSRF check for POST requests
    if (!isset($input['csrf_token']) || $input['csrf_token'] !== $_SESSION['csrf_token']) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'CSRF token mismatch.']);
        exit;
    }

    if (isset($input['action'])) {
        switch ($input['action']) {
            case 'book':
                $serviceId = intval($input['service_id']);
                $customerName = trim($input['name']);
                $customerMobile = isset($input['mobile']) ? trim($input['mobile']) : null;
                $appointmentDate = $input['date'];
                $appointmentTime = $input['time'];
                $appointmentDateTime = $appointmentDate . ' ' . $appointmentTime . ':00';
                
                if ($customerMobile && !preg_match('/^\d{10}$/', $customerMobile)) {
                    echo json_encode(['success' => false, 'message' => 'Invalid mobile number. Please enter a 10-digit number.']);
                    exit;
                }

                try {
                    $pdo->beginTransaction();

                    // Check if the slot is already taken
                    $checkSql = "SELECT COUNT(*) FROM appointments WHERE appointment_datetime = ?";
                    $checkStmt = $pdo->prepare($checkSql);
                    $checkStmt->execute([$appointmentDateTime]);
                    $slotIsTaken = $checkStmt->fetchColumn() > 0;

                    if ($slotIsTaken) {
                        // If the slot is taken, deny the booking
                        $pdo->rollBack();
                        echo json_encode(['success' => false, 'message' => 'The selected time slot is already booked. Please choose another time.']);
                        break;
                    }

                    // If we reach here, the slot is available. Proceed with booking.
                    $sql = "INSERT INTO appointments (service_id, customer_name, customer_mobile, appointment_datetime, booked_by_user_id) VALUES (?, ?, ?, ?, ?)";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute([$serviceId, $customerName, $customerMobile, $appointmentDateTime, $userId]);
                    
                    $appointmentId = $pdo->lastInsertId();

                    $date = date('Y-m-d', strtotime($appointmentDateTime));
                    
                    $stmtExistingSerials = $pdo->prepare("SELECT serial_number FROM appointments WHERE DATE(appointment_datetime) = ? AND id != ? ORDER BY CAST(serial_number AS UNSIGNED) ASC");
                    $stmtExistingSerials->execute([$date, $appointmentId]);
                    $existingSerials = $stmtExistingSerials->fetchAll(PDO::FETCH_COLUMN);
                    
                    $nextSerial = 1;
                    foreach ($existingSerials as $existingSerial) {
                        if ($existingSerial != $nextSerial) {
                            break;
                        }
                        $nextSerial++;
                    }
                    $serialNumber = $nextSerial;
                    
                    $sqlUpdateSerial = "UPDATE appointments SET serial_number = ? WHERE id = ?";
                    $stmtUpdateSerial = $pdo->prepare($sqlUpdateSerial);
                    $stmtUpdateSerial->execute([$serialNumber, $appointmentId]);
                    
                    $pdo->commit();

                    $stmt_service = $pdo->prepare("SELECT name, duration_minutes FROM services WHERE id = ?");
                    $stmt_service->execute([$serviceId]);
                    $service = $stmt_service->fetch(PDO::FETCH_ASSOC);

                    $startTime = new DateTime($appointmentDateTime);
                    $endTime = (clone $startTime)->add(new DateInterval('PT' . $service['duration_minutes'] . 'M'));

                    $details = [
                        'name' => $customerName,
                        'serial' => $serialNumber,
                        'service' => $service['name'],
                        'startTime' => $startTime->format('g:i A'),
                        'endTime' => $endTime->format('g:i A'),
                        'date' => $startTime->format('D, M j, Y')
                    ];

                    echo json_encode([
                        'success' => true,
                        'message' => 'Appointment booked successfully!',
                        'details' => $details
                    ]);
                    
                } catch (PDOException $e) {
                    $pdo->rollBack();
                    error_log("Booking error: " . $e->getMessage());
                    echo json_encode(['success' => false, 'message' => 'An error occurred. The slot might have been taken.']);
                }
                break;
                
            case 'change_password':
                $oldPassword = $input['old_password'];
                $newPassword = $input['new_password'];

                $sql = "SELECT hash FROM users WHERE id = ?";
                $stmt = $pdo->prepare($sql);
                $stmt->execute([$userId]);
                $user = $stmt->fetch();

                if (!$user || !password_verify($oldPassword, $user['hash'])) {
                    echo json_encode(['success' => false, 'message' => 'Incorrect current password.']);
                    exit;
                }
                
                if (password_verify($newPassword, $user['hash'])) {
                    echo json_encode(['success' => false, 'message' => 'New password cannot be the same as the old one.']);
                    exit;
                }

                $newPasswordHash = password_hash($newPassword, PASSWORD_DEFAULT);
                $sql = "UPDATE users SET hash = ?, isFirstLogin = 0, passwordLastChanged = CURDATE() WHERE id = ?";
                $stmt = $pdo->prepare($sql);
                if ($stmt->execute([$newPasswordHash, $userId])) {
                    echo json_encode(['success' => true, 'message' => 'Password changed successfully.']);
                } else {
                    echo json_encode(['success' => false, 'message' => 'Failed to update password.']);
                }
                break;

            case 'edit':
                $appointmentId = intval($input['appointment_id']);
                $customerName = trim($input['name']);
                $customerMobile = isset($input['mobile']) ? trim($input['mobile']) : null;
                $serviceId = intval($input['service_id']);
                try {
                    $sql = "UPDATE appointments SET customer_name = ?, customer_mobile = ?, service_id = ? WHERE id = ?";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute([$customerName, $customerMobile, $serviceId, $appointmentId]);
                    echo json_encode(['success' => true, 'message' => 'Appointment updated successfully.']);
                } catch (PDOException $e) {
                    error_log("Edit appointment error: " . $e->getMessage());
                    echo json_encode(['success' => false, 'message' => 'Failed to update appointment.']);
                }
                break;

            case 'reschedule':
                $appointmentId = intval($input['appointment_id']);
                $newDate = $input['new_date'];
                $newTime = $input['new_time'];
                $newAppointmentDateTime = $newDate . ' ' . $newTime . ':00';
                try {
                    $sql_original = "SELECT appointment_datetime FROM appointments WHERE id = ?";
                    $stmt_original = $pdo->prepare($sql_original);
                    $stmt_original->execute([$appointmentId]);
                    $original_datetime = $stmt_original->fetchColumn();

                    $sql = "UPDATE appointments SET appointment_datetime = ?, is_rescheduled = 1, original_appointment_datetime = ? WHERE id = ?";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute([$newAppointmentDateTime, $original_datetime, $appointmentId]);
                    echo json_encode(['success' => true, 'message' => 'Appointment rescheduled successfully.']);
                } catch (PDOException $e) {
                    error_log("Reschedule appointment error: " . $e->getMessage());
                    echo json_encode(['success' => false, 'message' => 'Failed to reschedule appointment.']);
                }
                break;

            case 'cancel':
                $appointmentId = intval($input['appointment_id']);
                try {
                    $sql = "DELETE FROM appointments WHERE id = ?";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute([$appointmentId]);
                    echo json_encode(['success' => true, 'message' => 'Appointment canceled successfully.']);
                } catch (PDOException $e) {
                    error_log("Cancel appointment error: " . $e->getMessage());
                    echo json_encode(['success' => false, 'message' => 'Failed to cancel appointment.']);
                }
                break;
                
            default:
                echo json_encode(['success' => false, 'message' => 'Invalid action provided.']);
                break;
        }
    }
    exit;
}

// Check for API request
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    handlePostRequest($pdo, $_SESSION['user_id']);
} elseif (isset($_GET['action'])) {
    handleGetRequest($pdo, $_SESSION['user_id']);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Booking Assistant | User Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700&family=Roboto:wght@300;400;500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/particles.js@2.0.0/particles.min.js"></script>
    <style>
        :root {
            --primary: #6366f1;
            --primary-dark: #4f46e5;
            --secondary: #06b6d4;
            --dark: #1e293b;
            --darker: #0f172a;
            --light: #f1f5f9;
            --accent: #8b5cf6;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
            --box-shadow-3d: 0 10px 30px rgba(0, 0, 0, 0.3), 0 1px 8px rgba(0, 0, 0, 0.15);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Montserrat', sans-serif;
        }
        
        body {
            background: linear-gradient(135deg, var(--darker) 0%, var(--dark) 100%);
            color: var(--light);
            min-height: 100vh;
            overflow-x: hidden;
            transition: var(--transition);
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: 280px 1fr;
            grid-template-rows: 1fr;
            grid-template-areas:
                "sidebar main";
            height: 100vh;
            overflow: hidden;
        }
        
        /* Header Styles */
        .header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 1.5rem 2rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            z-index: 10;
            background: rgba(15, 23, 42, 0.8);
            backdrop-filter: blur(10px);
        }
        
        .header-title {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--light);
        }
        
        .user-actions {
            display: flex;
            align-items: center;
            gap: 1.5rem;
        }
        
        .user-profile {
            display: flex;
            align-items: center;
            gap: 0.8rem;
            cursor: pointer;
        }
        
        .user-avatar {
            width: 45px;
            height: 45px;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            font-size: 1.2rem;
            transition: transform 0.3s ease;
        }
        
        .user-profile:hover .user-avatar {
            transform: scale(1.1);
        }
        
        .user-info-text {
            display: flex;
            flex-direction: column;
            text-align: right;
            line-height: 1.2;
        }
        
        .user-info-text .user-name {
            font-size: 1rem;
            font-weight: 600;
            color: var(--light);
        }
        
        .user-info-text .user-role {
            font-size: 0.8rem;
            opacity: 0.7;
        }
        
        /* Sidebar Styles */
        .sidebar {
            grid-area: sidebar;
            background: rgba(15, 23, 42, 0.8);
            backdrop-filter: blur(10px);
            border-right: 1px solid rgba(255, 255, 255, 0.1);
            padding: 2rem 1.5rem;
            display: flex;
            flex-direction: column;
            z-index: 10;
        }
        
        .logo {
            display: flex;
            align-items: center;
            gap: 0.8rem;
            margin-bottom: 2.5rem;
            padding-left: 0.5rem;
        }
        
        .logo-icon {
            font-size: 2rem;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .logo-text {
            font-size: 1.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .nav-list {
            list-style: none;
            display: flex;
            flex-direction: column;
            gap: 0.8rem;
            margin-bottom: auto; /* Push logout to the bottom */
        }
        
        .nav-item {
            padding: 0.9rem 1rem;
            border-radius: 12px;
            display: flex;
            align-items: center;
            gap: 0.8rem;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
            text-decoration: none;
            color: var(--light);
            opacity: 0.7;
        }
        
        .nav-item::before {
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            height: 100%;
            width: 4px;
            background: linear-gradient(to bottom, var(--primary), var(--secondary));
            opacity: 0;
            transition: opacity 0.3s;
        }
        
        .nav-item:hover {
            background: rgba(255, 255, 255, 0.05);
            opacity: 1;
        }
        
        .nav-item.active {
            background: rgba(99, 102, 241, 0.15);
            opacity: 1;
        }
        
        .nav-item.active::before {
            opacity: 1;
        }
        
        .nav-item i {
            font-size: 1.2rem;
            color: var(--light);
            width: 24px;
        }
        
        .nav-item.active i {
            color: var(--primary);
        }
        
        .nav-item span {
            font-weight: 500;
            font-size: 0.95rem;
        }
        
        .logout-btn {
            display: flex;
            align-items: center;
            justify-content: center;
            width: 100%;
            padding: 0.9rem 1rem;
            border-radius: 12px;
            background: rgba(239, 68, 68, 0.2);
            color: var(--danger);
            font-weight: 600;
            text-decoration: none;
            margin-top: 2rem;
            transition: all 0.3s ease;
        }
        
        .logout-btn:hover {
            background: rgba(239, 68, 68, 0.4);
        }
        
        .logout-btn i {
            margin-right: 8px;
        }
        
        /* Main Content Styles */
        .main {
            grid-area: main;
            display: flex;
            flex-direction: column;
            overflow-y: auto;
        }
        
        .page-content {
            background: rgba(30, 41, 59, 0.6);
            border-radius: 20px;
            padding: 2rem;
            margin: 2rem;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            min-height: calc(100vh - 120px);
            display: none; /* All pages are hidden by default */
        }
        
        .page-content.active {
            display: block; /* Only the active page is shown */
        }

        h1 {
            font-size: 2.2rem;
            margin-bottom: 0.5rem;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            line-height: 1.2;
        }
        
        h2 {
            font-size: 1.3rem;
            font-weight: 600;
            margin-bottom: 1rem;
            color: var(--light);
        }
        
        p.sub {
            font-size: 1rem;
            opacity: 0.7;
            max-width: 600px;
            margin-bottom: 2rem;
        }
        
        .current-time {
            background: rgba(99, 102, 241, 0.2);
            padding: 0.5rem 1rem;
            border-radius: 12px;
            font-size: 1rem;
            font-weight: 600;
            color: var(--primary);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        /* Form and Button styles */
        label {
            display: block;
            font-size: 0.9rem;
            color: var(--light);
            opacity: 0.7;
            margin-bottom: 0.5rem;
        }
        
        input, select {
            width: 100%;
            padding: 0.8rem 1rem;
            border-radius: 12px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            background: rgba(15, 23, 42, 0.4);
            color: var(--light);
            outline: none;
            font-size: 1rem;
            transition: var(--transition);
        }
        
        input:focus, select:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.3);
        }
        
        .grid-cols-2 {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
        }
        
        button {
            border: none;
            padding: 0.9rem 1.5rem;
            border-radius: 12px;
            cursor: pointer;
            font-weight: 600;
            font-size: 1rem;
            transition: var(--transition);
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        button.btn-primary {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: white;
            box-shadow: 0 5px 15px rgba(99, 102, 241, 0.3);
        }
        
        button.btn-secondary {
            background: rgba(255, 255, 255, 0.1);
            color: var(--light);
        }
        
        button.btn-danger {
            background: var(--danger);
            color: white;
        }
        
        button:hover {
            opacity: 0.9;
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.2);
        }
        
        button i {
            margin-right: 8px;
        }
        
        /* Modals and Dialogs */
        .dialog {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            background: rgba(0, 0, 0, 0.7);
            z-index: 1000;
            padding: 1rem;
            backdrop-filter: blur(5px);
            animation: fadeIn 0.3s ease-out;
        }

        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        .dialog-content {
            background: rgba(30, 41, 59, 0.8);
            border-radius: 20px;
            padding: 2rem;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
            max-width: 440px;
            width: 100%;
            text-align: center;
            position: relative;
            animation: modalAppear 0.3s ease-out;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        @keyframes modalAppear {
            0% { opacity: 0; transform: translateY(-50px) scale(0.9); }
            100% { opacity: 1; transform: translateY(0) scale(1); }
        }
        
        .dialog-content .close-btn {
            position: absolute;
            top: 10px;
            right: 10px;
            width: 30px;
            height: 30px;
            background: none;
            color: var(--light);
            opacity: 0.5;
            font-size: 1.2rem;
            cursor: pointer;
            border: none;
            transition: opacity 0.3s;
        }
        
        .dialog-content .close-btn:hover {
            opacity: 1;
        }
        
        .time-slot-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
            margin-top: 20px;
        }
        
        .time-slot-button {
            background: rgba(255, 255, 255, 0.06);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 0.8rem 0.5rem;
            text-align: center;
            cursor: pointer;
            font-size: 0.9rem;
            font-weight: 500;
            transition: var(--transition);
        }
        
        .time-slot-button:hover {
            border-color: var(--secondary);
            transform: translateY(-2px);
        }
        
        .time-slot-button.selected {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            border-color: transparent;
            color: white;
        }
        
        .service-category-list h2, .service-list-container h2 {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .category-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 1rem;
            margin-top: 1.5rem;
        }
        
        .category-button {
            background: rgba(15, 23, 42, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 14px;
            padding: 1.5rem;
            text-align: center;
            font-weight: 600;
            transition: var(--transition);
            cursor: pointer;
        }
        
        .category-button:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
            border-color: var(--primary);
        }
        
        .category-button i {
            font-size: 2rem;
            margin-bottom: 0.5rem;
            color: var(--light);
            opacity: 0.7;
        }
        
        .service-grid-modal {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1rem;
            margin-top: 1.5rem;
        }
        
        .service-grid-modal .service-button {
            background: rgba(15, 23, 42, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 1rem;
            display: flex;
            flex-direction: row;
            align-items: center;
            justify-content: flex-start;
            transition: var(--transition);
        }
        
        .service-grid-modal .service-button:hover {
            transform: translateY(-3px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
            border-color: var(--primary);
        }
        
        .service-grid-modal .service-button.selected {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            border-color: transparent;
            color: white;
        }
        
        .service-grid-modal .service-button i {
            margin-right: 1rem;
            font-size: 1.2rem;
        }
        
        .service-grid-modal .service-button span {
            text-align: left;
        }
        
        .service-grid-modal .service-button span span {
            font-size: 0.8rem;
            opacity: 0.7;
        }
        
        .hidden {
            display: none;
        }
        
        .form-section {
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
            margin-top: 1.5rem;
        }
        
        .form-section .dialog-actions {
            display: flex;
            justify-content: space-between;
            gap: 1rem;
            margin-top: 1.5rem;
        }
        
        .form-section .dialog-actions button {
            flex: 1;
        }
        
        .password-message {
            margin-top: 1rem;
            font-size: 0.9rem;
            text-align: center;
        }
        
        .password-message.success {
            color: var(--success);
        }
        
        .password-message.error {
            color: var(--danger);
        }
        
        .reschedule-badge {
            background-color: var(--warning);
            color: var(--darker);
            font-size: 0.6rem;
            font-weight: 700;
            padding: 2px 6px;
            border-radius: 6px;
            margin-left: 8px;
            text-transform: uppercase;
        }
        
        .summary-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: rgba(15, 23, 42, 0.4);
            border-radius: 16px;
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: var(--transition);
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
        }
        
        .stat-value {
            font-size: 2.2rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .stat-label {
            font-size: 0.9rem;
            opacity: 0.7;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        /* Table */
        .table-container {
            overflow-x: auto;
            border-radius: 12px;
            margin-top: 1rem;
            background: rgba(15, 23, 42, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .scrollable-table-container {
            max-height: 250px; /* Adjusted height for ~5 rows + header */
            overflow-y: auto;
        }
        
        .data-table {
            width: 100%;
            border-collapse: collapse;
            border-spacing: 0;
        }
        
        .data-table th, .data-table td {
            text-align: left;
            padding: 1rem;
            font-size: 0.9rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }
        
        .data-table th {
            color: var(--light);
            font-weight: 600;
            background: var(--dark); 
            position: sticky;
            top: 0;
            z-index: 1;
            box-shadow: 0 2px 2px -1px rgba(0, 0, 0, 0.4);
        }
        
        .data-table tbody tr:hover {
            background: rgba(255, 255, 255, 0.04);
        }
        
        .action-buttons {
            display: flex;
            gap: 0.5rem;
        }
        
        .action-button {
            background: none;
            border: 1px solid rgba(255, 255, 255, 0.1);
            width: 36px;
            height: 36px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--primary);
            cursor: pointer;
            transition: var(--transition);
            position: relative;
        }
        
        .action-button.reschedule-btn {
            color: var(--warning);
        }
        
        .action-button.cancel-btn {
            color: var(--danger);
        }
        
        .action-button:hover {
            background: rgba(255, 255, 255, 0.1);
            transform: translateY(-2px);
        }
        
        .action-button:hover::after {
            content: attr(data-tooltip);
            position: absolute;
            bottom: 120%;
            left: 50%;
            transform: translateX(-50%);
            background-color: var(--darker);
            color: var(--light);
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 12px;
            white-space: nowrap;
            z-index: 10;
            border: 1px solid rgba(255, 255, 255, 0.1);
            pointer-events: none;
        }
        
        /* Responsive Design */
        .hamburger-menu {
            display: none;
            font-size: 1.5rem;
            color: var(--light);
            cursor: pointer;
            padding: 1rem;
        }

        @media (max-width: 900px) {
            .dashboard {
                grid-template-columns: 1fr;
                grid-template-rows: auto 1fr;
                grid-template-areas:
                    "header"
                    "main";
                height: auto;
            }
            .sidebar {
                position: fixed;
                top: 0;
                left: -280px;
                height: 100%;
                z-index: 20;
                transition: left 0.3s ease-in-out;
            }
            .sidebar.active {
                left: 0;
            }
            .main { padding-top: 0; }
            .page-content { margin: 1rem; }
            .grid-cols-2 { grid-template-columns: 1fr; }
            .time-slot-grid, .service-grid-modal, .category-grid { grid-template-columns: repeat(2, 1fr); }
            .header-title { display: none; }
            .user-actions { flex-direction: row; gap: 1rem; }
            .user-info-text { display: none; }
            .hamburger-menu { display: block; }
        }
        
        @media (max-width: 600px) {
            .user-actions { flex-direction: row; gap: 1rem; }
            .page-header { flex-direction: column; align-items: flex-start; }
            .time-slot-grid, .service-grid-modal, .category-grid { grid-template-columns: 1fr; }
        }
        
        .floating-shapes {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: -1;
            overflow: hidden;
        }
        
        .floating-element {
            position: absolute;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            opacity: 0.1;
            animation: float 15s ease-in-out infinite;
        }
        
        .shape-1 { width: 400px; height: 400px; top: -100px; left: -100px; animation-delay: 0s; animation-duration: 25s; }
        .shape-2 { width: 300px; height: 300px; bottom: -50px; right: -50px; animation-delay: -5s; animation-duration: 20s; }
        .shape-3 { width: 200px; height: 200px; top: 50%; left: 70%; animation-delay: -10s; animation-duration: 15s; }
        
        @keyframes float {
            0% { transform: translate(0, 0) rotate(0deg); }
            50% { transform: translate(20px, 20px) rotate(180deg); }
            100% { transform: translate(0, 0) rotate(360deg); }
        }
        
        /* New Styles for Success Dialog */
        .checkmark-container {
            width: 80px;
            height: 80px;
            margin: 0 auto 1rem;
        }
        .checkmark-container .checkmark {
            width: 100%;
            height: 100%;
        }
        .booking-details-box {
            background-color: rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            padding: 1.5rem;
            margin-top: 1.5rem;
            text-align: left;
            line-height: 1.8;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        .booking-details-box strong {
            font-weight: 700;
            font-size: 1.1em;
            color: var(--primary);
        }
        .customer-name-display {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--light);
            margin-bottom: 0.5rem;
        }
        .appointment-confirmed-text {
            font-size: 1rem;
            opacity: 0.8;
        }
    </style>
</head>
<body>
    <div class="floating-shapes" id="particles-js">
    </div>
    
    <div class="dashboard">
        <aside class="sidebar">
            <div class="logo">
                <div class="logo-icon"><i class="fa-solid fa-calendar-plus"></i></div>
                <div class="logo-text">Booking App</div>
            </div>
            <ul class="nav-list">
                <a href="#book" class="nav-item active" data-page="book">
                    <i><i class="fas fa-calendar-plus"></i></i>
                    <span>Book Appointment</span>
                </a>
                <a href="#manage" class="nav-item" data-page="manage">
                    <i><i class="fas fa-list-alt"></i></i>
                    <span>Manage Appointments</span>
                </a>
                <a href="#roster" class="nav-item" data-page="roster">
                    <i><i class="fas fa-users-cog"></i></i>
                    <span>Team Roster</span>
                </a>
                <a href="#password" class="nav-item" data-page="password">
                    <i><i class="fas fa-lock"></i></i>
                    <span>Change Password</span>
                </a>
            </ul>
            <a href="../logout.php" class="logout-btn"><i class="fas fa-sign-out-alt"></i>Logout</a>
        </aside>
        
        <main class="main">
            <header class="header">
                <div class="hamburger-menu"><i class="fas fa-bars"></i></div>
                <div class="header-title">Booking Assistant</div>
                <div class="user-actions">
                    <div class="current-time"><i class="fas fa-clock"></i><span id="current-time"></span></div>
                    <div class="user-profile">
                        <div class="user-avatar"><?php echo strtoupper(substr($_SESSION['user_name'] ?? 'Guest', 0, 1)); ?></div>
                        <div class="user-info-text">
                            <div class="user-name"><?php echo htmlspecialchars($_SESSION['user_name'] ?? 'Guest'); ?></div>
                            <div class="user-role"><?php echo htmlspecialchars($_SESSION['role'] ?? 'N/A'); ?></div>
                        </div>
                    </div>
                </div>
            </header>
            
            <div id="book-page" class="page-content active">
                <h1>Book Appointment</h1>
                <p class="sub">Quickly book a new appointment for a walk-in customer. Select a service and provide customer details.</p>
                
                <div id="step-1-category">
                    <h2>1. Select a Service</h2>
                    <div class="form-group">
                        <label for="service-picker-input">Choose a Service</label>
                        <input type="text" id="service-picker-input" placeholder="Click to select a service..." readonly>
                    </div>
                </div>

                <div id="step-2" class="hidden">
                    <h2>2. Appointment Details</h2>
                    <input type="hidden" id="selected-service-id">
                    <div class="grid-cols-2">
                        <div><label for="booking-date">Select Date</label><input type="date" id="booking-date"></div>
                        <div>
                            <label for="booking-time">Select Time Slot</label>
                            <input type="text" id="booking-time" placeholder="Click to select a time slot..." readonly>
                            <input type="hidden" id="booking-time-select">
                        </div>
                    </div>
                </div>
                
                <div id="step-3" class="hidden">
                    <h2>3. Customer Details</h2>
                    <div class="form-section">
                        <div class="form-group-flex">
                            <label for="customer-name">Customer Full Name</label>
                            <input type="text" id="customer-name" placeholder="Enter customer name" required>
                        </div>
                        <div class="form-group-flex">
                            <label for="customer-mobile">Customer Mobile Number (Optional)</label>
                            <input type="tel" id="customer-mobile" name="customer-mobile" placeholder="Enter mobile number" maxlength="10" pattern="\d{10}" inputmode="numeric">
                        </div>
                    </div>
                    <button id="book-now-btn" class="btn-primary" style="margin-top: 2rem;"><i class="fas fa-check-circle"></i>Confirm Booking</button>
                </div>
            </div>
            
            <div id="manage-page" class="page-content hidden">
                <h1>Manage Appointments</h1>
                <p class="sub">View, edit, or cancel appointments for any day.</p>
                <div class="grid-cols-2" style="margin-bottom: 1.5rem; align-items: end;">
                    <div><label for="appointments-date">Select Date</label><input type="date" id="appointments-date"></div>
                    <div>
                        <label for="search-appointments">Search Appointments</label>
                        <div style="display: flex; gap: 0.5rem;">
                            <input type="text" id="search-appointments" placeholder="Search by name, mobile, service..." style="flex-grow: 1;">
                            <button id="search-btn" class="btn-primary" style="padding: 0.8rem 1rem;"><i class="fas fa-search"></i></button>
                        </div>
                    </div>
                </div>
                <div class="summary-stats">
                    <div class="stat-card"><div class="stat-value" id="total-bookings">0</div><div class="stat-label">Total Bookings</div></div>
                </div>
                <div class="table-container scrollable-table-container">
                    <table class="data-table">
                        <thead><tr><th>Serial #</th><th>Time</th><th>Customer Name</th><th>Mobile</th><th>Service</th><th>Actions</th></tr></thead>
                        <tbody id="appointments-table-body"></tbody>
                    </table>
                </div>
            </div>

            <div id="edit-section" class="page-content hidden">
                <h2>Edit Appointment</h2>
                <form id="edit-form" class="form-section">
                    <input type="hidden" id="edit-app-id">
                    <div class="form-group-flex">
                        <label for="edit-app-name">Customer Name</label>
                        <input type="text" id="edit-app-name" required>
                    </div>
                    <div class="form-group-flex">
                        <label for="edit-app-mobile">Mobile Number</label>
                        <input type="tel" id="edit-app-mobile" maxlength="10">
                    </div>
                    <div class="form-group-flex">
                        <label for="edit-app-service">Service</label>
                        <select id="edit-app-service"></select>
                    </div>
                    <div class="dialog-actions">
                        <button type="submit" class="btn-primary"><i class="fas fa-save"></i>Save Changes</button>
                        <button type="button" class="btn-secondary" onclick="showPage('manage')"><i class="fas fa-times"></i>Cancel</button>
                    </div>
                </form>
            </div>
            
            <div id="reschedule-section" class="page-content hidden">
                <h2>Reschedule Appointment</h2>
                <form id="reschedule-form" class="form-section">
                    <input type="hidden" id="reschedule-app-id">
                    <input type="hidden" id="reschedule-service-id">
                    <div class="grid-cols-2">
                        <div><label for="reschedule-date">New Date</label><input type="date" id="reschedule-date" required></div>
                        <div>
                            <label for="reschedule-time">New Time</label>
                            <input type="text" id="reschedule-time" placeholder="Select a time slot" readonly required>
                            <input type="hidden" id="reschedule-time-select">
                        </div>
                    </div>
                    <div class="dialog-actions">
                        <button type="submit" class="btn-primary"><i class="fas fa-redo"></i>Confirm Reschedule</button>
                        <button type="button" class="btn-secondary" onclick="showPage('manage')"><i class="fas fa-times"></i>Cancel</button>
                    </div>
                </form>
            </div>
            
            <div id="cancel-section" class="page-content hidden">
                <h2>Cancel Appointment</h2>
                <p class="sub">Are you sure you want to cancel this appointment? This action cannot be undone.</p>
                <input type="hidden" id="cancel-app-id">
                <div class="dialog-actions">
                    <button id="confirm-cancel-btn" class="btn-danger"><i class="fas fa-trash-alt"></i>Confirm Cancel</button>
                    <button type="button" class="btn-secondary" onclick="showPage('manage')"><i class="fas fa-times"></i>Keep Appointment</button>
                </div>
            </div>

            <div id="roster-page" class="page-content hidden">
                <h1>Team Roster</h1>
                <p class="sub">View team's blocked time slots and daily breaks.</p>
                <div>
                    <label for="roster-date">Select Date</label>
                    <input type="date" id="roster-date" name="roster-date">
                </div>
                <h2 style="margin-top: 2rem;">Blocked Slots</h2>
                <div class="table-container scrollable-table-container">
                    <table class="data-table">
                        <thead><tr><th>Start Time</th><th>End Time</th><th>Reason</th></tr></thead>
                        <tbody id="roster-blocked-slots-body"></tbody>
                    </table>
                </div>
                <h2 style="margin-top: 2rem;">Daily Breaks</h2>
                <div class="table-container scrollable-table-container">
                    <table class="data-table">
                        <thead><tr><th>Start Time</th><th>End Time</th></tr></thead>
                        <tbody id="roster-daily-breaks-body"></tbody>
                    </table>
                </div>
            </div>
            
            <div id="password-page" class="page-content hidden">
                <h1>Change Password</h1>
                <p class="sub">Update your password to something new. Your old password cannot be your new password.</p>
                <form id="change-password-form" class="form-section">
                    <div class="form-group-flex">
                        <label for="old-password">Current Password</label>
                        <input type="password" id="old-password" required>
                    </div>
                    <div class="form-group-flex">
                        <label for="new-password">New Password</label>
                        <input type="password" id="new-password" required>
                    </div>
                    <div class="form-group-flex">
                        <label for="confirm-new-password">Confirm New Password</label>
                        <input type="password" id="confirm-new-password" required>
                    </div>
                    <button type="submit" id="change-password-btn" class="btn-primary"><i class="fas fa-save"></i>Change Password</button>
                    <div id="password-message" class="password-message hidden"></div>
                </form>
            </div>
        </main>
    </div>
    
    <div id="message-dialog" class="dialog hidden">
      <div class="dialog-content">
        <button class="close-btn"><i class="fas fa-times"></i></button>
        <div id="message-icon-container" class="checkmark-container"></div>
        <div id="message-text" style="color: var(--light); font-weight: 600; font-size: 22px;"></div>
        <div id="message-details" style="color: var(--light); opacity: 0.7; font-size: 14px; margin-top: 10px;"></div>
        <button id="close-dialog" class="btn-primary" style="margin-top: 1.5rem;"><i class="fas fa-check"></i>OK</button>
      </div>
    </div>
    
    <div id="time-slot-modal" class="dialog hidden time-slot-modal">
        <div class="dialog-content" style="max-width: 640px; max-height: 80vh; overflow-y: auto;">
            <button class="close-btn"><i class="fas fa-times"></i></button>
            <h2 id="modal-date-display"></h2>
            <p class="sub">Select an available time slot below.</p>
            <div id="time-slot-grid" class="time-slot-grid"></div>
            <button id="close-time-modal" class="btn-secondary" style="margin-top: 1.5rem;"><i class="fas fa-times"></i>Close</button>
        </div>
    </div>
    
    <div id="service-picker-modal" class="dialog hidden service-modal">
        <div class="dialog-content" style="max-width: 640px;">
            <button class="close-btn"><i class="fas fa-times"></i></button>
            <div id="service-category-list">
                <h2>Select a Service Category</h2>
                <div id="category-grid" class="category-grid"></div>
            </div>
            <div id="service-list-container" class="service-list-container hidden">
                <h2 id="service-list-title"></h2>
                <div id="service-grid-modal" class="service-grid-modal"></div>
                <button id="back-to-categories" class="btn-secondary" style="margin-top: 1.5rem;"><i class="fas fa-arrow-left"></i>Back to Categories</button>
            </div>
        </div>
    </div>
    
    <script>
        const csrfToken = "<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>";
        let servicesData = {};
        let allFetchedAppointments = [];
        let selected = { serviceId: null, serviceName: null, date: null, time: null };
        let longPollingInterval = null;
        const elements = {
            pages: {
                book: document.getElementById('book-page'),
                manage: document.getElementById('manage-page'),
                password: document.getElementById('password-page'),
                roster: document.getElementById('roster-page'),
                'edit-section': document.getElementById('edit-section'),
                'reschedule-section': document.getElementById('reschedule-section'),
                'cancel-section': document.getElementById('cancel-section')
            },
            navLinks: document.querySelectorAll('.nav-item'),
            servicePickerInput: document.getElementById('service-picker-input'),
            servicePickerModal: document.getElementById('service-picker-modal'),
            categoryGrid: document.getElementById('category-grid'),
            serviceCategoryList: document.getElementById('service-category-list'),
            serviceListContainer: document.getElementById('service-list-container'),
            serviceListTitle: document.getElementById('service-list-title'),
            serviceGridModal: document.getElementById('service-grid-modal'),
            backToCategoriesBtn: document.getElementById('back-to-categories'),
            step2: document.getElementById('step-2'),
            step3: document.getElementById('step-3'),
            selectedServiceId: document.getElementById('selected-service-id'),
            bookingDateInput: document.getElementById('booking-date'),
            bookingTimeInput: document.getElementById('booking-time'),
            bookingTimeSelect: document.getElementById('booking-time-select'),
            customerNameInput: document.getElementById('customer-name'),
            customerMobileInput: document.getElementById('customer-mobile'),
            bookNowBtn: document.getElementById('book-now-btn'),
            appointmentsDateInput: document.getElementById('appointments-date'),
            searchInput: document.getElementById('search-appointments'),
            searchBtn: document.getElementById('search-btn'),
            totalBookings: document.getElementById('total-bookings'),
            appointmentsTableBody: document.getElementById('appointments-table-body'),
            messageDialog: document.getElementById('message-dialog'),
            messageIconContainer: document.getElementById('message-icon-container'),
            messageText: document.getElementById('message-text'),
            messageDetails: document.getElementById('message-details'),
            closeDialogBtn: document.getElementById('close-dialog'),
            timeSlotModal: document.getElementById('time-slot-modal'),
            modalDateDisplay: document.getElementById('modal-date-display'),
            timeSlotGrid: document.getElementById('time-slot-grid'),
            closeTimeModal: document.getElementById('close-time-modal'),
            currentTimeDisplay: document.getElementById('current-time'),
            oldPasswordInput: document.getElementById('old-password'),
            newPasswordInput: document.getElementById('new-password'),
            confirmNewPasswordInput: document.getElementById('confirm-new-password'),
            passwordMessage: document.getElementById('password-message'),
            rosterDateInput: document.getElementById('roster-date'),
            rosterBlockedSlotsBody: document.getElementById('roster-blocked-slots-body'),
            rosterDailyBreaksBody: document.getElementById('roster-daily-breaks-body'),
            editAppId: document.getElementById('edit-app-id'),
            editAppName: document.getElementById('edit-app-name'),
            editAppMobile: document.getElementById('edit-app-mobile'),
            editAppService: document.getElementById('edit-app-service'),
            rescheduleAppId: document.getElementById('reschedule-app-id'),
            rescheduleServiceId: document.getElementById('reschedule-service-id'),
            rescheduleDate: document.getElementById('reschedule-date'),
            rescheduleTime: document.getElementById('reschedule-time'),
            rescheduleTimeSelect: document.getElementById('reschedule-time-select'),
            cancelAppId: document.getElementById('cancel-app-id'),
            confirmCancelBtn: document.getElementById('confirm-cancel-btn')
        };
        
        const formatDateForDisplay = (dateString) => {
            const date = new Date(dateString);
            return date.toLocaleDateString('en-IN', { day: '2-digit', month: '2-digit', year: 'numeric' });
        };
        
        const fetchRosterData = async (date) => {
            try {
                const response = await fetch(`?action=roster_data&date=${date}`);
                const result = await response.json();
                if (result.success) {
                    renderBlockedSlots(result.blocked_slots);
                    renderDailyBreaks(result.daily_breaks);
                } else {
                    renderBlockedSlots([]);
                    renderDailyBreaks([]);
                }
            } catch (error) {
                console.error('Failed to fetch roster data:', error);
                showMessage('Error', 'Failed to load roster data.', 'error');
            }
        };
        
        const renderBlockedSlots = (slots) => {
            elements.rosterBlockedSlotsBody.innerHTML = '';
            if (slots.length === 0) {
                elements.rosterBlockedSlotsBody.innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--light); opacity: 0.7;">No blocked slots for this day.</td></tr>`;
                return;
            }
            slots.forEach(slot => {
                const row = document.createElement('tr');
                const format = timeStr => {
                    if (timeStr) {
                        const date = new Date(timeStr);
                        return date.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true });
                    }
                    return '';
                };
                row.innerHTML = `
                    <td>${format(slot.start_datetime)}</td>
                    <td>${format(slot.end_datetime)}</td>
                    <td>${slot.reason}</td>
                `;
                elements.rosterBlockedSlotsBody.appendChild(row);
            });
        };
        
        const renderDailyBreaks = (breaks) => {
            elements.rosterDailyBreaksBody.innerHTML = '';
            if (breaks.length === 0) {
                elements.rosterDailyBreaksBody.innerHTML = `<tr><td colspan="2" style="text-align: center; color: var(--light); opacity: 0.7;">No daily breaks set.</td></tr>`;
                return;
            }
            breaks.forEach(breakData => {
                const row = document.createElement('tr');
                const format = timeStr => {
                    const [hour, minute] = timeStr.split(':');
                    const date = new Date();
                    date.setHours(hour, minute, 0);
                    return date.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true });
                };
                row.innerHTML = `
                    <td>${format(breakData.start_time)}</td>
                    <td>${format(breakData.end_time)}</td>
                `;
                elements.rosterDailyBreaksBody.appendChild(row);
            });
        };
        
        const showPage = (pageId) => {
            for (const key in elements.pages) {
                if(elements.pages[key]) {
                    elements.pages[key].classList.remove('active');
                    elements.pages[key].classList.add('hidden');
                }
            }
            
            if (elements.pages[pageId]) {
                elements.pages[pageId].classList.remove('hidden');
                elements.pages[pageId].classList.add('active');
            }
            
            elements.navLinks.forEach(link => {
                link.classList.remove('active');
                if (link.dataset.page === pageId) link.classList.add('active');
            });
            
            if (['edit-section', 'reschedule-section', 'cancel-section'].includes(pageId)) {
                document.querySelector('.nav-item[data-page="manage"]').classList.add('active');
            }
            
            history.pushState(null, '', '#' + pageId);

            if (pageId === 'book') {
                resetBookingForm();
            } else if (pageId === 'manage') {
                const today = new Date().toISOString().slice(0, 10);
                elements.appointmentsDateInput.value = today;
                fetchAppointments(today);
            } else if (pageId === 'roster') {
                const today = new Date().toISOString().slice(0, 10);
                elements.rosterDateInput.value = today;
                fetchRosterData(today);
            }
        };
        
        const updateCurrentTime = () => {
            const now = new Date();
            elements.currentTimeDisplay.textContent = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true });
        }
        
        const showMessage = (title, message, type = 'success', details = null) => {
            elements.messageText.textContent = title;
            const dialogContent = elements.messageDialog.querySelector('.dialog-content');
            
            let iconHtml = '';
            if (type === 'success') {
                iconHtml = `<svg class="checkmark" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 52 52"><circle class="checkmark-circle" cx="26" cy="26" r="25" fill="none" style="stroke: var(--success);"/><path class="checkmark-check" fill="none" d="M14.1 27.2l7.1 7.2 16.7-16.8" style="stroke: var(--success);"/></svg>`;
            } else if (type === 'error') {
                iconHtml = `<i class="fas fa-times-circle" style="font-size: 3rem; color: var(--danger);"></i>`;
            } else if (type === 'info') {
                 iconHtml = `<i class="fas fa-info-circle" style="font-size: 3rem; color: var(--secondary);"></i>`;
            }

            elements.messageIconContainer.innerHTML = iconHtml;

            elements.messageDialog.classList.remove('success-receipt');
            
            let detailsHtml = message ? `<p>${message}</p>` : '';
            if (details) {
                detailsHtml = `
                    <div class="customer-name-display">${details.name}</div>
                    <div class="appointment-confirmed-text">Your appointment is confirmed.</div>
                    <div class="booking-details-box">
                        <div style="font-size: 1.1em;">Serial Number: <strong>${details.serial}</strong></div>
                        <div style="font-size: 1.1em;">Service: <strong>${details.service}</strong></div>
                        <div style="font-size: 1.1em;">Date: <strong>${details.date}</strong></div>
                        <div style="font-size: 1.1em;">Time: <strong>${details.startTime} - ${details.endTime}</strong></div>
                    </div>
                `;
            }
            elements.messageDetails.innerHTML = detailsHtml;
            elements.messageDialog.classList.remove('hidden');
        };
        
        const apiPost = async (body) => {
            try {
                const response = await fetch('dashboard.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
                    body: JSON.stringify({...body, csrf_token: csrfToken})
                });
                 if (response.status === 401) { // Unauthorized (session expired)
                    showMessage('Session Expired', 'You have been logged out due to inactivity.', 'info');
                    setTimeout(() => window.location.href = '../logout.php?reason=inactive', 3000);
                    return { success: false, message: 'Session expired.' };
                }
                return await response.json();
            } catch (error) {
                console.error('API Error:', error);
                showMessage('Network Error', 'Could not connect to the server.', 'error');
                return { success: false, message: 'Network error.' };
            }
        };

        // UPDATED: New function to calculate max booking date
        const calculateMaxBookingDate = () => {
            let currentDate = new Date();
            let workingDaysToAdd = 2;
            while (workingDaysToAdd > 0) {
                currentDate.setDate(currentDate.getDate() + 1);
                // getDay() returns 0 for Sunday
                if (currentDate.getDay() !== 0) {
                    workingDaysToAdd--;
                }
            }
            return currentDate.toISOString().slice(0, 10);
        };
        
        const fetchServices = async () => {
            try {
                const response = await fetch('?action=services');
                if (!response.ok) throw new Error('Network response was not ok');
                const result = await response.json();
                if (result.success) {
                    servicesData = result.services;
                    renderServiceCategories(Object.keys(servicesData));
                } else {
                    throw new Error(result.message || "Failed to fetch services.");
                }
            } catch (error) {
                console.error('Failed to fetch services:', error);
                showMessage('Error', 'Failed to load services. Please check the database connection.', 'error');
            }
        };
        
        const renderServiceOptions = (allServices, selectedId) => {
            const selectElement = document.getElementById('edit-app-service');
            selectElement.innerHTML = '';
            allServices.forEach(service => {
                const option = document.createElement('option');
                option.value = service.id;
                option.textContent = service.name;
                if (service.id == selectedId) option.selected = true;
                selectElement.appendChild(option);
            });
        };
        
        const renderServiceCategories = (categories) => {
            elements.categoryGrid.innerHTML = '';
            if (categories.length === 0) {
                elements.categoryGrid.innerHTML = '<p style="grid-column: 1 / -1; text-align: center; color: var(--light); opacity: 0.7;">No categories available.</p>';
                return;
            }
            categories.forEach(category => {
                const button = document.createElement('div');
                button.className = 'category-button';
                button.innerHTML = `<span>${category}</span>`;
                button.dataset.category = category;
                button.addEventListener('click', () => {
                    renderServiceList(category);
                });
                elements.categoryGrid.appendChild(button);
            });
            elements.serviceCategoryList.classList.remove('hidden');
            elements.serviceListContainer.classList.add('hidden');
            elements.servicePickerModal.classList.remove('hidden');
        };
        
        const renderServiceList = (category) => {
            const services = servicesData[category] || [];
            elements.serviceGridModal.innerHTML = '';
            if (services.length === 0) {
                elements.serviceGridModal.innerHTML = '<p style="grid-column: 1 / -1; text-align: center; color: var(--light); opacity: 0.7;">No services available in this category.</p>';
                return;
            }
            elements.serviceListTitle.textContent = category;
            services.forEach(service => {
                const button = document.createElement('div');
                button.className = 'service-button';
                button.innerHTML = `<i class="fas ${service.icon || 'fa-concierge-bell'}"></i><span>${service.name} <br><span style="font-size: 0.8rem; opacity: 0.7;">${service.duration_minutes} min</span></span>`;
                button.dataset.serviceId = service.id;
                button.dataset.serviceName = service.name;
                button.addEventListener('click', (event) => {
                    event.stopPropagation();
                    selectService(service.id, service.name);
                });
                elements.serviceGridModal.appendChild(button);
            });
            elements.serviceCategoryList.classList.add('hidden');
            elements.serviceListContainer.classList.remove('hidden');
        };
        
        const selectService = (serviceId, serviceName) => {
            selected.serviceId = serviceId;
            selected.serviceName = serviceName;
            elements.servicePickerInput.value = serviceName;
            elements.selectedServiceId.value = serviceId;
            elements.servicePickerModal.classList.add('hidden');
            
            elements.step2.classList.remove('hidden');
            elements.step3.classList.remove('hidden');
            
            const today = new Date().toISOString().slice(0, 10);
            
            // UPDATED: Use new function to calculate max date
            const maxDateStr = calculateMaxBookingDate();

            elements.bookingDateInput.value = today;
            elements.bookingDateInput.min = today;
            elements.bookingDateInput.max = maxDateStr;

            elements.bookingTimeInput.readOnly = true;
            elements.bookingTimeInput.placeholder = 'Click to select a time slot...';
            elements.bookingTimeSelect.value = '';

            openTimeSlotModal(
                elements.bookingTimeInput, elements.bookingTimeSelect, elements.bookingDateInput.value,
                elements.selectedServiceId.value, elements.timeSlotModal, elements.timeSlotGrid, elements.modalDateDisplay
            );
        };

        const openTimeSlotModal = async (targetInput, targetSelect, date, serviceId, modalElement, gridElement, dateDisplayElement) => {
            if (!date || !serviceId) {
                showMessage('Error', 'Please select a service and date first.', 'error');
                return;
            }
            
            dateDisplayElement.textContent = `Available Slots for ${formatDateForDisplay(date)}`;
            gridElement.innerHTML = '<div style="grid-column: 1 / -1; color: var(--light); opacity: 0.7; text-align: center;">Loading available slots...</div>';
            modalElement.classList.remove('hidden');
            
            try {
                const response = await fetch(`?action=available_slots&service_id=${serviceId}&date=${date}`);
                if (!response.ok) throw new Error('Network response was not ok');
                const result = await response.json();
                
                gridElement.innerHTML = '';
                if (result.success && result.slots.length > 0) {
                    result.slots.forEach(slot => {
                        const button = document.createElement('div');
                        button.className = 'time-slot-button';
                        const formattedTime = new Date(`1970-01-01T${slot}:00`).toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true });
                        button.textContent = formattedTime;
                        button.onclick = () => {
                            document.querySelectorAll('.time-slot-button.selected').forEach(btn => btn.classList.remove('selected'));
                            button.classList.add('selected');
                            
                            targetInput.value = formattedTime;
                            targetSelect.value = slot;
                            modalElement.classList.add('hidden');
                        };
                        gridElement.appendChild(button);
                    });
                    
                    const firstSlot = result.slots[0];
                    if(firstSlot) {
                        const firstButton = gridElement.querySelector('.time-slot-button');
                        if (firstButton) {
                            firstButton.classList.add('selected');
                            targetInput.value = firstButton.textContent;
                            targetSelect.value = firstSlot;
                        }
                    }
                } else {
                    gridElement.innerHTML = `<div style="grid-column: 1 / -1; color: var(--light); opacity: 0.7; text-align: center;">${result.message || 'No slots available for this day.'}</div>`;
                    targetInput.value = '';
                    targetSelect.value = '';
                }
            } catch (error) {
                console.error('Failed to fetch available slots:', error);
                showMessage('Error', 'An error occurred while fetching slots.', 'error');
            }
        };

        const submitBooking = async () => {
            const name = elements.customerNameInput.value;
            const mobile = elements.customerMobileInput.value;
            const serviceId = elements.selectedServiceId.value;
            const date = elements.bookingDateInput.value;
            const time = elements.bookingTimeSelect.value;
            
            if (!name || !date || !time) return showMessage('Incomplete', 'Please fill in all required fields.', 'error');
            if (mobile && (mobile.length !== 10 || !/^\d{10}$/.test(mobile))) {
                return showMessage('Invalid Mobile Number', 'Please enter a valid 10-digit mobile number.', 'error');
            }
            
            const result = await apiPost({ action: 'book', service_id: serviceId, name, mobile, date, time });
            if (result.success) {
                showMessage('', '', 'success', result.details);
                resetBookingForm();
            } else {
                showMessage('Booking Failed', result.message, 'error');
            }
        };
        
        const resetBookingForm = () => {
            elements.step2.classList.add('hidden');
            elements.step3.classList.add('hidden');
            elements.customerNameInput.value = '';
            elements.customerMobileInput.value = '';
            elements.selectedServiceId.value = null;
            elements.servicePickerInput.value = '';
            selected.serviceId = null;
            selected.serviceName = null;
        };
        
        const fetchAppointments = async (date) => {
            try {
                const response = await fetch(`?action=view_appointments&date=${date}`);
                if (!response.ok) throw new Error('Network response was not ok');
                const result = await response.json();
                if (result.success) {
                    allFetchedAppointments = result.appointments;
                    elements.totalBookings.textContent = allFetchedAppointments.length;
                    renderAppointments(allFetchedAppointments);
                }
            } catch(error) {
                showMessage('Error', 'Failed to fetch appointments.', 'error');
            }
        };
        
        const renderAppointments = (appointments) => {
            const searchTerm = elements.searchInput.value.toLowerCase();
            const filteredAppointments = appointments.filter(app => {
                const nameMatch = app.customer_name.toLowerCase().includes(searchTerm);
                const mobileMatch = app.customer_mobile ? app.customer_mobile.toLowerCase().includes(searchTerm) : false;
                const serviceMatch = app.service_name.toLowerCase().includes(searchTerm);
                return nameMatch || mobileMatch || serviceMatch;
            });

            elements.appointmentsTableBody.innerHTML = '';
            if (filteredAppointments.length === 0) {
                elements.appointmentsTableBody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--light); opacity: 0.7; padding: 40px;">No bookings found for this date.</td></tr>`;
                return;
            }
            
            filteredAppointments.forEach(app => {
                const row = document.createElement('tr');
                const formattedTime = new Date(app.appointment_datetime).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: true });
                
                let rescheduleInfo = '';
                if (app.is_rescheduled == 1 && app.original_appointment_datetime) {
                    const originalTime = new Date(app.original_appointment_datetime);
                    const formattedOriginal = originalTime.toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' });
                    rescheduleInfo = `<span class="reschedule-badge" data-tooltip="Original: ${formattedOriginal}">Rescheduled</span>`;
                }

                row.innerHTML = `
                    <td>${app.serial_number}</td>
                    <td>${formattedTime}</td>
                    <td>${app.customer_name} ${rescheduleInfo}</td>
                    <td>${app.customer_mobile || 'N/A'}</td>
                    <td>${app.service_name} <br><span style="font-size: 0.8rem; opacity: 0.7;">${app.duration_minutes} min</span></td>
                    <td>
                        <div class="action-buttons">
                            <button class="action-button edit-btn" data-tooltip="Edit" data-id="${app.id}" data-name="${app.customer_name}" data-mobile="${app.customer_mobile}" data-service="${app.service_id}"><i class="fas fa-edit"></i></button>
                            <button class="action-button reschedule-btn" data-tooltip="Reschedule" data-id="${app.id}" data-service="${app.service_id}"><i class="fas fa-redo"></i></button>
                            <button class="action-button cancel-btn" data-tooltip="Cancel" data-id="${app.id}"><i class="fas fa-trash-alt"></i></button>
                        </div>
                    </td>
                `;
                elements.appointmentsTableBody.appendChild(row);
            });
            addActionListeners();
        };
        
        const changePassword = async (event) => {
            event.preventDefault();
            const oldPassword = elements.oldPasswordInput.value;
            const newPassword = elements.newPasswordInput.value;
            const confirmPassword = elements.confirmNewPasswordInput.value;
            elements.passwordMessage.classList.add('hidden');

            if (newPassword !== confirmPassword) {
                elements.passwordMessage.textContent = 'New passwords do not match.';
                elements.passwordMessage.classList.remove('hidden', 'success');
                elements.passwordMessage.classList.add('error');
                return;
            }
            if (newPassword.length < 8) {
                elements.passwordMessage.textContent = 'New password must be at least 8 characters long.';
                elements.passwordMessage.classList.remove('hidden', 'success');
                elements.passwordMessage.classList.add('error');
                return;
            }
            
            const result = await apiPost({ action: 'change_password', old_password: oldPassword, new_password: newPassword });
            
            elements.passwordMessage.textContent = result.message;
            elements.passwordMessage.classList.remove('hidden');
            if (result.success) {
                elements.passwordMessage.classList.remove('error');
                elements.passwordMessage.classList.add('success');
                elements.oldPasswordInput.value = '';
                elements.newPasswordInput.value = '';
                elements.confirmNewPasswordInput.value = '';
            } else {
                elements.passwordMessage.classList.remove('success');
                elements.passwordMessage.classList.add('error');
            }
        };
        
        const addActionListeners = () => {
            document.querySelectorAll('.action-button.edit-btn').forEach(button => {
                button.addEventListener('click', (e) => {
                    const id = e.currentTarget.dataset.id;
                    const name = e.currentTarget.dataset.name;
                    const mobile = e.currentTarget.dataset.mobile;
                    const serviceId = e.currentTarget.dataset.service;
                    prepareAndShowEditSection(id, name, mobile, serviceId);
                });
            });
            
            document.querySelectorAll('.action-button.reschedule-btn').forEach(button => {
                button.addEventListener('click', (e) => {
                    const id = e.currentTarget.dataset.id;
                    const serviceId = e.currentTarget.dataset.service;
                    prepareAndShowRescheduleSection(id, serviceId);
                });
            });

            document.querySelectorAll('.action-button.cancel-btn').forEach(button => {
                button.addEventListener('click', (e) => {
                    const id = e.currentTarget.dataset.id;
                    prepareAndShowCancelSection(id);
                });
            });
        };
        
        const prepareAndShowEditSection = async (id, name, mobile, serviceId) => {
            elements.editAppId.value = id;
            elements.editAppName.value = name;
            elements.editAppMobile.value = mobile === 'null' ? '' : mobile;
            
            if (Object.keys(servicesData).length === 0) {
                await fetchServices();
            }
            const allServices = Object.values(servicesData).flat();
            renderServiceOptions(allServices, serviceId);
            
            showPage('edit-section');
        };

        const prepareAndShowRescheduleSection = (id, serviceId) => {
            elements.rescheduleAppId.value = id;
            elements.rescheduleServiceId.value = serviceId;
            
            const today = new Date().toISOString().slice(0, 10);
            elements.rescheduleDate.value = today;
            elements.rescheduleDate.min = today;
            
            // UPDATED: Use new function to calculate max date for reschedule page
            const maxDateStr = calculateMaxBookingDate();
            elements.rescheduleDate.max = maxDateStr;

            elements.rescheduleTime.value = 'Click to select time slot...';
            elements.rescheduleTimeSelect.value = '';
            
            showPage('reschedule-section');
        };

        const prepareAndShowCancelSection = (id) => {
            elements.cancelAppId.value = id;
            showPage('cancel-section');
        };

        const setupModalCloseEvents = () => {
            const modals = document.querySelectorAll('.dialog');
            modals.forEach(modal => {
                modal.addEventListener('click', (event) => {
                    if (event.target === modal) {
                        modal.classList.add('hidden');
                    }
                });
                const closeBtn = modal.querySelector('.close-btn');
                if (closeBtn) {
                    closeBtn.addEventListener('click', () => {
                        modal.classList.add('hidden');
                    });
                }
            });
        };

        const pollAppointments = async (date) => {
            try {
                const response = await fetch(`?action=view_appointments&date=${date}`);
                const result = await response.json();
                if (result.success) {
                    allFetchedAppointments = result.appointments;
                    elements.totalBookings.textContent = allFetchedAppointments.length;
                    renderAppointments(allFetchedAppointments);
                }
            } catch (error) {
                console.error('Polling failed:', error);
            }
        };

        /**
         * Sets up a client-side timer to detect user inactivity and log them out.
         */
        const setupInactivityTimer = () => {
            let inactivityTimeout;

            const logoutUser = () => {
                // Use the existing showMessage function to inform the user
                showMessage('Session Expired', 'You will be logged out due to inactivity.', 'info');
                
                // Hide the default "OK" button to prevent the user from dismissing the notice
                elements.closeDialogBtn.style.display = 'none';

                // Redirect to the logout page after a few seconds
                setTimeout(() => {
                    window.location.href = '../logout.php?reason=inactive';
                }, 4000); // Redirect after 4 seconds
            };

            const resetTimer = () => {
                clearTimeout(inactivityTimeout);
                inactivityTimeout = setTimeout(logoutUser, 300000); // 5 minutes = 300,000 ms
            };

            // Listen for various user activities to reset the timer
            window.addEventListener('mousemove', resetTimer, false);
            window.addEventListener('mousedown', resetTimer, false);
            window.addEventListener('keypress', resetTimer, false);
            window.addEventListener('touchmove', resetTimer, false);
            window.addEventListener('scroll', resetTimer, false);

            // Start the timer when the page loads
            resetTimer();
        };
        
        document.addEventListener('DOMContentLoaded', () => {
            particlesJS('particles-js', {
                particles: {
                    number: { value: 80, density: { enable: true, value_area: 800 } },
                    color: { value: "#6366f1" },
                    shape: { type: "circle" },
                    opacity: { value: 0.5, random: true },
                    size: { value: 3, random: true },
                    line_linked: {
                        enable: true,
                        distance: 150,
                        color: "#6366f1",
                        opacity: 0.4,
                        width: 1
                    },
                    move: {
                        enable: true,
                        speed: 2,
                        direction: "none",
                        random: true,
                        straight: false,
                        out_mode: "out",
                        bounce: false
                    }
                },
                interactivity: {
                    detect_on: "canvas",
                    events: {
                        onhover: { enable: true, mode: "grab" },
                        onclick: { enable: true, mode: "push" },
                        resize: true
                    }
                },
                retina_detect: true
            });
            
            elements.navLinks.forEach(link => {
                link.addEventListener('click', (e) => {
                    e.preventDefault();
                    showPage(link.dataset.page);
                    if (document.querySelector('.sidebar').classList.contains('active')) {
                        document.querySelector('.sidebar').classList.remove('active');
                    }
                });
            });
            
            window.addEventListener('hashchange', () => {
                const pageId = window.location.hash.substring(1) || 'book';
                showPage(pageId);
            });

            elements.servicePickerInput.addEventListener('click', (e) => {
                e.stopPropagation();
                fetchServices();
            });
            elements.backToCategoriesBtn.addEventListener('click', () => {
                elements.serviceListContainer.classList.add('hidden');
                elements.serviceCategoryList.classList.remove('hidden');
            });
            
            document.querySelectorAll('.dialog .close-btn').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    e.target.closest('.dialog').classList.add('hidden');
                });
            });

            elements.bookingTimeInput.addEventListener('click', (e) => {
                e.stopPropagation();
                openTimeSlotModal(
                    elements.bookingTimeInput, elements.bookingTimeSelect, elements.bookingDateInput.value,
                    elements.selectedServiceId.value, elements.timeSlotModal, elements.timeSlotGrid, elements.modalDateDisplay
                );
            });
            elements.bookingDateInput.addEventListener('change', () => {
                elements.bookingTimeInput.value = 'Click to select a time slot...';
                elements.bookingTimeSelect.value = '';
                openTimeSlotModal(
                    elements.bookingTimeInput, elements.bookingTimeSelect, elements.bookingDateInput.value,
                    elements.selectedServiceId.value, elements.timeSlotModal, elements.timeSlotGrid, elements.modalDateDisplay
                );
            });
            elements.bookNowBtn.addEventListener('click', submitBooking);
            elements.closeDialogBtn.addEventListener('click', () => elements.messageDialog.classList.add('hidden'));
            elements.closeTimeModal.addEventListener('click', () => elements.timeSlotModal.classList.add('hidden'));
            elements.appointmentsDateInput.addEventListener('change', (e) => {
                elements.searchInput.value = ''; // Clear search on date change
                clearInterval(longPollingInterval);
                fetchAppointments(e.target.value);
                longPollingInterval = setInterval(() => pollAppointments(e.target.value), 3000);
            });
            
            elements.searchInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    renderAppointments(allFetchedAppointments);
                }
            });

            elements.searchBtn.addEventListener('click', () => {
                renderAppointments(allFetchedAppointments);
            });

            elements.rosterDateInput.addEventListener('change', (e) => fetchRosterData(e.target.value));
            document.getElementById('change-password-form').addEventListener('submit', changePassword);
            
            document.getElementById('edit-form').addEventListener('submit', async (e) => {
                e.preventDefault();
                const appointmentId = elements.editAppId.value;
                const name = elements.editAppName.value;
                const mobile = elements.editAppMobile.value;
                const serviceId = elements.editAppService.value;
                const result = await apiPost({ action: 'edit', appointment_id: appointmentId, name, mobile, service_id: serviceId });
                if (result.success) {
                    showMessage('Success', result.message);
                    showPage('manage');
                } else {
                    showMessage('Error', result.message, 'error');
                }
            });
            
            document.getElementById('reschedule-form').addEventListener('submit', async (e) => {
                e.preventDefault();
                const appointmentId = elements.rescheduleAppId.value;
                const newDate = elements.rescheduleDate.value;
                const newTime = elements.rescheduleTimeSelect.value;
                
                if (!newDate || !newTime) return showMessage('Incomplete', 'Please select a new date and time.', 'error');
                
                const result = await apiPost({ action: 'reschedule', appointment_id: appointmentId, new_date: newDate, new_time: newTime });
                if (result.success) {
                    showMessage('Success', result.message);
                    showPage('manage');
                } else {
                    showMessage('Error', result.message, 'error');
                }
            });
            
            elements.confirmCancelBtn.addEventListener('click', async () => {
                const appointmentId = elements.cancelAppId.value;
                const result = await apiPost({ action: 'cancel', appointment_id: appointmentId });
                if (result.success) {
                    showMessage('Success', result.message);
                    showPage('manage');
                } else {
                    showMessage('Error', result.message, 'error');
                }
            });
            
            elements.rescheduleTime.addEventListener('click', (e) => {
                e.stopPropagation();
                openTimeSlotModal(
                    elements.rescheduleTime, elements.rescheduleTimeSelect, elements.rescheduleDate.value,
                    elements.rescheduleServiceId.value, elements.timeSlotModal, elements.timeSlotGrid, elements.modalDateDisplay
                );
            });
            elements.rescheduleDate.addEventListener('change', () => {
                elements.rescheduleTime.value = 'Click to select a time slot...';
                elements.rescheduleTimeSelect.value = '';
                openTimeSlotModal(
                    elements.rescheduleTime, elements.rescheduleTimeSelect, elements.rescheduleDate.value,
                    elements.rescheduleServiceId.value, elements.timeSlotModal, elements.timeSlotGrid, elements.modalDateDisplay
                );
            });
            
            // Hamburger menu functionality
            const hamburgerMenu = document.querySelector('.hamburger-menu');
            const sidebar = document.querySelector('.sidebar');
            hamburgerMenu.addEventListener('click', () => {
                sidebar.classList.toggle('active');
            });
            
            setInterval(updateCurrentTime, 1000);
            updateCurrentTime();
            setupModalCloseEvents();

            const initialPage = window.location.hash.substring(1) || 'book';
            showPage(initialPage);
            
            // Initialize the inactivity timer
            setupInactivityTimer();
        });
    </script>
</body>
</html>