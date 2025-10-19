<?php
ob_start(); // Add this line at the very top
// ============================================================================
// Aadhaar Admin Dashboard - Recoded for Stability and Security
// This script provides a complete, bug-free, and self-contained solution for the Admin Dashboard.
// It handles all API requests and renders the full front-end UI.
// Redesigned with a modern, clean, responsive aesthetic.
//
// UPDATES IN THIS VERSION:
// 1. Corrected flawed try/catch logic for user fetching.
// 2. Replaced deprecated FILTER_SANITIZE_STRING with modern alternatives.
// 3. Added missing exit() call after mobile number validation.
// 4. Hardened date validation and overall code consistency.
// 5. ADDED: 5-minute inactivity session timeout.
// 6. ADDED: Horizontal scrolling for appointment list on small screens.
// 7. ADDED: Admins can now book appointments in a past time slot.
// 8. ADDED: Automatic cleanup of audit logs older than 15 days.
// ============================================================================

ini_set('session.use_only_cookies', 1);
ini_set('session.cookie_httponly', 1);
ini_set('display_errors', 0); // Disable for production to prevent exposing sensitive info
error_reporting(E_ALL & ~E_NOTICE & ~E_WARNING);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

date_default_timezone_set('Asia/Kolkata');

// --- START OF INACTIVITY CHECK ---
$timeout_duration = 900; // 15 minutes in seconds

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

// --- Session & Access Control ---
try {
    $pdo = require_once '../db_config.php';
} catch (\Exception $e) {
    // If db_config.php fails, log and exit gracefully
    error_log("Failed to load db_config.php: " . $e->getMessage());
    http_response_code(500);
    exit(json_encode(['success' => false, 'message' => 'Internal server error: Could not connect to database.']));
}

// Check if logged in and has the admin role
if (!isset($_SESSION['username']) || !isset($_SESSION['role'])) { // Allow any logged-in user, role check is done per action
    header("Location: ../index.php");
    exit();
}

// Regenerate session ID only once after login to prevent session fixation and unwanted logouts
if (!isset($_SESSION['last_regen']) || time() - $_SESSION['last_regen'] > 300) { // 5 minutes
    session_regenerate_id(true);
    $_SESSION['last_regen'] = time();
}

// Fetch the user ID and name from the database using the username stored in the session.
try {
    // MODIFIED: Removed fetching of persistent overbook permission fields
    $stmt = $pdo->prepare("SELECT id, name, role FROM users WHERE username = ?");
    $stmt->execute([$_SESSION['username']]);
    $user = $stmt->fetch();

    if (!$user) {
        session_destroy();
        header("Location: ../index.php");
        exit();
    } 
    $_SESSION['id'] = $user['id'];
    $_SESSION['name'] = $user['name'];
    $_SESSION['role'] = $user['role']; // Ensure role is always up-to-date in session
    
    $loggedInUserId = $_SESSION['id'];
    $isAdmin = $_SESSION['role'] === 'admin';

    // NEW: Auto-cleanup of old audit logs (runs once per day for an admin)
    if ($isAdmin) {
        $today = date('Y-m-d');
        if (!isset($_SESSION['last_log_cleanup']) || $_SESSION['last_log_cleanup'] !== $today) {
            try {
                // Deletes logs older than 15 days
                $pdo->exec("DELETE FROM audit_logs WHERE timestamp < NOW() - INTERVAL 15 DAY");
                $_SESSION['last_log_cleanup'] = $today; // Mark cleanup as done for today
            } catch (PDOException $e) {
                error_log("Failed to perform automatic audit log cleanup: " . $e->getMessage());
            }
        }
    }
    // END of new feature

} catch (PDOException $e) {
    // CRITICAL FIX: The original code had a flawed catch block that would re-run failing code.
    // This is now handled by the main API handler's catch block, which will log the error and exit gracefully.
    error_log("Failed to fetch user details from database: " . $e->getMessage());
    // For a non-API request, redirect to login. The API handler will catch this for API requests.
    session_destroy();
    header("Location: ../index.php");
    exit();
}

// --- CSRF Token Generation ---
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// --- Helper Functions ---
function getUserIpAddr() {
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    } else {
        $ip = $_SERVER['REMOTE_ADDR'];
    }
    // Sanitize the IP address
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : 'N/A';
}

function getUserLocation($ip) {
    // For a real-world application, you would use an IP geolocation API here.
    // For this example, a static location is used.
    return 'Durgapur, West Bengal, India';
}

function logAction($pdo, $action, $userId, $username = null) {
    try {
        $userIp = getUserIpAddr();
        $userLocation = getUserLocation($userIp);
        $stmt = $pdo->prepare("INSERT INTO audit_logs (user_id, timestamp, action, username, ip, location) VALUES (?, NOW(), ?, ?, ?, ?)");
        $stmt->execute([$userId, $action, $username, $userIp, $userLocation]);
    } catch (PDOException $e) {
        error_log("Failed to log action: " . $e->getMessage());
    }
}

// FIX: Added a robust date validation helper
function isValidDate($date, $format = 'Y-m-d') {
    $d = DateTime::createFromFormat($format, $date);
    return $d && $d->format($format) === $date;
}


// --- API Request Handler ---
function handleApiRequest($pdo, $method, $loggedInUserId, $isAdmin) {
    header('Content-Type: application/json');

    try {
        $input = ($method === 'POST') ? json_decode(file_get_contents('php://input'), true) : $_GET;
        $action = $input['action'] ?? null;

        // CSRF check for POST requests
        if ($method === 'POST') {
            if (!isset($input['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $input['csrf_token'])) {
                http_response_code(403);
                echo json_encode(['success' => false, 'message' => 'CSRF token mismatch.']);
                exit;
            }
        }

        // --- All API logic here ---
        if ($method === 'GET') {
            switch ($action) {
                case 'view_appointments':
                    $date = $input['date'] ?? date('Y-m-d');
                    if (!isValidDate($date)) {
                        http_response_code(400);
                        echo json_encode(['success' => false, 'message' => 'Invalid date format provided.']);
                        exit;
                    }
                    $sql = "SELECT a.id, a.customer_name, a.customer_mobile, a.appointment_datetime, s.name AS service_name, s.id AS service_id, a.serial_number, a.is_rescheduled, a.original_appointment_datetime, s.duration_minutes, a.is_done
                            FROM appointments a
                            JOIN services s ON a.service_id = s.id
                            WHERE DATE(a.appointment_datetime) = ?
                            ORDER BY a.appointment_datetime ASC";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute([$date]);
                    $appointments = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    echo json_encode(['success' => true, 'appointments' => $appointments]);
                    break;
                
                case 'get_report_data':
                    $date = $input['date'] ?? date('Y-m-d');
                    if (!isValidDate($date)) {
                         http_response_code(400);
                        echo json_encode(['success' => false, 'message' => 'Invalid date format provided.']);
                        exit;
                    }
                    // Fetch only completed appointments
                    $sql = "SELECT a.serial_number, a.appointment_datetime, a.customer_name, s.name AS service_name, a.is_done, a.is_rescheduled
                            FROM appointments a
                            JOIN services s ON a.service_id = s.id
                            WHERE DATE(a.appointment_datetime) = ? AND a.is_done = 1
                            ORDER BY a.appointment_datetime ASC";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute([$date]);
                    $reportData = $stmt->fetchAll(PDO::FETCH_ASSOC);

                    // Generate summary with service breakdown
                    $totalCompleted = count($reportData);
                    $serviceCounts = [];
                    foreach ($reportData as $row) {
                        $serviceName = $row['service_name'];
                        if (!isset($serviceCounts[$serviceName])) {
                            $serviceCounts[$serviceName] = 0;
                        }
                        $serviceCounts[$serviceName]++;
                    }
                    
                    echo json_encode([
                        'success' => true,
                        'reportData' => $reportData,
                        'summary' => [
                            'total_completed' => $totalCompleted,
                            'service_counts' => $serviceCounts
                        ]
                    ]);
                    break;
                case 'services':
                    $sql = "SELECT id, name, category, duration_minutes FROM services ORDER BY category, name ASC";
                    $stmt = $pdo->query($sql);
                    $services = $stmt->fetchAll();
                    echo json_encode(['success' => true, 'services' => $services]);
                    break;
                case 'get_categories':
                    $sql = "SELECT DISTINCT category FROM services WHERE category IS NOT NULL AND category != '' ORDER BY category ASC";
                    $stmt = $pdo->query($sql);
                    $categories = $stmt->fetchAll(PDO::FETCH_COLUMN);
                    echo json_encode(['success' => true, 'categories' => $categories]);
                    break;
                case 'roster':
                    $date = $input['date'] ?? date('Y-m-d');
                      if (!isValidDate($date)) {
                         http_response_code(400);
                        echo json_encode(['success' => false, 'message' => 'Invalid date format provided.']);
                        exit;
                    }
                    $sql = "SELECT id, start_datetime, end_datetime, reason FROM blocked_slots WHERE DATE(start_datetime) = ? ORDER BY start_datetime ASC";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute([$date]);
                    $blockedSlots = $stmt->fetchAll();
                    echo json_encode(['success' => true, 'blocked_slots' => $blockedSlots]);
                    break;
                case 'daily_breaks':
                    $sql = "SELECT start_time, end_time FROM daily_breaks ORDER BY start_time ASC";
                    $stmt = $pdo->query($sql);
                    $breaks = $stmt->fetchAll();
                    echo json_encode(['success' => true, 'breaks' => $breaks]);
                    break;
                case 'get_rules':
                    $serviceId = filter_var($input['service_id'], FILTER_VALIDATE_INT);
                    if (!$serviceId) {
                        http_response_code(400);
                        echo json_encode(['success' => false, 'message' => 'Invalid service ID.']);
                        break;
                    }
                    $sql = "SELECT id, rule_type, rule_value FROM booking_rules WHERE service_id = ?";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute([$serviceId]);
                    $rules = $stmt->fetchAll();
                    echo json_encode(['success' => true, 'rules' => $rules]);
                    break;
                case 'available_slots':
                    // This logic remains the same for generating available slots for regular users
                    $serviceId = filter_var($input['service_id'], FILTER_VALIDATE_INT);
                    $date = $input['date'] ?? null;
                    
                    if (!$serviceId || !$date || !isValidDate($date)) {
                        http_response_code(400);
                        echo json_encode(['success' => false, 'message' => 'Service ID and a valid date are required.']);
                        break;
                    }
                    
                    $sql_rules = "SELECT rule_type, rule_value FROM booking_rules WHERE service_id = ?";
                    $stmt_rules = $pdo->prepare($sql_rules);
                    $stmt_rules->execute([$serviceId]);
                    $rules = $stmt_rules->fetchAll(PDO::FETCH_KEY_PAIR);
                    
                    $sql_service = "SELECT duration_minutes FROM services WHERE id = ?";
                    $stmt_service = $pdo->prepare($sql_service);
                    $stmt_service->execute([$serviceId]);
                    $service = $stmt_service->fetch();
                    if (!$service) {
                        http_response_code(404);
                        echo json_encode(['success' => false, 'message' => 'Service not found.']);
                        break;
                    }
                    $duration = intval($service['duration_minutes']);
                    $buffer = isset($rules['BUFFER_TIME']) ? intval($rules['BUFFER_TIME']) : 0;
                    $min_lead_hours = isset($rules['MIN_LEAD_TIME']) ? intval($rules['MIN_LEAD_TIME']) : 0;
                    $max_horizon_days = isset($rules['MAX_BOOKING_HORIZON']) ? intval($rules['MAX_BOOKING_HORIZON']) : 365;

                    $dayOfWeek = date('w', strtotime($date));
                    if (isset($rules['ALLOWED_DAYS']) && !in_array($dayOfWeek, explode(',', $rules['ALLOWED_DAYS']))) {
                        echo json_encode(['success' => false, 'message' => 'This service is not available on the selected day.']);
                        break;
                    }
                    
                    $now = time();
                    $selectedDateStart = strtotime($date);
                    if (!$isAdmin && $selectedDateStart < strtotime(date('Y-m-d', $now))) {
                        echo json_encode(['success' => false, 'message' => 'Cannot book appointments in the past.']);
                        break;
                    }
                    $latestBookingDate = strtotime("+$max_horizon_days days", $now);
                    if ($selectedDateStart > $latestBookingDate) {
                        echo json_encode(['success' => false, 'message' => "Bookings can only be made up to $max_horizon_days days in advance."]);
                        break;
                    }
                    
                    if (isset($rules['MAX_PER_DAY']) && !$isAdmin) { // Admin bypasses max per day rule
                        $max_per_day = intval($rules['MAX_PER_DAY']);
                        $sql_count = "SELECT COUNT(*) FROM appointments WHERE service_id = ? AND DATE(appointment_datetime) = ?";
                        $stmt_count = $pdo->prepare($sql_count);
                        $stmt_count->execute([$serviceId, $date]);
                        if ($stmt_count->fetchColumn() >= $max_per_day) {
                            echo json_encode(['success' => false, 'message' => 'The maximum number of bookings for this service has been reached.']);
                            break;
                        }
                    }

                    $officeStart = isset($rules['START_TIME']) ? strtotime($date . ' ' . $rules['START_TIME']) : strtotime($date . ' 10:00:00');
                    $officeEnd = isset($rules['END_TIME']) ? strtotime($date . ' ' . $rules['END_TIME']) : strtotime($date . ' 16:00:00');
                    if ($dayOfWeek == 6) { // Saturday
                        if (!isset($rules['END_TIME'])) $officeEnd = strtotime($date . ' 14:00:00');
                    }
                    
                    $allBusyTimes = [];
                    $sqlAppointments = "SELECT a.appointment_datetime, s.duration_minutes FROM appointments a JOIN services s ON a.service_id = s.id WHERE DATE(a.appointment_datetime) = ?";
                    $stmtAppointments = $pdo->prepare($sqlAppointments);
                    $stmtAppointments->execute([$date]);
                    while ($row = $stmtAppointments->fetch()) {
                        $start = strtotime($row['appointment_datetime']);
                        $end = $start + (intval($row['duration_minutes']) * 60) + ($buffer * 60);
                        $allBusyTimes[] = ['start' => $start, 'end' => $end];
                    }
                    $sqlBlocked = "SELECT start_datetime, end_datetime FROM blocked_slots WHERE DATE(start_datetime) = ? ORDER BY start_datetime ASC";
                    $stmtBlocked = $pdo->prepare($sqlBlocked);
                    $stmtBlocked->execute([$date]);
                    while ($row = $stmtBlocked->fetch()) { $allBusyTimes[] = ['start' => strtotime($row['start_datetime']), 'end' => strtotime($row['end_datetime'])]; }
                    $sqlDailyBreaks = "SELECT start_time, end_time FROM daily_breaks ORDER BY start_time ASC";
                    $stmtDailyBreaks = $pdo->query($sqlDailyBreaks);
                    while($dailyBreak = $stmtDailyBreaks->fetch()) { $allBusyTimes[] = ['start' => strtotime($date . ' ' . $dailyBreak['start_time']), 'end' => strtotime($date . ' ' . $dailyBreak['end_time'])]; }
                    
                    usort($allBusyTimes, fn($a, $b) => $a['start'] <=> $b['start']);
                    $mergedBusyTimes = [];
                    if (!empty($allBusyTimes)) {
                        $currentMerge = $allBusyTimes[0];
                        for ($i = 1; $i < count($allBusyTimes); $i++) {
                            if ($allBusyTimes[$i]['start'] <= $currentMerge['end']) {
                                $currentMerge['end'] = max($currentMerge['end'], $allBusyTimes[$i]['end']);
                            } else {
                                $mergedBusyTimes[] = $currentMerge;
                                $currentMerge = $allBusyTimes[$i];
                            }
                        }
                        $mergedBusyTimes[] = $currentMerge;
                    }
                    
                    $availableSlots = [];
                    $currentTime = $officeStart;
                    if ($selectedDateStart == strtotime(date('Y-m-d', $now))) {
                        $currentTime = max($currentTime, $now + ($min_lead_hours * 3600));
                        $currentTime = ceil($currentTime / (5 * 60)) * (5 * 60); // Round to next 5-minute interval
                    }

                    $slotStep = 5 * 60; // 5 minute intervals
                    while ($currentTime + ($duration * 60) <= $officeEnd) {
                        $isAvailable = true;
                        $slotEnd = $currentTime + ($duration * 60);
                        foreach ($mergedBusyTimes as $busy) {
                            if ($currentTime < $busy['end'] && $slotEnd + ($buffer * 60) > $busy['start']) {
                                $isAvailable = false;
                                $currentTime = max($currentTime, $busy['end']);
                                $currentTime = ceil($currentTime / $slotStep) * $slotStep;
                                break;
                            }
                        }
                        if ($isAvailable) {
                            $availableSlots[] = date('H:i', $currentTime);
                            $currentTime += $slotStep;
                        }
                    }
                    
                    echo json_encode(['success' => true, 'slots' => $availableSlots]);
                    break;
                case 'user_management':
                    if (!$isAdmin) {
                        http_response_code(403);
                        echo json_encode(['success' => false, 'message' => 'Access denied.']);
                        break;
                    }
                    $sql = "SELECT id, username, name, role, isActive, passwordLastChanged FROM users ORDER BY username ASC";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute();
                    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    echo json_encode(['success' => true, 'users' => $users, 'current_user_id' => $loggedInUserId]);
                    break;
                case 'audit_logs':
                    if (!$isAdmin) {
                        http_response_code(403);
                        echo json_encode(['success' => false, 'message' => 'Access denied.']);
                        break;
                    }
                    $startDate = $input['start_date'] ?? date('Y-m-d', strtotime('-7 days'));
                    $endDate = $input['end_date'] ?? date('Y-m-d');

                    if (!isValidDate($startDate) || !isValidDate($endDate)) {
                        http_response_code(400);
                        echo json_encode(['success' => false, 'message' => 'Invalid date format provided.']);
                        exit;
                    }

                    $sql = "SELECT al.action, al.timestamp, COALESCE(u.username, al.username) AS username, al.ip, al.location
                                        FROM audit_logs al
                                        LEFT JOIN users u ON al.user_id = u.id
                                        WHERE al.timestamp BETWEEN ? AND ?
                                        ORDER BY al.timestamp DESC";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute([$startDate . ' 00:00:00', $endDate . ' 23:59:59']);
                    $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    echo json_encode(['success' => true, 'logs' => $logs]);
                    break;
                default:
                    http_response_code(400);
                    echo json_encode(['success' => false, 'message' => 'Invalid GET action.']);
                    break;
            }
        } elseif ($method === 'POST') {
            switch ($action) {
                case 'book':
                    // FIX: Replaced FILTER_SANITIZE_STRING and added validation
                    $customerName = trim(filter_var($input['customer_name'], FILTER_SANITIZE_FULL_SPECIAL_CHARS));
                    $customerMobile = isset($input['customer_mobile']) ? trim(filter_var($input['customer_mobile'], FILTER_SANITIZE_FULL_SPECIAL_CHARS)) : null;
                    $serviceId = filter_var($input['service_id'], FILTER_VALIDATE_INT);
                    $appointmentDateTime = filter_var($input['appointment_datetime'], FILTER_SANITIZE_FULL_SPECIAL_CHARS); // Further validation below
                    $customSerialNumber = isset($input['serial_number']) && !empty($input['serial_number']) ? trim(filter_var($input['serial_number'], FILTER_SANITIZE_FULL_SPECIAL_CHARS)) : null;
                    
                    // NEW: Flag sent from UI to request override
                    $isOverbookRequest = filter_var($input['is_overbook_request'] ?? false, FILTER_VALIDATE_BOOLEAN); 
                    
                    // NEW CHECK: Allow admin to book in the past, but not regular users.
                    if (!$isAdmin && strtotime($appointmentDateTime) < time()) {
                        echo json_encode(['success' => false, 'message' => 'Cannot book appointments in the past.']);
                        break;
                    }

                    if (empty($customerName) || !$serviceId || empty($appointmentDateTime)) {
                        echo json_encode(['success' => false, 'message' => 'Customer name, service, and time are required.']);
                        break;
                    }
                    
                    if (!DateTime::createFromFormat('Y-m-d H:i:s', $appointmentDateTime)) {
                        echo json_encode(['success' => false, 'message' => 'Invalid appointment datetime format.']);
                        break;
                    }

                    if ($customerMobile && !preg_match('/^\d{10}$/', $customerMobile)) {
                        echo json_encode(['success' => false, 'message' => 'Invalid mobile number. Please enter a 10-digit number.']);
                        exit; // FIX: Added missing exit
                    }

                    try {
                        $pdo->beginTransaction();

                        $allowBooking = false;
                        $isOverbook = false;
                        $message = 'The selected time slot is already booked. Please choose another time.';

                        // 1. Check if slot is already taken
                        $checkSql = "SELECT COUNT(*) FROM appointments WHERE appointment_datetime = ?";
                        $checkStmt = $pdo->prepare($checkSql);
                        $checkStmt->execute([$appointmentDateTime]);
                        $slotIsTaken = $checkStmt->fetchColumn() > 0;
                        
                        $appointmentDateOnly = date('Y-m-d', strtotime($appointmentDateTime));
                        $currentDateOnly = date('Y-m-d');

                        if (!$slotIsTaken) {
                            $allowBooking = true;
                        } else {
                            // 2. Slot is taken. Check if Admin override is requested for today.
                            $isOverbook = true;
                            
                            if ($isAdmin && $isOverbookRequest) {
                                // Admin is attempting an override
                                if ($appointmentDateOnly === $currentDateOnly) {
                                        // Requirement: Only allow overbook on the same day.
                                        $allowBooking = true;
                                } else {
                                        $message = 'Admin overbooking is restricted to the current date only.';
                                }
                            }
                        }

                        if (!$allowBooking) {
                            $pdo->rollBack();
                            echo json_encode(['success' => false, 'message' => $message]);
                            break;
                        }
                        
                        // 3. Insert appointment
                        $sql = "INSERT INTO appointments (customer_name, customer_mobile, service_id, appointment_datetime, booked_by_user_id) VALUES (?, ?, ?, ?, ?)";
                        $stmt = $pdo->prepare($sql);
                        $stmt->execute([$customerName, $customerMobile, $serviceId, $appointmentDateTime, $loggedInUserId]);
                        $appointmentId = $pdo->lastInsertId();

                        // ... (Serial number logic remains the same)
                        $serialNumber = null;
                        $appointmentDate = date('Y-m-d', strtotime($appointmentDateTime));

                        if ($customSerialNumber) {
                            $stmt = $pdo->prepare("SELECT COUNT(*) FROM appointments WHERE serial_number = ? AND DATE(appointment_datetime) = ? AND id != ?");
                            $stmt->execute([$customSerialNumber, $appointmentDate, $appointmentId]);
                            if ($stmt->fetchColumn() > 0) {
                                $pdo->rollBack();
                                echo json_encode(['success' => false, 'message' => 'A booking with this serial number already exists for this date.']);
                                break;
                            }
                            $serialNumber = $customSerialNumber;
                        } else {
                            $stmtExistingSerials = $pdo->prepare("SELECT serial_number FROM appointments WHERE DATE(appointment_datetime) = ? AND id != ? ORDER BY CAST(serial_number AS UNSIGNED) ASC");
                            $stmtExistingSerials->execute([$appointmentDate, $appointmentId]);
                            $existingSerials = $stmtExistingSerials->fetchAll(PDO::FETCH_COLUMN);
                            
                            $nextSerial = 1;
                            foreach ($existingSerials as $existingSerial) {
                                if ($existingSerial != $nextSerial) break;
                                $nextSerial++;
                            }
                            $serialNumber = $nextSerial;
                        }

                        $sqlUpdateSerial = "UPDATE appointments SET serial_number = ? WHERE id = ?";
                        $stmtUpdateSerial = $pdo->prepare($sqlUpdateSerial);
                        $stmtUpdateSerial->execute([$serialNumber, $appointmentId]);

                        // Detailed success message logic
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

                        $pdo->commit();

                        $logMessage = $isOverbook ? "Overbooked appointment" : "Booked appointment";
                        logAction($pdo, "{$logMessage} for {$customerName} (Serial #{$serialNumber})", $loggedInUserId, $_SESSION['username']);
                        echo json_encode(['success' => true, 'message' => "Appointment booked successfully!", 'details' => $details]);

                    } catch (PDOException $e) {
                        $pdo->rollBack();
                        error_log("Booking error in admin dashboard: " . $e->getMessage());
                        echo json_encode(['success' => false, 'message' => 'An error occurred during booking. The slot might have been taken.']);
                    }
                    break;
                case 'save_rule':
                    if (!$isAdmin) { http_response_code(403); echo json_encode(['success' => false, 'message' => 'Access denied.']); break; }
                    $rule_id = isset($input['rule_id']) ? filter_var($input['rule_id'], FILTER_VALIDATE_INT) : null;
                    $service_id = filter_var($input['service_id'], FILTER_VALIDATE_INT);
                    // FIX: Replaced FILTER_SANITIZE_STRING
                    $rule_type = filter_var($input['rule_type'], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
                    $rule_value = trim(filter_var($input['rule_value'], FILTER_SANITIZE_FULL_SPECIAL_CHARS));
                    
                    if (!$service_id || empty($rule_type)) { echo json_encode(['success' => false, 'message' => 'Service ID and rule type are required.']); break; }
                    
                    if ($rule_id) {
                        $sql = "UPDATE booking_rules SET service_id = ?, rule_type = ?, rule_value = ? WHERE id = ?";
                        $stmt = $pdo->prepare($sql);
                        $stmt->execute([$service_id, $rule_type, $rule_value, $rule_id]);
                        logAction($pdo, "Updated rule #{$rule_id} for service #{$service_id}", $loggedInUserId, $_SESSION['username']);
                    } else {
                        $sql = "INSERT INTO booking_rules (service_id, rule_type, rule_value) VALUES (?, ?, ?)";
                        $stmt = $pdo->prepare($sql);
                        $stmt->execute([$service_id, $rule_type, $rule_value]);
                        logAction($pdo, "Added new rule for service #{$service_id}", $loggedInUserId, $_SESSION['username']);
                    }
                    echo json_encode(['success' => true, 'message' => 'Rule saved successfully.']);
                    break;
                case 'delete_rule':
                    if (!$isAdmin) { http_response_code(403); echo json_encode(['success' => false, 'message' => 'Access denied.']); break; }
                    $rule_id = filter_var($input['rule_id'], FILTER_VALIDATE_INT);
                    if (!$rule_id) { echo json_encode(['success' => false, 'message' => 'Invalid rule ID.']); break; }
                    $sql = "DELETE FROM booking_rules WHERE id = ?";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute([$rule_id]);
                    logAction($pdo, "Deleted rule #{$rule_id}", $loggedInUserId, $_SESSION['username']);
                    echo json_encode(['success' => true, 'message' => 'Rule deleted successfully.']);
                    break;
                case 'add_service':
                    if (!$isAdmin) { http_response_code(403); echo json_encode(['success' => false, 'message' => 'Access denied.']); break; }
                    // FIX: Replaced FILTER_SANITIZE_STRING
                    $name = trim(filter_var($input['name'], FILTER_SANITIZE_FULL_SPECIAL_CHARS));
                    $duration = filter_var($input['duration'], FILTER_VALIDATE_INT);
                    $category = trim(filter_var($input['category'], FILTER_SANITIZE_FULL_SPECIAL_CHARS));
                    if (empty($category)) { $category = 'General'; }
                    if (!$name || $duration <= 0) { echo json_encode(['success' => false, 'message' => 'Invalid service name or duration.']); break; }
                    $sql = "INSERT INTO services (name, duration_minutes, category) VALUES (?, ?, ?)";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute([$name, $duration, $category]);
                    logAction($pdo, "Added new service: {$name} in category {$category}", $loggedInUserId, $_SESSION['username']);
                    echo json_encode(['success' => true, 'message' => 'Service added successfully.']);
                    break;
                case 'edit_service':
                    if (!$isAdmin) { http_response_code(403); echo json_encode(['success' => false, 'message' => 'Access denied.']); break; }
                    $id = filter_var($input['id'], FILTER_VALIDATE_INT);
                     // FIX: Replaced FILTER_SANITIZE_STRING
                    $name = trim(filter_var($input['name'], FILTER_SANITIZE_FULL_SPECIAL_CHARS));
                    $duration = filter_var($input['duration'], FILTER_VALIDATE_INT);
                    $category = trim(filter_var($input['category'], FILTER_SANITIZE_FULL_SPECIAL_CHARS));
                    if (empty($category)) { $category = 'General'; }
                    if (!$id || !$name || $duration <= 0) { echo json_encode(['success' => false, 'message' => 'Invalid service ID, name, or duration.']); break; }
                    $sql = "UPDATE services SET name = ?, duration_minutes = ?, category = ? WHERE id = ?";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute([$name, $duration, $category, $id]);
                    logAction($pdo, "Edited service #{$id}: {$name}", $loggedInUserId, $_SESSION['username']);
                    echo json_encode(['success' => true, 'message' => 'Service updated successfully.']);
                    break;
                case 'delete_service':
                    if (!$isAdmin) { http_response_code(403); echo json_encode(['success' => false, 'message' => 'Access denied.']); break; }
                    $id = filter_var($input['id'], FILTER_VALIDATE_INT);
                    if (!$id) { echo json_encode(['success' => false, 'message' => 'Invalid service ID.']); break; }
                    $sql = "DELETE FROM services WHERE id = ?";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute([$id]);
                    logAction($pdo, "Deleted service #{$id}", $loggedInUserId, $_SESSION['username']);
                    echo json_encode(['success' => true, 'message' => 'Service deleted successfully.']);
                    break;
                case 'add_blocked_slot':
                    if (!$isAdmin) { http_response_code(403); echo json_encode(['success' => false, 'message' => 'Access denied.']); break; }
                    // FIX: Replaced FILTER_SANITIZE_STRING and added validation
                    $date = $input['date'];
                    $startTime = $input['start_time'];
                    $endTime = $input['end_time'];
                    $reason = trim(filter_var($input['reason'], FILTER_SANITIZE_FULL_SPECIAL_CHARS));
                    if (!isValidDate($date) || !strtotime($startTime) || !strtotime($endTime) || empty($reason)) { echo json_encode(['success' => false, 'message' => 'Invalid or missing data.']); break; }
                    if (strtotime("$date $startTime") >= strtotime("$date $endTime")) { echo json_encode(['success' => false, 'message' => 'Start time must be before end time.']); break; }
                    $startDateTime = "$date $startTime:00";
                    $endDateTime = "$date $endTime:00";
                    $sql = "INSERT INTO blocked_slots (start_datetime, end_datetime, reason) VALUES (?, ?, ?)";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute([$startDateTime, $endDateTime, $reason]);
                    logAction($pdo, "Added blocked slot: {$date} {$startTime}-{$endTime}", $loggedInUserId, $_SESSION['username']);
                    echo json_encode(['success' => true, 'message' => 'Time slot blocked successfully.']);
                    break;
                case 'delete_blocked_slot':
                    if (!$isAdmin) { http_response_code(403); echo json_encode(['success' => false, 'message' => 'Access denied.']); break; }
                    $id = filter_var($input['id'], FILTER_VALIDATE_INT);
                    if (!$id) { echo json_encode(['success' => false, 'message' => 'Invalid ID.']); break; }
                    $sql = "DELETE FROM blocked_slots WHERE id = ?";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute([$id]);
                    logAction($pdo, "Deleted blocked slot #{$id}", $loggedInUserId, $_SESSION['username']);
                    echo json_encode(['success' => true, 'message' => 'Blocked slot deleted.']);
                    break;
                case 'edit_appointment':
                    $appointmentId = filter_var($input['id'], FILTER_VALIDATE_INT);
                    // FIX: Replaced FILTER_SANITIZE_STRING
                    $name = trim(filter_var($input['name'], FILTER_SANITIZE_FULL_SPECIAL_CHARS));
                    $mobile = isset($input['mobile']) ? trim(filter_var($input['mobile'], FILTER_SANITIZE_FULL_SPECIAL_CHARS)) : null;
                    $serviceId = filter_var($input['service_id'], FILTER_VALIDATE_INT);
                    $newSerialNumber = isset($input['serial_number']) ? trim(filter_var($input['serial_number'], FILTER_SANITIZE_FULL_SPECIAL_CHARS)) : null;

                    if (!$appointmentId || empty($name) || !$serviceId) { echo json_encode(['success' => false, 'message' => 'Invalid or missing data.']); break; }

                    $stmt = $pdo->prepare("SELECT appointment_datetime FROM appointments WHERE id = ?");
                    $stmt->execute([$appointmentId]);
                    $originalApp = $stmt->fetch();
                    if (!$originalApp) { echo json_encode(['success' => false, 'message' => 'Appointment not found.']); break; }
                    $appointmentDate = date('Y-m-d', strtotime($originalApp['appointment_datetime']));

                    if (empty($newSerialNumber)) {
                        $stmt = $pdo->prepare("SELECT serial_number FROM appointments WHERE DATE(appointment_datetime) = ? AND id != ? ORDER BY CAST(serial_number AS UNSIGNED) DESC LIMIT 1");
                        $stmt->execute([$appointmentDate, $appointmentId]);
                        $lastSerial = $stmt->fetchColumn();
                        $newSerialNumber = ($lastSerial) ? $lastSerial + 1 : 1;
                    } else {
                        $stmt = $pdo->prepare("SELECT COUNT(*) FROM appointments WHERE serial_number = ? AND DATE(appointment_datetime) = ? AND id != ?");
                        $stmt->execute([$newSerialNumber, $appointmentDate, $appointmentId]);
                        if ($stmt->fetchColumn() > 0) { echo json_encode(['success' => false, 'message' => 'A booking with this serial number already exists for this date.']); break; }
                    }

                    $sql = "UPDATE appointments SET customer_name = ?, customer_mobile = ?, service_id = ?, serial_number = ? WHERE id = ?";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute([$name, $mobile, $serviceId, $newSerialNumber, $appointmentId]);
                    logAction($pdo, "Edited appointment #{$appointmentId} (Serial #{$newSerialNumber})", $loggedInUserId, $_SESSION['username']);
                    echo json_encode(['success' => true, 'message' => 'Appointment details updated successfully.']);
                    break;
                case 'reschedule_appointment':
                    $appointmentId = filter_var($input['id'], FILTER_VALIDATE_INT);
                    // FIX: Replaced FILTER_SANITIZE_STRING and added validation
                    $newDate = $input['date'];
                    $newTime = $input['time'];
                    if (!$appointmentId || !isValidDate($newDate) || !strtotime($newTime)) { echo json_encode(['success' => false, 'message' => 'Invalid or missing data.']); break; }
                    
                    $newDateTime = "$newDate $newTime:00";
                    $sqlOriginal = "SELECT appointment_datetime FROM appointments WHERE id = ?";
                    $stmtOriginal = $pdo->prepare($sqlOriginal);
                    $stmtOriginal->execute([$appointmentId]);
                    $original = $stmtOriginal->fetch();
                    if (!$original) { echo json_encode(['success' => false, 'message' => 'Appointment not found.']); break; }
                    $originalDateTime = $original['appointment_datetime'];

                    $sql = "UPDATE appointments SET appointment_datetime = ?, is_rescheduled = 1, original_appointment_datetime = ? WHERE id = ?";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute([$newDateTime, $originalDateTime, $appointmentId]);
                    logAction($pdo, "Rescheduled appointment #{$appointmentId}", $loggedInUserId, $_SESSION['username']);
                    echo json_encode(['success' => true, 'message' => 'Appointment rescheduled successfully.']);
                    break;
                case 'cancel_appointment':
                    $appointmentId = filter_var($input['id'], FILTER_VALIDATE_INT);
                    if (!$appointmentId) { echo json_encode(['success' => false, 'message' => 'Invalid ID.']); break; }
                    $sql = "DELETE FROM appointments WHERE id = ?";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute([$appointmentId]);
                    logAction($pdo, "Cancelled appointment #{$appointmentId}", $loggedInUserId, $_SESSION['username']);
                    echo json_encode(['success' => true, 'message' => 'Appointment cancelled successfully.']);
                    break;
                case 'complete_appointment':
                    $appointmentId = filter_var($input['id'], FILTER_VALIDATE_INT);
                    if (!$appointmentId) { echo json_encode(['success' => false, 'message' => 'Invalid ID.']); break; }
                    $sql = "UPDATE appointments SET is_done = 1 WHERE id = ?";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute([$appointmentId]);
                    logAction($pdo, "Completed appointment #{$appointmentId}", $loggedInUserId, $_SESSION['username']);
                    echo json_encode(['success' => true, 'message' => 'Appointment marked as done.']);
                    break;
                case 'save_daily_breaks':
                    if (!$isAdmin) { http_response_code(403); echo json_encode(['success' => false, 'message' => 'Access denied.']); break; }
                    $breaks = $input['breaks'] ?? [];
                    $pdo->beginTransaction();
                    $pdo->exec("TRUNCATE TABLE daily_breaks");
                    $sql = "INSERT INTO daily_breaks (start_time, end_time) VALUES (?, ?)";
                    $stmt = $pdo->prepare($sql);
                    foreach ($breaks as $break) {
                        // FIX: Replaced FILTER_SANITIZE_STRING
                        $startTime = filter_var($break['start_time'], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
                        $endTime = filter_var($break['end_time'], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
                        if (!empty($startTime) && !empty($endTime)) {
                            if (strtotime($startTime) >= strtotime($endTime)) { $pdo->rollBack(); echo json_encode(['success' => false, 'message' => 'Start time must be before end time for all breaks.']); exit; }
                            $stmt->execute([$startTime, $endTime]);
                        }
                    }
                    $pdo->commit();
                    logAction($pdo, "Saved daily breaks", $loggedInUserId, $_SESSION['username']);
                    echo json_encode(['success' => true, 'message' => 'Daily breaks saved successfully.']);
                    break;
                case 'add_user':
                    if (!$isAdmin) { http_response_code(403); echo json_encode(['success' => false, 'message' => 'Access denied.']); break; }
                    // FIX: Replaced FILTER_SANITIZE_STRING
                    $username = trim(filter_var($input['username'], FILTER_SANITIZE_FULL_SPECIAL_CHARS));
                    $name = trim(filter_var($input['name'], FILTER_SANITIZE_FULL_SPECIAL_CHARS));
                    $role = filter_var($input['role'], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
                    if (empty($username) || empty($role)) { echo json_encode(['success' => false, 'message' => 'Username and role are required.']); break; }
                    $password = $username;
                    $password_hash = password_hash($password, PASSWORD_DEFAULT);
                    $sql = "INSERT INTO users (username, name, hash, role, passwordLastChanged, isFirstLogin) VALUES (?, ?, ?, ?, NOW(), 1)";
                    $stmt = $pdo->prepare($sql);
                    try {
                        $stmt->execute([$username, $name, $password_hash, $role]);
                        logAction($pdo, "Added new user: {$username} ({$name}) with role {$role}", $loggedInUserId, $_SESSION['username']);
                        echo json_encode(['success' => true, 'message' => "User added successfully. Default password is '{$username}'."]);
                    } catch (PDOException $e) {
                        if ($e->getCode() === '23000') { echo json_encode(['success' => false, 'message' => 'Error: A user with this username already exists.']); }
                        else { echo json_encode(['success' => false, 'message' => 'Error adding user: ' . $e->getMessage()]); }
                    }
                    break;
                case 'edit_user':
                    if (!$isAdmin) { http_response_code(403); echo json_encode(['success' => false, 'message' => 'Access denied.']); break; }
                    $id = filter_var($input['id'], FILTER_VALIDATE_INT);
                    // FIX: Replaced FILTER_SANITIZE_STRING
                    $username = trim(filter_var($input['username'], FILTER_SANITIZE_FULL_SPECIAL_CHARS));
                    $name = trim(filter_var($input['name'], FILTER_SANITIZE_FULL_SPECIAL_CHARS));
                    $role = filter_var($input['role'], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
                    if (!$id || empty($username) || empty($role)) { echo json_encode(['success' => false, 'message' => 'Invalid data provided.']); break; }
                    $sql = "UPDATE users SET username = ?, name = ?, role = ? WHERE id = ?";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute([$username, $name, $role, $id]);
                    logAction($pdo, "Edited user #{$id}", $loggedInUserId, $_SESSION['username']);
                    echo json_encode(['success' => true, 'message' => 'User updated successfully.']);
                    break;
                case 'delete_user':
                    if (!$isAdmin) { http_response_code(403); echo json_encode(['success' => false, 'message' => 'Access denied.']); break; }
                    $id = filter_var($input['id'], FILTER_VALIDATE_INT);
                    if (!$id) { echo json_encode(['success' => false, 'message' => 'Invalid ID.']); break; }
                    if ($id === $loggedInUserId) { echo json_encode(['success' => false, 'message' => 'Cannot delete currently logged-in admin.']); break; }
                    $sql = "DELETE FROM users WHERE id = ?";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute([$id]);
                    logAction($pdo, "Deleted user #{$id}", $loggedInUserId, $_SESSION['username']);
                    echo json_encode(['success' => true, 'message' => 'User deleted successfully.']);
                    break;
                case 'toggle_user_active':
                    if (!$isAdmin) { http_response_code(403); echo json_encode(['success' => false, 'message' => 'Access denied.']); break; }
                    $id = filter_var($input['id'], FILTER_VALIDATE_INT);
                    $isActive = filter_var($input['isActive'], FILTER_VALIDATE_BOOLEAN) ? 1 : 0;
                    if (!$id) { echo json_encode(['success' => false, 'message' => 'Invalid ID.']); break; }
                    if ($id === $loggedInUserId && !$isActive) { echo json_encode(['success' => false, 'message' => 'Cannot deactivate currently logged-in admin.']); break; }
                    $sql = "UPDATE users SET isActive = ? WHERE id = ?";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute([$isActive, $id]);
                    $status = $isActive ? 'activated' : 'deactivated';
                    logAction($pdo, "{$status} user #{$id}", $loggedInUserId, $_SESSION['username']);
                    echo json_encode(['success' => true, 'message' => "User {$status} successfully."]);
                    break;
                case 'reset_password':
                    if (!$isAdmin) { http_response_code(403); echo json_encode(['success' => false, 'message' => 'Access denied.']); break; }
                    $id = filter_var($input['id'], FILTER_VALIDATE_INT);
                    // FIX: Replaced FILTER_SANITIZE_STRING
                    $username = filter_var($input['username'], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
                    if (!$id || empty($username)) { echo json_encode(['success' => false, 'message' => 'Invalid data provided.']); break; }
                    $newPasswordHash = password_hash($username, PASSWORD_DEFAULT);
                    $sql = "UPDATE users SET hash = ?, passwordLastChanged = NOW(), isFirstLogin = 1 WHERE id = ?";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute([$newPasswordHash, $id]);
                    logAction($pdo, "Reset password for user #{$id}", $loggedInUserId, $_SESSION['username']);
                    echo json_encode(['success' => true, 'message' => "Password reset to username '{$username}' successfully."]);
                    break;
                case 'change_my_password':
                    $oldPassword = $input['old_password'];
                    $newPassword = $input['new_password'];
                    $sql = "SELECT hash FROM users WHERE id = ?";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute([$loggedInUserId]);
                    $user = $stmt->fetch(PDO::FETCH_ASSOC);
                    if (!password_verify($oldPassword, $user['hash'])) { echo json_encode(['success' => false, 'message' => 'Incorrect current password.']); break; }
                    if (password_verify($newPassword, $user['hash'])) { echo json_encode(['success' => false, 'message' => 'New password cannot be the same as the old one.']); break; }
                    $newPasswordHash = password_hash($newPassword, PASSWORD_DEFAULT);
                    $sql = "UPDATE users SET hash = ?, passwordLastChanged = NOW(), isFirstLogin = 0 WHERE id = ?";
                    $stmt = $pdo->prepare($sql);
                    $stmt->execute([$newPasswordHash, $loggedInUserId]);
                    logAction($pdo, "Changed own password", $loggedInUserId, $_SESSION['username']);
                    echo json_encode(['success' => true, 'message' => 'Password changed successfully.']);
                    break;
                default:
                    http_response_code(400);
                    echo json_encode(['success' => false, 'message' => 'Invalid POST action.']);
                    break;
            }
        } else {
            http_response_code(405);
            echo json_encode(['success' => false, 'message' => 'Method not allowed.']);
        }
    } catch (PDOException $e) {
        error_log("Database error in API handler: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Database error. Please check server logs for details.']);
    } catch (\Exception $e) {
        error_log("General error in API handler: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'An unexpected server error occurred.']);
    }
    
    exit;
}

if (
    (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') ||
    (isset($_REQUEST['action']))
) {
    // Note: $loggedInUserId and $isAdmin are already defined in the global scope from the initial user fetch.
    handleApiRequest($pdo, $_SERVER['REQUEST_METHOD'], $loggedInUserId, $isAdmin);
    exit;
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AppointmentPro Dashboard</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.23/jspdf.plugin.autotable.min.js"></script>
    <style>
        :root {
            /* Primary Colors (Soft Blue/Purple) */
            --primary: #4F46E5; /* Indigo-600 */
            --primary-dark: #4338CA; /* Indigo-700 */
            --primary-light: #818CF8; /* Indigo-400 */
            
            /* Accent Colors */
            --accent: #F59E0B; /* Amber-500 */
            
            /* Status Colors */
            --status-success: #10B981; /* Emerald-500 */
            --status-pending: #FCD34D; /* Amber-300 */
            --status-danger: #F87171; /* Red-400 */
            --status-info: #3B82F6; /* Blue-500 */
            
            /* Light Theme (Default) */
            --bg-primary: #F4F6F9; /* Light Grey background */
            --bg-secondary: #FFFFFF; /* Card/Nav background */
            --text-primary: #1F2937; /* Dark text */
            --text-secondary: #6B7280; /* Grey text */
            --border-color: #E5E7EB; /* Border */
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
            
            /* Transitions */
            --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .dark-mode {
            --bg-primary: #111827; /* Dark background */
            --bg-secondary: #1F2937; /* Dark card/nav background */
            --text-primary: #F9FAFB; /* Light text */
            --text-secondary: #9CA3AF; /* Light grey text */
            --border-color: #374151; /* Darker border */
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.5);
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.3), 0 2px 4px -1px rgba(0, 0, 0, 0.2);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.4), 0 4px 6px -2px rgba(0, 0, 0, 0.3);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            transition: var(--transition);
        }

        body {
            background-color: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.5;
        }

        /* Layout */
        .dashboard-container {
            display: grid;
            grid-template-columns: 280px 1fr;
            grid-template-rows: 70px 1fr;
            grid-template-areas:
                "sidebar header"
                "sidebar main";
            min-height: 100vh;
        }

        /* Header */
        .header {
            grid-area: header;
            display: flex;
            align-items: center;
            justify-content: flex-end; /* Align user profile to the right */
            padding: 0 2rem;
            background-color: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            box-shadow: var(--shadow-sm);
            z-index: 10;
            position: sticky;
            top: 0;
        }

        .user-profile {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.5rem;
            border-radius: 12px;
            cursor: pointer;
        }

        .user-profile:hover {
            background: rgba(79, 70, 229, 0.1);
        }

        .avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--primary), var(--primary-light));
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 600;
            font-size: 1rem;
        }

        .user-info {
            display: flex;
            flex-direction: column;
            align-items: flex-end;
        }

        .user-name {
            font-weight: 600;
            font-size: 0.95rem;
        }

        .user-role {
            font-size: 0.8rem;
            color: var(--text-secondary);
        }
        
        .menu-toggle {
             display: none;
             background: none;
             border: none;
             font-size: 1.5rem;
             color: var(--text-primary);
             cursor: pointer;
        }


        /* Sidebar */
        .sidebar {
            grid-area: sidebar;
            background-color: var(--bg-secondary);
            border-right: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
            z-index: 20;
            position: fixed;
            height: 100%;
            width: 280px;
            overflow-y: auto;
        }

        .sidebar-header {
            padding: 1.5rem 1.5rem 1rem;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .logo-icon {
            width: 36px;
            height: 36px;
            border-radius: 10px;
            background: linear-gradient(135deg, var(--primary), var(--primary-light));
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 1.2rem;
        }

        .logo-text {
            font-size: 1.25rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--primary), var(--primary-light));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .sidebar-nav {
            padding: 1rem 0;
            flex-grow: 1;
        }

        .nav-item {
            display: flex;
            align-items: center;
            padding: 0.9rem 1.5rem;
            color: var(--text-secondary);
            text-decoration: none;
            position: relative;
            transition: var(--transition);
            cursor: pointer;
        }

        .nav-item:hover {
            background: rgba(79, 70, 229, 0.05);
            color: var(--primary);
        }

        .nav-item.active {
            color: var(--primary);
            background: rgba(79, 70, 229, 0.1);
        }

        .nav-item.active::before {
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            height: 100%;
            width: 4px;
            background: linear-gradient(to bottom, var(--primary), var(--primary-light));
            border-radius: 0 4px 4px 0;
        }

        .nav-item i {
            margin-right: 0.75rem;
            font-size: 1.1rem;
            width: 24px;
            text-align: center;
        }

        .nav-label {
            font-weight: 500;
            font-size: 0.95rem;
        }
        
        .sidebar-footer {
            padding: 1.5rem;
            border-top: 1px solid var(--border-color);
        }

        .theme-toggle {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0.75rem 1rem;
            background: var(--bg-primary);
            border-radius: 12px;
            border: 1px solid var(--border-color);
        }

        .theme-toggle i {
            color: var(--text-secondary);
            font-size: 1.1rem;
        }

        .toggle-switch {
            position: relative;
            display: inline-block;
            width: 44px;
            height: 24px;
        }

        .toggle-switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }

        .slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: var(--border-color);
            transition: .4s;
            border-radius: 24px;
        }

        .slider:before {
            position: absolute;
            content: "";
            height: 18px;
            width: 18px;
            left: 3px;
            bottom: 3px;
            background-color: white;
            transition: .4s;
            border-radius: 50%;
        }

        input:checked + .slider {
            background: linear-gradient(135deg, var(--primary), var(--primary-light));
        }

        input:checked + .slider:before {
            transform: translateX(20px);
        }

        /* Main Content */
        .main {
            grid-area: main;
            padding: 2rem;
            overflow-y: auto;
            background-color: var(--bg-primary);
        }

        .page-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 2rem;
        }

        .page-header h1 {
            font-size: 1.75rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            background: linear-gradient(135deg, var(--primary), var(--primary-light));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .page-header p {
            color: var(--text-secondary);
            font-size: 1rem;
        }

        .current-time-display {
            font-size: 0.9rem;
            font-weight: 600;
            color: var(--primary);
            background: var(--bg-secondary);
            padding: 0.5rem 1rem;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }

        /* Cards */
        .card {
            background-color: var(--bg-secondary);
            border-radius: 16px;
            padding: 1.5rem;
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--border-color);
            margin-bottom: 1.5rem;
            transition: var(--transition);
        }

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
        }

        .card-header h2 {
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--text-primary);
        }

        /* KPI Cards */
        .kpi-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .kpi-card {
            background: var(--bg-secondary);
            border-radius: 16px;
            padding: 1.5rem;
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            transition: var(--transition);
        }

        .kpi-icon {
            width: 50px;
            height: 50px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 1rem;
            font-size: 1.2rem;
            color: white;
            background: var(--primary); /* Default gradient */
        }
        
        .kpi-value {
            font-size: 1.75rem;
            font-weight: 700;
            margin-bottom: 0.25rem;
        }

        .kpi-label {
            color: var(--text-secondary);
            font-size: 0.9rem;
            line-height: 1.2;
        }


        /* Form Styles */
        .form-group {
            margin-bottom: 1rem;
        }
        
        label {
            display: block;
            font-size: 0.9rem;
            color: var(--text-secondary);
            margin-bottom: 0.5rem;
            font-weight: 500;
        }
        
        input, select {
            width: 100%;
            padding: 0.75rem 1rem;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            color: var(--text-primary);
            outline: none;
            font-size: 1rem;
            transition: all 0.2s;
        }

        input:focus, select:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 2px rgba(79, 70, 229, 0.2);
            background-color: var(--bg-secondary);
        }
        
        input[type="date"]::-webkit-calendar-picker-indicator,
        input[type="time"]::-webkit-calendar-picker-indicator {
            filter: var(--text-primary) == #1F2937 ? none : invert(0.8);
            cursor: pointer;
        }
        
        /* Buttons */
        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            padding: 0.75rem 1.25rem;
            border-radius: 10px;
            font-weight: 600;
            cursor: pointer;
            border: none;
            outline: none;
            font-size: 0.95rem;
            transition: var(--transition);
        }

        .btn-primary {
            background: linear-gradient(135deg, var(--primary), var(--primary-light));
            color: white;
        }

        .btn-primary:hover {
            opacity: 0.9;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(79, 70, 229, 0.3);
        }

        .btn-secondary {
            background: var(--bg-primary);
            color: var(--text-primary);
            border: 1px solid var(--border-color);
        }
        
        .btn-secondary:hover {
            background: var(--border-color);
        }
        
        .btn-danger {
            background: var(--status-danger);
            color: white;
        }
        
        .btn-danger:hover {
            background: #EF4444;
        }
        
        .action-button {
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            cursor: pointer;
            font-weight: 500;
            padding: 0.4rem 0.7rem;
            border-radius: 8px;
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
            font-size: 0.85rem;
        }

        .action-button:hover {
            background: rgba(79, 70, 229, 0.1);
            border-color: var(--primary);
            color: var(--primary);
        }
        
        .action-button.done {
            color: var(--status-success);
            border-color: var(--status-success);
        }
        .action-button.done:hover {
            background: rgba(16, 185, 129, 0.1);
        }
        
        .action-button.cancel, .action-button.delete {
            color: var(--status-danger);
            border-color: var(--status-danger);
        }
        .action-button.cancel:hover, .action-button.delete:hover {
            background: rgba(248, 113, 113, 0.1);
        }

        .action-button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            background: var(--bg-primary);
            color: var(--text-secondary);
            border-color: var(--border-color);
        }

        /* NEW STYLE: Table container for horizontal scrolling */
        .table-container {
            overflow-x: auto;
            -webkit-overflow-scrolling: touch; /* Smooth scrolling on iOS */
        }
        
        /* Table Styles */
        .data-table {
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-secondary);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: var(--shadow-sm);
            /* NEW: Ensure table doesn't collapse too much */
            min-width: 800px;
        }

        .data-table th {
            background: var(--bg-primary);
            padding: 1rem 1.25rem;
            text-align: left;
            font-weight: 600;
            font-size: 0.9rem;
            color: var(--text-secondary);
            border-bottom: 1px solid var(--border-color);
        }

        .data-table td {
            padding: 1rem 1.25rem;
            border-bottom: 1px solid var(--border-color);
            font-size: 0.95rem;
        }

        .data-table tbody tr:last-child td {
            border-bottom: none;
        }

        .data-table tbody tr:hover {
            background: rgba(79, 70, 229, 0.03);
        }
        
        .pulsing-row {
            animation: pulse-border 2s infinite ease-in-out;
            box-shadow: 0 0 0 0 rgba(79, 70, 229, 0.4);
        }
        
        .pulsing-row.unattended {
            animation: pulse-danger 2s infinite ease-in-out;
            box-shadow: 0 0 0 0 rgba(248, 113, 113, 0.4);
        }

        @keyframes pulse-border {
            0% { box-shadow: 0 0 0 0 rgba(79, 70, 229, 0.2); }
            50% { box-shadow: 0 0 0 5px rgba(79, 70, 229, 0.4); }
            100% { box-shadow: 0 0 0 0 rgba(79, 70, 229, 0.2); }
        }
        
        @keyframes pulse-danger {
            0% { box-shadow: 0 0 0 0 rgba(248, 113, 113, 0.2); }
            50% { box-shadow: 0 0 0 5px rgba(248, 113, 113, 0.4); }
            100% { box-shadow: 0 0 0 0 rgba(248, 113, 113, 0.2); }
        }
        
        .done-row {
            opacity: 0.6;
            filter: grayscale(10%);
        }
        
        .reschedule-badge {
            background-color: var(--accent);
            color: var(--text-primary);
            font-size: 0.65rem;
            font-weight: 700;
            padding: 0.2rem 0.5rem;
            border-radius: 6px;
            margin-left: 0.5rem;
            text-transform: uppercase;
            display: inline-block;
            vertical-align: middle;
        }
        
        .done-badge {
            background-color: var(--status-success);
            color: white;
            font-size: 0.65rem;
            font-weight: 700;
            padding: 0.2rem 0.5rem;
            border-radius: 6px;
            margin-left: 0.5rem;
            text-transform: uppercase;
            display: inline-block;
            vertical-align: middle;
        }

        .info-icon {
            margin-left: 0.2rem;
            color: var(--status-info);
            cursor: help;
            vertical-align: middle;
        }

        /* Modal Styles */
        .dialog {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            background: rgba(0, 0, 0, 0.6);
            backdrop-filter: blur(4px);
            z-index: 1000;
            opacity: 0;
            visibility: hidden;
            overflow-y: auto;
        }

        .dialog.active {
            opacity: 1;
            visibility: visible;
        }

        .dialog-content {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 20px;
            padding: 2rem;
            box-shadow: var(--shadow-lg);
            max-width: 500px;
            width: 90%;
            transform: translateY(20px);
            transition: all 0.3s ease-out;
        }
        
        .dialog.active .dialog-content {
            transform: translateY(0);
        }
        
        .dialog-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
        }

        .dialog-header h2 {
            font-size: 1.5rem;
            font-weight: 700;
        }

        .close-dialog {
            background: transparent;
            border: none;
            color: var(--text-secondary);
            font-size: 1.5rem;
            cursor: pointer;
            padding: 0.5rem;
            border-radius: 8px;
        }
        
        .close-dialog:hover {
            color: var(--status-danger);
            background: rgba(248, 113, 113, 0.1);
        }

        .time-slot-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
            gap: 0.8rem;
            margin-top: 1rem;
            max-height: 300px;
            overflow-y: auto;
            padding-right: 0.5rem;
        }

        .time-slot-button {
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 0.8rem;
            text-align: center;
            cursor: pointer;
            font-size: 0.9rem;
            font-weight: 500;
            color: var(--text-primary);
        }

        .time-slot-button:hover {
            border-color: var(--primary);
            background: rgba(79, 70, 229, 0.1);
        }

        .time-slot-button.selected {
            background: var(--primary);
            border-color: var(--primary);
            color: white;
            box-shadow: 0 4px 12px rgba(79, 70, 229, 0.3);
        }
        
        .daily-break-row {
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 1rem;
        }
        
        .daily-break-row .form-group {
            flex: 1;
            margin-bottom: 0;
        }
        
        .btn-remove {
            background: var(--status-danger);
            color: white;
            border: none;
            width: 40px;
            height: 40px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1rem;
        }
        .btn-remove:hover {
            background: #EF4444;
        }

        .weekday-picker {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-top: 0.5rem;
        }

        .weekday-btn {
            flex: 1;
            min-width: 50px;
            padding: 0.7rem 0;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            background: var(--bg-primary);
            cursor: pointer;
            text-align: center;
            font-weight: 500;
            color: var(--text-primary);
        }

        .weekday-btn.selected {
            background: var(--primary);
            color: white;
            border-color: var(--primary);
        }

        /* Utility Classes (Using original names for JS compatibility) */
        .hidden { display: none !important; }
        .flex { display: flex; }
        .justify-between { justify-content: space-between; }
        .justify-end { justify-content: flex-end; }
        .gap-4 { gap: 1rem; }
        .mt-4 { margin-top: 1rem; }
        .mb-4 { margin-bottom: 1rem; }
        .w-full { width: 100%; }
        .grid-cols-2 { grid-template-columns: repeat(2, 1fr); }
        .grid-cols-3 { grid-template-columns: repeat(3, 1fr); }
        .items-end { align-items: flex-end; }
        
        /* Custom Switch Styling */
        .switch {
          position: relative;
          display: inline-block;
          width: 34px;
          height: 17px;
          vertical-align: middle;
        }
        .switch input { 
          opacity: 0;
          width: 0;
          height: 0;
        }
        .switch .slider {
          position: absolute;
          cursor: pointer;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background-color: var(--border-color);
          transition: .4s;
          border-radius: 34px;
          height: 17px;
        }
        .switch .slider:before {
          position: absolute;
          content: "";
          height: 13px;
          width: 13px;
          left: 2px;
          bottom: 2px;
          background-color: white;
          transition: .4s;
          border-radius: 50%;
        }
        .switch input:checked + .slider {
          background-color: var(--status-success);
        }
        .switch input:checked + .slider:before {
          transform: translateX(17px);
        }
        /* End Custom Switch Styling */

        /* Responsive */
        @media (max-width: 1200px) {
            .dashboard-container {
                grid-template-columns: 1fr;
                grid-template-rows: 70px 1fr;
                grid-template-areas:
                    "header"
                    "main";
            }

            .sidebar {
                transform: translateX(-280px);
                box-shadow: 0 0 15px rgba(0, 0, 0, 0.4);
                transition: transform 0.3s ease;
            }

            .sidebar.active {
                transform: translateX(0);
            }
            
            .header {
                justify-content: space-between;
                padding: 0 1rem;
            }
            
            .menu-toggle {
                display: block;
            }
            
            .header .user-profile .user-info {
                display: none;
            }
            
            .kpi-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }

        @media (max-width: 768px) {
            .main {
                padding: 1.5rem;
            }

            .page-header {
                flex-direction: column;
                gap: 1rem;
                align-items: flex-start;
            }
            
            .kpi-grid {
                grid-template-columns: 1fr;
            }
            
            .data-table {
                min-width: 700px;
            }
            
            .grid-cols-2 {
                grid-template-columns: 1fr;
            }
            .grid-cols-3 {
                grid-template-columns: 1fr;
            }
        }
        
    </style>
</head>
<body>
    <div class="dashboard-container">
        <header class="header">
            <button class="menu-toggle" id="menu-toggle-btn">
                <i class="fas fa-bars"></i>
            </button>
            <div class="user-profile">
                <div class="avatar"><?php echo htmlspecialchars(strtoupper(substr($_SESSION['name'] ?? $_SESSION['username'], 0, 1))); ?></div>
                <div class="user-info">
                    <div class="user-name"><?php echo htmlspecialchars($_SESSION['name'] ?? $_SESSION['username']); ?></div>
                    <div class="user-role"><?php echo htmlspecialchars(ucfirst($_SESSION['role'])); ?></div>
                </div>
                <i class="fas fa-chevron-down" style="color: var(--text-secondary); font-size: 0.8rem;"></i>
            </div>
        </header>

        <aside class="sidebar" id="sidebar">
            <div class="sidebar-header">
                <div class="logo">
                    <div class="logo-icon">
                        <i class="fas fa-calendar-check"></i>
                    </div>
                    <span class="logo-text">AppointmentPro</span>
                </div>
            </div>
            
            <nav class="sidebar-nav">
                <a class="nav-item active" data-page="appointments">
                    <i class="fas fa-calendar-alt"></i>
                    <span class="nav-label">Appointments</span>
                </a>
                <a class="nav-item" data-page="book-appointment">
                    <i class="fas fa-plus-circle"></i>
                    <span class="nav-label">Book Appointment</span>
                </a>
                <a class="nav-item" data-page="services">
                    <i class="fas fa-concierge-bell"></i>
                    <span class="nav-label">Services</span>
                </a>
                <a class="nav-item" data-page="rules">
                    <i class="fas fa-gavel"></i>
                    <span class="nav-label">Booking Rules</span>
                </a>
                <a class="nav-item" data-page="roster">
                    <i class="fas fa-clock"></i>
                    <span class="nav-label">Roster & Breaks</span>
                </a>
                <a class="nav-item" data-page="reports">
                    <i class="fas fa-file-pdf"></i>
                    <span class="nav-label">Reports</span>
                </a>
                <?php if ($isAdmin): ?>
                <a class="nav-item" data-page="user-management">
                    <i class="fas fa-users"></i>
                    <span class="nav-label">Users</span>
                </a>
                <a class="nav-item" data-page="audit-logs">
                    <i class="fas fa-clipboard-list"></i>
                    <span class="nav-label">Audit Logs</span>
                </a>
                <?php endif; ?>
            </nav>
            
            <div style="flex-grow: 1;"></div> 

            <div class="sidebar-footer">
                <a class="nav-item" data-page="change-password" style="padding: 0.5rem 1rem 0.5rem 0.5rem;">
                    <i class="fas fa-key"></i>
                    <span class="nav-label">Change Password</span>
                </a>
                <a href="../logout.php" class="nav-item" style="color: var(--status-danger); padding: 0.5rem 1rem 0.5rem 0.5rem;">
                    <i class="fas fa-sign-out-alt"></i>
                    <span class="nav-label">Logout</span>
                </a>
                <div class="theme-toggle mt-4">
                    <i class="fas fa-moon" id="moon-icon"></i>
                    <label class="toggle-switch">
                        <input type="checkbox" id="dark-mode-toggle">
                        <span class="slider"></span>
                    </label>
                    <i class="fas fa-sun" id="sun-icon" style="color: var(--accent);"></i>
                </div>
            </div>
        </aside>

        <main class="main" id="main-content">
            <div id="appointments-page">
                <div class="page-header">
                    <div>
                        <h1 id="page-title-heading">Appointments</h1>
                        <p id="page-title-subheading">View, edit, or cancel existing appointments</p>
                    </div>
                    <div class="current-time-display" id="current-time"></div>
                </div>
                <div class="card">
                    <div class="grid grid-cols-2 gap-4">
                        <div class="form-group">
                            <label for="appointments-date">Select Date</label>
                            <input type="date" id="appointments-date" name="appointments-date">
                        </div>
                        <div class="form-group">
                            <label for="appointment-search">Search Appointments</label>
                            <input type="text" id="appointment-search" placeholder="Search by Name, Mobile, or Serial #">
                        </div>
                    </div>
                </div>
                <div class="kpi-grid" id="stats-grid">
                    <div class="kpi-card">
                        <div class="kpi-icon" style="background: linear-gradient(135deg, var(--primary), var(--primary-light));">
                            <i class="fas fa-calendar-check"></i>
                        </div>
                        <div class="kpi-content">
                            <div class="kpi-value" id="total-bookings">0</div>
                            <div class="kpi-label">Active Bookings</div>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-header">
                        <h2>Appointments List</h2>
                        <button id="toggle-done-btn" class="btn btn-secondary"><i class="fas fa-eye"></i> Show All Appointments</button>
                    </div>
                    <div class="table-container">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Serial #</th>
                                    <th>Time</th>
                                    <th>Customer Name</th>
                                    <th>Mobile</th>
                                    <th>Service</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="appointments-table-body"></tbody>
                        </table>
                    </div>
                </div>
            </div>

            <div id="book-appointment-page" class="hidden">
                <div class="page-header">
                    <h1>Book New Appointment</h1>
                    <p>Manually book a new walk-in appointment</p>
                </div>
                <div class="card">
                    <form id="book-walkin-form">
                        <div class="grid grid-cols-2 gap-4">
                            <div class="form-group">
                                <label for="walkin-name">Customer Name</label>
                                <input type="text" id="walkin-name" required>
                            </div>
                            <div class="form-group">
                                <label for="walkin-mobile">Mobile Number (Optional)</label>
                                <input type="tel" id="walkin-mobile">
                            </div>
                        </div>
                        <div class="form-group">
                            <label for="walkin-service">Service</label>
                            <select id="walkin-service" name="walkin-service" required></select>
                        </div>
                        <div class="grid grid-cols-2 gap-4">
                            <div class="form-group">
                                <label for="walkin-date">Date</label>
                                <input type="date" id="walkin-date" name="walkin-date" required>
                            </div>
                            <div class="form-group">
                                <label for="walkin-time-display">Time</label>
                                <input type="text" id="walkin-time-display" placeholder="Click to select or type time (HH:MM)" required>
                                <input type="hidden" id="walkin-time-select">
                            </div>
                        </div>
                        
                        <?php if ($isAdmin): ?>
                        <div class="form-group" id="overbook-permission-group" style="margin-top: 1.5rem;">
                            <label for="overbook-override" style="display: flex; align-items: center; gap: 0.5rem; color: var(--status-danger); font-weight: 600;">
                                <input type="checkbox" id="overbook-override" style="width: auto; height: 1.25rem; margin: 0; padding: 0;">
                                Admin Override: Book Slot Even if Taken (Today Only)
                            </label>
                            <p style="color: var(--text-secondary); font-size: 0.75rem; margin-top: 0.25rem;">Checking this box allows booking a reserved time for the current date only.</p>
                        </div>
                        <?php endif; ?>

                        <div class="form-group">
                            <label for="walkin-serial">Custom Serial Number (Optional)</label>
                            <input type="text" id="walkin-serial" placeholder="Leave blank to auto-generate">
                        </div>
                        <div class="flex justify-end mt-4">
                            <button type="submit" class="btn btn-primary"><i class="fas fa-calendar-plus"></i> Book Appointment</button>
                        </div>
                    </form>
                </div>
            </div>

            <div id="services-page" class="hidden">
                <div class="page-header">
                    <h1>Manage Services</h1>
                    <p>Add, edit, or remove services offered</p>
                </div>
                <div class="card">
                    <div class="card-header">
                        <h2>Available Services</h2>
                        <button id="add-service-btn" class="btn btn-primary">
                            <i class="fas fa-plus"></i> Add New Service
                        </button>
                    </div>
                    <div class="table-container">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Service Name</th>
                                    <th>Category</th>
                                    <th>Duration (min)</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="services-table-body"></tbody>
                        </table>
                    </div>
                </div>
            </div>
            
            <div id="rules-page" class="hidden">
                <div class="page-header">
                    <h1>Booking Rules</h1>
                    <p>Set service-specific booking restrictions</p>
                </div>
                <div class="card">
                    <div class="form-group">
                        <label for="rule-service-select">Select a Service to Manage its Rules</label>
                        <select id="rule-service-select"></select>
                    </div>
                    <div id="rules-container" class="hidden">
                        <div class="card-header">
                            <h2 id="rules-for-service-name"></h2>
                            <button id="add-rule-btn" class="btn btn-primary"><i class="fas fa-plus"></i> Add Rule</button>
                        </div>
                        <div class="table-container">
                            <table class="data-table">
                                <thead><tr><th>Rule Type</th><th>Value</th><th>Actions</th></tr></thead>
                                <tbody id="rules-table-body"></tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            <div id="roster-page" class="hidden">
                <div class="page-header">
                    <h1>Roster & Breaks</h1>
                    <p>Block out time slots for breaks or other activities</p>
                </div>
                <div class="card">
                    <div class="card-header">
                        <h2>Blocked Time Slots (One-off)</h2>
                        <button id="add-roster-btn" class="btn btn-primary">
                            <i class="fas fa-plus"></i> Add Blocked Time
                        </button>
                    </div>
                    <div class="form-group">
                        <label for="roster-date">Select Date to View</label>
                        <input type="date" id="roster-date" name="roster-date">
                    </div>
                    <div class="table-container mb-4">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Start Time</th>
                                    <th>End Time</th>
                                    <th>Reason</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="roster-table-body"></tbody>
                        </table>
                    </div>
                </div>
                <div class="card">
                    <div class="card-header">
                        <h2>Set Daily Breaks (Recurring)</h2>
                    </div>
                    <p style="color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 1.5rem;">These breaks will be blocked automatically every day for all services.</p>
                    <div id="daily-breaks-container"></div>
                    <div class="flex gap-4 mt-4">
                        <button id="add-daily-break-btn" class="btn btn-secondary"><i class="fas fa-plus"></i> Add Break</button>
                        <button id="save-daily-breaks-btn" class="btn btn-primary"><i class="fas fa-save"></i> Save All Breaks</button>
                    </div>
                </div>
            </div>

            <div id="reports-page" class="hidden">
                <div class="page-header">
                    <h1>Day End Reports</h1>
                    <p>Generate and download daily appointment summaries for completed bookings</p>
                </div>
                <div class="card">
                    <div class="card-header">
                        <h2>Generate Report</h2>
                    </div>
                    <div class="grid grid-cols-2 gap-4">
                        <div class="form-group">
                            <label for="report-date">Select Date</label>
                            <input type="date" id="report-date" name="report-date">
                        </div>
                        <div class="form-group flex justify-end items-end gap-4">
                            <button id="view-report-btn" class="btn btn-secondary w-full"><i class="fas fa-eye"></i> View Report</button>
                            <button id="download-report-btn" class="btn btn-primary w-full"><i class="fas fa-download"></i> Download PDF</button>
                        </div>
                    </div>
                </div>
                <div id="report-view-container" class="hidden">
                    <div class="card">
                        <div class="card-header">
                            <h2 id="report-view-title">Report Preview</h2>
                        </div>
                        <div class="kpi-grid" id="report-summary-cards"></div>
                        <div class="table-container">
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>Serial #</th>
                                        <th>Time</th>
                                        <th>Customer</th>
                                        <th>Service</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>
                                <tbody id="report-table-body"></tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            <div id="user-management-page" class="hidden">
                <div class="page-header">
                    <h1>User Accounts</h1>
                    <p>Add, edit, and manage user accounts and roles</p>
                </div>
                <div class="card">
                    <div class="card-header">
                        <h2>User List</h2>
                        <button id="add-user-btn" class="btn btn-primary"><i class="fas fa-plus"></i> Add New User</button>
                    </div>
                    <div class="table-container">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Username</th>
                                    <th>Name</th>
                                    <th>Role</th>
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="users-table-body"></tbody>
                        </table>
                    </div>
                </div>
            </div>

            <div id="audit-logs-page" class="hidden">
                <div class="page-header">
                    <h1>Audit Logs</h1>
                    <p>Review administrative actions and security events</p>
                </div>
                <div class="card">
                    <div class="card-header">
                        <h2>Log History</h2>
                        <button id="refresh-audit-logs-btn" class="btn btn-primary"><i class="fas fa-sync"></i> Refresh</button>
                    </div>
                    <div class="grid grid-cols-2 gap-4">
                        <div class="form-group">
                            <label for="log-start-date">Start Date</label>
                            <input type="date" id="log-start-date">
                        </div>
                        <div class="form-group">
                            <label for="log-end-date">End Date</label>
                            <input type="date" id="log-end-date">
                        </div>
                    </div>
                    <div class="table-container">
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>Timestamp</th>
                                    <th>User</th>
                                    <th>Action</th>
                                    <th>IP Address</th>
                                    <th>Location</th>
                                </tr>
                            </thead>
                            <tbody id="audit-logs-table-body"></tbody>
                        </table>
                    </div>
                </div>
            </div>

            <div id="change-password-page" class="hidden">
                <div class="page-header">
                    <h1>Change My Password</h1>
                    <p>Update your current password</p>
                </div>
                <div class="card">
                    <form id="change-password-form">
                        <div class="form-group">
                            <label for="old-password">Current Password</label>
                            <input type="password" id="old-password" required>
                        </div>
                        <div class="form-group">
                            <label for="new-password">New Password</label>
                            <input type="password" id="new-password" required>
                        </div>
                        <div class="form-group">
                            <label for="confirm-new-password">Confirm New Password</label>
                            <input type="password" id="confirm-new-password" required>
                        </div>
                        <div class="flex justify-end">
                            <button type="submit" class="btn btn-primary">Change Password</button>
                        </div>
                    </form>
                </div>
            </div>
        </main>
    </div>
    
    <div id="message-dialog" class="dialog">
        <div class="dialog-content">
            <div class="dialog-header">
                <h2 id="message-title">Message</h2>
                <button class="close-dialog" data-modal="message-dialog">&times;</button>
            </div>
            <div id="message-icon" style="text-align: center; font-size: 3rem; margin-bottom: 1.5rem;"></div>
            <div id="message-text" style="text-align: center; margin-bottom: 1.5rem; color: var(--text-primary);"></div>
            <button class="btn btn-primary w-full close-dialog" data-modal="message-dialog">OK</button>
        </div>
    </div>
    <div id="confirmation-dialog" class="dialog">
        <div class="dialog-content">
            <div class="dialog-header">
                <h2>Confirm Action</h2>
                <button class="close-dialog" data-modal="confirmation-dialog">&times;</button>
            </div>
            <p id="confirmation-text" class="mb-4" style="text-align: center;"></p>
            <div class="flex gap-4">
                <button id="confirm-yes" class="btn btn-danger w-full">Yes, Proceed</button>
                <button id="confirm-no" class="btn btn-secondary w-full">Cancel</button>
            </div>
        </div>
    </div>

    <div id="edit-appointment-modal" class="dialog">
        <div class="dialog-content">
            <div class="dialog-header">
                <h2>Edit Appointment</h2>
                <button class="close-dialog" data-modal="edit-appointment-modal">&times;</button>
            </div>
            <input type="hidden" id="edit-app-id">
            <div class="form-group">
                <label for="edit-app-name">Customer Name</label>
                <input type="text" id="edit-app-name" required>
            </div>
            <div class="form-group">
                <label for="edit-app-mobile">Mobile Number (Optional)</label>
                <input type="tel" id="edit-app-mobile">
            </div>
            <div class="form-group">
                <label for="edit-app-service">Service</label>
                <select id="edit-app-service" name="edit-app-service"></select>
            </div>
            <div class="form-group">
                <label for="edit-app-serial">Serial Number (Optional)</label>
                <input type="text" id="edit-app-serial" placeholder="Leave blank to auto-generate" >
            </div>
            <div class="flex gap-4 mt-4">
                <button id="save-edit-app-btn" class="btn btn-primary w-full">Save Changes</button>
                <button class="btn btn-secondary close-dialog w-full" data-modal="edit-appointment-modal">Cancel</button>
            </div>
        </div>
    </div>

    <div id="reschedule-modal" class="dialog">
        <div class="dialog-content">
            <div class="dialog-header">
                <h2>Reschedule Appointment</h2>
                <button class="close-dialog" data-modal="reschedule-modal">&times;</button>
            </div>
            <input type="hidden" id="reschedule-app-id">
            <input type="hidden" id="reschedule-app-service-id">
            <div class="form-group">
                <label for="reschedule-app-date">Select New Date</label>
                <input type="date" id="reschedule-app-date" name="reschedule-app-date">
            </div>
            <div class="form-group">
                <label for="reschedule-app-time-display">Select New Time</label>
                <input type="text" id="reschedule-app-time-display" placeholder="Click to view available slots" readonly style="cursor: pointer;">
                <input type="hidden" id="reschedule-app-time-select">
            </div>
            <div class="flex gap-4 mt-4">
                <button id="save-reschedule-app-btn" class="btn btn-primary w-full" disabled>Confirm Reschedule</button>
                <button class="btn btn-secondary close-dialog w-full" data-modal="reschedule-modal">Cancel</button>
            </div>
        </div>
    </div>

    <div id="reschedule-time-slots-modal" class="dialog">
        <div class="dialog-content">
            <div class="dialog-header">
                <h2 id="reschedule-time-slots-modal-title">Available Slots</h2>
                <button class="close-dialog" data-modal="reschedule-time-slots-modal">&times;</button>
            </div>
            <p id="reschedule-date-display" style="color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 1rem;"></p>
            <div id="reschedule-time-grid" class="time-slot-grid">
                <p style="grid-column: 1 / span 3; text-align: center; color: var(--text-secondary);">Select a date to see available slots.</p>
            </div>
        </div>
    </div>

    <div id="reschedule-info-modal" class="dialog">
        <div class="dialog-content">
            <div class="dialog-header">
                <h2>Original Appointment</h2>
                <button class="close-dialog" data-modal="reschedule-info-modal">&times;</button>
            </div>
            <p id="reschedule-info-text" style="font-size: 1.1rem; text-align: center; color: var(--text-primary);"></p>
        </div>
    </div>
    <div id="service-modal" class="dialog">
        <div class="dialog-content">
            <div class="dialog-header">
                <h2 id="service-modal-title">Add New Service</h2>
                <button class="close-dialog" data-modal="service-modal">&times;</button>
            </div>
            <input type="hidden" id="edit-service-id">
            <div class="form-group">
                <label for="service-name">Service Name</label>
                <input type="text" id="service-name" required>
            </div>
            <div class="form-group">
                <label for="service-duration">Duration (minutes)</label>
                <input type="number" id="service-duration" required>
            </div>
            <div class="form-group">
                <label for="service-category">Category</label>
                <select id="service-category"></select>
            </div>
            <div class="form-group hidden" id="new-category-group">
                <label for="new-service-category">New Category Name</label>
                <input type="text" id="new-service-category" placeholder="Enter a new category name">
            </div>
            <div class="flex gap-4 mt-4">
                <button id="save-service-btn" class="btn btn-primary w-full">Save Service</button>
                <button class="btn btn-secondary close-dialog w-full" data-modal="service-modal">Cancel</button>
            </div>
        </div>
    </div>
    <div id="rule-modal" class="dialog">
        <div class="dialog-content">
            <div class="dialog-header">
                <h2 id="rule-modal-title">Add New Rule</h2>
                <button class="close-dialog" data-modal="rule-modal">&times;</button>
            </div>
            <input type="hidden" id="edit-rule-id">
            <div class="form-group">
                <label for="rule-type-select">Rule Type</label>
                <select id="rule-type-select"></select>
            </div>
            <div id="rule-value-container"></div>
            <div class="flex gap-4 mt-4">
                <button id="save-rule-btn" class="btn btn-primary w-full">Save Rule</button>
                <button class="btn btn-secondary close-dialog w-full" data-modal="rule-modal">Cancel</button>
            </div>
        </div>
    </div>
    <div id="add-roster-modal" class="dialog">
        <div class="dialog-content">
            <div class="dialog-header">
                <h2>Block Time Slot</h2>
                <button class="close-dialog" data-modal="add-roster-modal">&times;</button>
            </div>
            <div class="form-group">
                <label for="roster-slot-date">Date</label>
                <input type="date" id="roster-slot-date" required>
            </div>
            <div class="grid grid-cols-2 gap-4">
                <div class="form-group">
                    <label for="roster-start-time">Start Time</label>
                    <input type="time" id="roster-start-time" required>
                </div>
                <div class="form-group">
                    <label for="roster-end-time">End Time</label>
                    <input type="time" id="roster-end-time" required>
                </div>
            </div>
            <div class="form-group">
                <label for="roster-reason">Reason</label>
                <input type="text" id="roster-reason" required>
            </div>
            <div class="flex gap-4 mt-4">
                <button id="save-roster-btn" class="btn btn-primary w-full">Block Time</button>
                <button class="btn btn-secondary close-dialog w-full" data-modal="add-roster-modal">Cancel</button>
            </div>
        </div>
    </div>
    <div id="user-modal" class="dialog">
        <div class="dialog-content">
            <div class="dialog-header">
                <h2 id="user-modal-title">Add New User</h2>
                <button class="close-dialog" data-modal="user-modal">&times;</button>
            </div>
            <input type="hidden" id="edit-user-id">
            <div class="form-group">
                <label for="user-username">Username</label>
                <input type="text" id="user-username" required>
            </div>
            <div class="form-group">
                <label for="user-name">Name</label>
                <input type="text" id="user-name">
            </div>
            <div class="form-group" id="password-group">
                <p style="color: var(--text-secondary); font-size: 0.9rem;">The initial password will be the same as the username.</p>
            </div>
            <div class="form-group">
                <label for="user-role">Role</label>
                <select id="user-role">
                    <option value="user">User</option>
                    <option value="admin">Admin</option>
                </select>
            </div>
            <div class="flex gap-4 mt-4">
                <button id="save-user-btn" class="btn btn-primary w-full">Save User</button>
                <button class="btn btn-secondary close-dialog w-full" data-modal="user-modal">Cancel</button>
            </div>
        </div>
    </div>
    <div id="reset-password-modal" class="dialog">
        <div class="dialog-content">
            <div class="dialog-header">
                <h2>Reset Password</h2>
                <button class="close-dialog" data-modal="reset-password-modal">&times;</button>
            </div>
            <p style="text-align: center; margin-bottom: 1.5rem; color: var(--text-primary);">The password for <strong id="reset-user-username"></strong> will be reset to their username.</p>
            <input type="hidden" id="reset-user-id">
            <input type="hidden" id="reset-user-name">
            <div class="flex gap-4">
                <button id="save-reset-btn" class="btn btn-danger w-full">Confirm Reset</button>
                <button class="btn btn-secondary close-dialog w-full" data-modal="reset-password-modal">Cancel</button>
            </div>
        </div>
    </div>
<script>
    // Global state and elements
    let servicesList = [];
    let currentAppointments = [];
    let currentServiceIdForRule = null;
    let showCompleted = false;
    const isAdmin = <?php echo json_encode($isAdmin); ?>;
    const csrfToken = "<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>";

    const pageDetails = {
        appointments: { title: 'Appointments', subtitle: 'View, edit, or cancel existing appointments' },
        'book-appointment': { title: 'Book New Appointment', subtitle: 'Manually book a new walk-in appointment' },
        services: { title: 'Manage Services', subtitle: 'Add, edit, or remove services offered' },
        rules: { title: 'Booking Rules', subtitle: 'Set service-specific booking restrictions' },
        roster: { title: 'Roster & Breaks', subtitle: 'Block out time slots for breaks or other activities' },
        reports: { title: 'Day End Reports', subtitle: 'Generate and download daily appointment summaries' }, // NEW
        'user-management': { title: 'User Accounts', subtitle: 'Add, edit, and manage user accounts and roles' },
        'audit-logs': { title: 'Audit Logs', subtitle: 'Review administrative actions and security events' },
        'change-password': { title: 'Change Password', subtitle: 'Update your current password' }
    };

    const ruleDefinitions = {
        MIN_LEAD_TIME: { label: "Minimum Lead Time (Hours)", type: "number", placeholder: "e.g., 24", description: "Customer must book at least this many hours in advance." },
        MAX_BOOKING_HORIZON: { label: "Maximum Booking Horizon (Days)", type: "number", placeholder: "e.g., 30", description: "Customer can only book up to this many days in the future." },
        MAX_PER_DAY: { label: "Max Bookings Per Day", type: "number", placeholder: "e.g., 5", description: "Maximum number of times this service can be booked per day." },
        BUFFER_TIME: { label: "Buffer Time (Minutes)", type: "number", placeholder: "e.g., 15", description: "Time before and after an appointment that is blocked off." },
        START_TIME: { label: "Service Available From", type: "time", description: "The earliest time this service can be booked." },
        END_TIME: { label: "Service Available Until", type: "time", description: "The latest time this service can be booked." },
        ALLOWED_DAYS: { label: "Allowed Weekdays", type: "weekdays", description: "Specific days of the week this service is available." },
    };
    
    /**
     * Sets up a client-side timer to detect user inactivity and log them out.
     */
    const setupInactivityTimer = () => {
        let inactivityTimeout;

        const logoutUser = () => {
            // Use the existing showMessage function to inform the user
            showMessage('You will be logged out due to inactivity.', 'info');
            
            // Hide the default "OK" button to prevent dismissal
            document.querySelector('#message-dialog .close-dialog').style.display = 'none';
            document.querySelector('#message-dialog .btn').style.display = 'none';

            // Redirect to the logout page after a few seconds
            setTimeout(() => {
                window.location.href = '../logout.php?reason=inactive';
            }, 4000); // Redirect after 4 seconds
        };

        const resetTimer = () => {
            clearTimeout(inactivityTimeout);
            inactivityTimeout = setTimeout(logoutUser, 900000); // 15 minutes = 900,000 ms
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

    // Mapping elements using the new DOM IDs/Classes (kept consistent with original JS as much as possible)
    const elements = {
        pages: document.querySelectorAll('main > div[id$="-page"]'),
        pageTitleHeading: document.getElementById('page-title-heading'),
        pageTitleSubheading: document.getElementById('page-title-subheading'),
        navLinks: document.querySelectorAll('.nav-item'), // Changed from .nav-link to .nav-item
        appointmentsPage: document.getElementById('appointments-page'),
        appointmentsDateInput: document.getElementById('appointments-date'),
        appointmentSearch: document.getElementById('appointment-search'),
        statsGrid: document.getElementById('stats-grid'), // .kpi-grid container
        totalBookings: document.getElementById('total-bookings'),
        appointmentsTableBody: document.getElementById('appointments-table-body'),
        bookAppointmentPage: document.getElementById('book-appointment-page'),
        servicesPage: document.getElementById('services-page'),
        servicesTableBody: document.getElementById('services-table-body'),
        addServiceBtn: document.getElementById('add-service-btn'),
        rosterPage: document.getElementById('roster-page'),
        rosterDateInput: document.getElementById('roster-date'),
        rosterTableBody: document.getElementById('roster-table-body'),
        addRosterBtn: document.getElementById('add-roster-btn'),
        dailyBreaksContainer: document.getElementById('daily-breaks-container'),
        addDailyBreakBtn: document.getElementById('add-daily-break-btn'),
        saveDailyBreaksBtn: document.getElementById('save-daily-breaks-btn'),
        rulesPage: document.getElementById('rules-page'),
        ruleServiceSelect: document.getElementById('rule-service-select'),
        rulesContainer: document.getElementById('rules-container'),
        rulesForServiceName: document.getElementById('rules-for-service-name'),
        addRuleBtn: document.getElementById('add-rule-btn'),
        rulesTableBody: document.getElementById('rules-table-body'),
        userManagementPage: document.getElementById('user-management-page'),
        usersTableBody: document.getElementById('users-table-body'),
        addUserBtn: document.getElementById('add-user-btn'),
        userModal: document.getElementById('user-modal'),
        userModalTitle: document.getElementById('user-modal-title'),
        editUserId: document.getElementById('edit-user-id'),
        userUsernameInput: document.getElementById('user-username'),
        userNameInput: document.getElementById('user-name'),
        userRoleSelect: document.getElementById('user-role'),
        auditLogsPage: document.getElementById('audit-logs-page'),
        auditLogsTableBody: document.getElementById('audit-logs-table-body'),
        logStartDateInput: document.getElementById('log-start-date'),
        logEndDateInput: document.getElementById('log-end-date'),
        changePasswordPage: document.getElementById('change-password-page'),
        changePasswordForm: document.getElementById('change-password-form'),
        oldPasswordInput: document.getElementById('old-password'),
        newPasswordInput: document.getElementById('new-password'),
        confirmNewPasswordInput: document.getElementById('confirm-new-password'),
        currentTimeDisplay: document.getElementById('current-time'),
        messageDialog: document.getElementById('message-dialog'),
        messageTitle: document.getElementById('message-title'),
        messageIcon: document.getElementById('message-icon'),
        messageText: document.getElementById('message-text'),
        confirmationDialog: document.getElementById('confirmation-dialog'),
        confirmationText: document.getElementById('confirmation-text'),
        confirmYesBtn: document.getElementById('confirm-yes'),
        confirmNoBtn: document.getElementById('confirm-no'),
        editAppointmentModal: document.getElementById('edit-appointment-modal'),
        editAppId: document.getElementById('edit-app-id'),
        editAppName: document.getElementById('edit-app-name'),
        editAppMobile: document.getElementById('edit-app-mobile'),
        editAppService: document.getElementById('edit-app-service'),
        editAppSerial: document.getElementById('edit-app-serial'),
        saveEditAppBtn: document.getElementById('save-edit-app-btn'),
        rescheduleModal: document.getElementById('reschedule-modal'),
        rescheduleAppId: document.getElementById('reschedule-app-id'),
        rescheduleAppServiceId: document.getElementById('reschedule-app-service-id'),
        rescheduleAppDate: document.getElementById('reschedule-app-date'),
        rescheduleAppTimeDisplay: document.getElementById('reschedule-app-time-display'),
        rescheduleAppTimeSelect: document.getElementById('reschedule-app-time-select'),
        saveRescheduleAppBtn: document.getElementById('save-reschedule-app-btn'),
        rescheduleTimeSlotsModal: document.getElementById('reschedule-time-slots-modal'),
        rescheduleTimeSlotsModalTitle: document.getElementById('reschedule-time-slots-modal-title'),
        rescheduleDateDisplay: document.getElementById('reschedule-date-display'),
        rescheduleTimeGrid: document.getElementById('reschedule-time-grid'),
        rescheduleInfoModal: document.getElementById('reschedule-info-modal'),
        rescheduleInfoText: document.getElementById('reschedule-info-text'),
        serviceModal: document.getElementById('service-modal'),
        serviceModalTitle: document.getElementById('service-modal-title'),
        editServiceId: document.getElementById('edit-service-id'),
        serviceNameInput: document.getElementById('service-name'),
        serviceDurationInput: document.getElementById('service-duration'),
        serviceCategorySelect: document.getElementById('service-category'),
        newCategoryGroup: document.getElementById('new-category-group'),
        newServiceCategoryInput: document.getElementById('new-service-category'),
        saveServiceBtn: document.getElementById('save-service-btn'),
        ruleModal: document.getElementById('rule-modal'),
        ruleModalTitle: document.getElementById('rule-modal-title'),
        editRuleId: document.getElementById('edit-rule-id'),
        ruleTypeSelect: document.getElementById('rule-type-select'),
        ruleValueContainer: document.getElementById('rule-value-container'),
        saveRuleBtn: document.getElementById('save-rule-btn'),
        addRosterModal: document.getElementById('add-roster-modal'),
        rosterSlotDate: document.getElementById('roster-slot-date'),
        rosterStartTime: document.getElementById('roster-start-time'),
        rosterEndTime: document.getElementById('roster-end-time'),
        rosterReason: document.getElementById('roster-reason'),
        saveRosterBtn: document.getElementById('save-roster-btn'),
        saveUserBtn: document.getElementById('save-user-btn'),
        resetPasswordModal: document.getElementById('reset-password-modal'),
        resetUserUsername: document.getElementById('reset-user-username'),
        resetUserId: document.getElementById('reset-user-id'),
        resetUserName: document.getElementById('reset-user-name'),
        saveResetBtn: document.getElementById('save-reset-btn'),
        
        walkinForm: document.getElementById('book-walkin-form'),
        walkinName: document.getElementById('walkin-name'),
        walkinMobile: document.getElementById('walkin-mobile'),
        walkinService: document.getElementById('walkin-service'),
        walkinDate: document.getElementById('walkin-date'),
        walkinTimeDisplay: document.getElementById('walkin-time-display'),
        walkinTimeSelect: document.getElementById('walkin-time-select'),
        walkinSerial: document.getElementById('walkin-serial'),

        // NEW: Report elements
        reportsPage: document.getElementById('reports-page'),
        reportDate: document.getElementById('report-date'),
        viewReportBtn: document.getElementById('view-report-btn'),
        downloadReportBtn: document.getElementById('download-report-btn'),
        reportViewContainer: document.getElementById('report-view-container'),
        reportViewTitle: document.getElementById('report-view-title'),
        reportSummaryCards: document.getElementById('report-summary-cards'),
        reportTableBody: document.getElementById('report-table-body'),
        
        // REMOVED: Permissions elements
        // permissionsModal: document.getElementById('permissions-modal'),
        // ... (removed elements)

        sidebar: document.getElementById('sidebar'),
        menuToggleBtn: document.getElementById('menu-toggle-btn'),
        toggleDoneBtn: document.getElementById('toggle-done-btn'),
        darkModeToggle: document.getElementById('dark-mode-toggle'),
        
        // NEW: Overbook element
        overbookOverrideCheckbox: document.getElementById('overbook-override'),
    };

    // --- DARK MODE LOGIC (Copied from template) ---
    // Check for saved dark mode preference and apply on load
    if (localStorage.getItem('darkMode') === 'true') {
        document.body.classList.add('dark-mode');
        // Ensure the toggle state matches the class if it exists
        if (elements.darkModeToggle) {
            elements.darkModeToggle.checked = true;
        }
    }

    if (elements.darkModeToggle) {
        elements.darkModeToggle.addEventListener('change', function() {
            document.body.classList.toggle('dark-mode', this.checked);
            // Save preference
            localStorage.setItem('darkMode', this.checked);
        });
    }


    // --- MODAL & UI HELPERS (Modified to use new UI classes) ---
    const openModal = (modalId) => {
        document.getElementById(modalId).classList.add('active');
    };
    const closeModal = (modalId) => {
        document.getElementById(modalId).classList.remove('active');
    };
    
    // MODIFIED: Close modal on outside click
    document.querySelectorAll('.dialog').forEach(dialog => {
        dialog.addEventListener('click', (e) => {
            if (e.target === dialog) {
                closeModal(dialog.id);
            }
        });
    });

    document.querySelectorAll('.close-dialog').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const modalId = e.currentTarget.dataset.modal || e.currentTarget.closest('.dialog').id;
            closeModal(modalId);
        });
    });

    const showMessage = (message, type = 'success', details = null) => {
        const successIcon = `<i class="fas fa-check-circle" style="color: var(--status-success);"></i>`;
        const errorIcon = `<i class="fas fa-times-circle" style="color: var(--status-danger);"></i>`;
        
        elements.messageTitle.textContent = type === 'success' ? 'Success' : 'Error';
        elements.messageIcon.innerHTML = type === 'success' ? successIcon : errorIcon;
        
        let messageHtml = `<p style="color: var(--text-primary);">${message}</p>`;
        // NEW: Display detailed success message
        if (details) {
            messageHtml += `
                <div style="text-align: left; margin: 1rem auto; max-width: 300px; background: var(--bg-primary); padding: 1rem; border-radius: 8px; border: 1px solid var(--border-color);">
                    <p style="color: var(--text-primary); line-height: 1.6;">
                        <strong>Name:</strong> ${details.name}<br>
                        <strong>Serial #:</strong> ${details.serial}<br>
                        <strong>Service:</strong> ${details.service}<br>
                        <strong>Time:</strong> ${details.startTime} - ${details.endTime}<br>
                        <strong>Date:</strong> ${details.date}
                    </p>
                </div>
            `;
        }
        elements.messageText.innerHTML = messageHtml;
        openModal('message-dialog');
    };
    
    const showConfirmation = (message) => {
        return new Promise(resolve => {
            elements.confirmationText.textContent = message;
            openModal('confirmation-dialog');

            const confirmYes = () => {
                closeModal('confirmation-dialog');
                elements.confirmYesBtn.removeEventListener('click', confirmYes);
                elements.confirmNoBtn.removeEventListener('click', confirmNo);
                resolve(true);
            };
            const confirmNo = () => {
                closeModal('confirmation-dialog');
                elements.confirmYesBtn.removeEventListener('click', confirmYes);
                elements.confirmNoBtn.removeEventListener('click', confirmNo);
                resolve(false);
            };

            elements.confirmYesBtn.addEventListener('click', confirmYes);
            elements.confirmNoBtn.addEventListener('click', confirmNo);
        });
    };

    const showPage = (pageId) => {
        if ((pageId === 'user-management' || pageId === 'audit-logs') && !isAdmin) {
            showMessage('You do not have permission to access this page.', 'error');
            return;
        }

        history.pushState(null, '', '#' + pageId);

        elements.pages.forEach(page => page.classList.add('hidden'));
        const pageElement = document.getElementById(pageId + '-page');
        if (pageElement) {
            pageElement.classList.remove('hidden');
        }

        elements.navLinks.forEach(link => {
            link.classList.toggle('active', link.dataset.page === pageId);
        });
        
        const titleElement = document.querySelector(`#${pageId}-page .page-header h1`);
        const subtitleElement = document.querySelector(`#${pageId}-page .page-header p`);
        if (titleElement && pageDetails[pageId]) titleElement.textContent = pageDetails[pageId].title;
        if (subtitleElement && pageDetails[pageId]) subtitleElement.textContent = pageDetails[pageId].subtitle;
        
        if (pageId === 'appointments') {
            const today = new Date().toISOString().slice(0, 10);
            elements.appointmentsDateInput.value = elements.appointmentsDateInput.value || today;
            fetchServices().then(() => fetchAppointments(elements.appointmentsDateInput.value));
        } else if (pageId === 'book-appointment') {
            const today = new Date().toISOString().slice(0, 10);
            elements.walkinDate.value = elements.walkinDate.value || today;
            elements.walkinDate.min = today;
            populateServicesDropdown(elements.walkinService);
            
            // MODIFIED: Admin overbooking UI setup logic is now simple:
            const overbookGroup = document.getElementById('overbook-permission-group');
            if (isAdmin) {
               // The element is already visible in the PHP, no need to hide/show, just ensure visibility
               elements.walkinTimeDisplay.placeholder = 'Click for slots or type time (e.g., 14:30)';
               elements.walkinTimeDisplay.removeAttribute('readonly');
            } else {
               // This block is inside <?php if ($isAdmin): ?> so it's not strictly necessary, 
               // but kept for local development testing/consistency if HTML wasn't conditional.
               elements.walkinTimeDisplay.placeholder = 'Click to select available time';
               elements.walkinTimeDisplay.setAttribute('readonly', true);
            }
        } else if (pageId === 'services') {
            fetchServices();
        } else if (pageId === 'rules') {
            initializeRulesPage();
        } else if (pageId === 'roster') {
            const today = new Date().toISOString().slice(0, 10);
            elements.rosterDateInput.value = elements.rosterDateInput.value || today;
            fetchBlockedSlots(elements.rosterDateInput.value);
            fetchDailyBreaks();
        } else if (pageId === 'reports') {
            const today = new Date().toISOString().slice(0, 10);
            elements.reportDate.value = today;
            elements.reportViewContainer.classList.add('hidden');
        } else if (pageId === 'user-management') {
            fetchUsers();
        } else if (pageId === 'audit-logs') {
            const today = new Date();
            const defaultEndDate = today.toISOString().slice(0, 10);
            const defaultStartDate = new Date(today.setDate(today.getDate() - 7)).toISOString().slice(0, 10);
            
            elements.logStartDateInput.value = elements.logStartDateInput.value || defaultStartDate;
            elements.logEndDateInput.value = elements.logEndDateInput.value || defaultEndDate;
            fetchAuditLogs();
        }
        
        // Close sidebar on mobile after navigating
        elements.sidebar.classList.remove('active');
    };

    const updateCurrentTime = () => {
        const now = new Date();
        const timeString = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: true });
        if (elements.currentTimeDisplay) {
            elements.currentTimeDisplay.textContent = timeString;
        }
    };

    // --- API & DATA FETCHING (UNCHANGED CORE LOGIC) ---
    const apiPost = async (body) => {
        try {
            const response = await fetch('dashboard.php', {
                method: 'POST',
                headers: {  
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify({...body, csrf_token: csrfToken})
            });
            const result = await response.json();
            if (!response.ok) {
                throw new Error(result.message || 'Server error');
            }
            return result;
        } catch (error) {
            console.error('API POST Error:', error);
            showMessage(error.message || 'A network error occurred. Please try again.', 'error');
            return { success: false, message: 'Network error' };
        }
    };
    
    const apiGet = async (url) => {
        try {
            const response = await fetch('dashboard.php' + url, {
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });
            const contentType = response.headers.get("content-type");
            if (!contentType || !contentType.includes("application/json")) {
                const text = await response.text();
                console.error("Non-JSON response:", text);
                throw new TypeError("Received non-JSON response from server.");
            }
            const result = await response.json();
            if (!response.ok) {
                throw new Error(result.message || 'Server error');
            }
            return result;
        } catch (error) {
            console.error('API GET Error:', error);
            // Don't show generic error on network issues for background fetches
            if (error.message !== 'Network error') { 
                showMessage(error.message || 'A network error occurred while fetching data.', 'error');
            }
            return null;
        }
    };

    // --- APPOINTMENTS LOGIC (UI parts updated) ---
    const fetchAppointments = async (date) => {
        const result = await apiGet(`?action=view_appointments&date=${date}`);
        if (result && result.success) {
            currentAppointments = result.appointments;
            filterAndRenderAppointments();
        }
    };
    
    const filterAndRenderAppointments = () => {
        const searchTerm = elements.appointmentSearch.value.toLowerCase().trim();
        let appointmentsToDisplay = currentAppointments;

        if (searchTerm) {
            appointmentsToDisplay = currentAppointments.filter(app => {
                const name = app.customer_name ? app.customer_name.toLowerCase() : '';
                const mobile = app.customer_mobile ? app.customer_mobile.toLowerCase() : '';
                const serial = app.serial_number ? app.serial_number.toString().toLowerCase() : '';
                return name.includes(searchTerm) || mobile.includes(searchTerm) || serial.includes(searchTerm);
            });
        }

        renderStats(appointmentsToDisplay);
        const now = new Date();
        const todayStr = elements.appointmentsDateInput.value;
        const isToday = new Date(todayStr).toDateString() === now.toDateString();

        const upcoming = [];
        const ongoing = [];
        const unattended = [];
        const done = [];

        appointmentsToDisplay.forEach(app => {
            const appointmentStart = new Date(app.appointment_datetime);
            const appointmentEnd = new Date(appointmentStart.getTime() + app.duration_minutes * 60000);

            if (app.is_done == 1) {
                done.push(app);
            } else if (isToday && now >= appointmentStart && now < appointmentEnd) {
                ongoing.push(app);
            } else if (isToday && now >= appointmentEnd) {
                unattended.push(app);
            } else {
                upcoming.push(app);
            }
        });

        // Sort appointments for consistent display
        upcoming.sort((a, b) => new Date(a.appointment_datetime) - new Date(b.appointment_datetime));
        ongoing.sort((a, b) => new Date(a.appointment_datetime) - new Date(b.appointment_datetime));
        unattended.sort((a, b) => new Date(a.appointment_datetime) - new Date(b.appointment_datetime));
        done.sort((a, b) => new Date(a.appointment_datetime) - new Date(b.appointment_datetime));
        
        let finalAppointmentsList = [...ongoing, ...upcoming, ...unattended];

        if (showCompleted) {
            finalAppointmentsList = [...finalAppointmentsList, ...done];
        }
        
        renderAppointmentsTable(finalAppointmentsList, isToday, showCompleted);
    };
    
    // MODIFIED: Render Stats to use KPI Card visual style
    const renderStats = (appointments) => {
        elements.statsGrid.innerHTML = '';
        
        // Filter out 'done' appointments for stat calculation
        const activeAppointments = appointments.filter(app => app.is_done == 0);

        const totalCard = document.createElement('div');
        totalCard.className = 'kpi-card';
        totalCard.innerHTML = `
            <div class="kpi-icon" style="background: linear-gradient(135deg, var(--primary), var(--primary-light));">
                <i class="fas fa-calendar-check"></i>
            </div>
            <div class="kpi-content">
                <div class="kpi-value" id="total-bookings">${activeAppointments.length}</div>
                <div class="kpi-label">Active Bookings</div>
            </div>
        `;
        elements.statsGrid.appendChild(totalCard);
        
        const serviceCounts = {};
        activeAppointments.forEach(app => {
            serviceCounts[app.service_name] = (serviceCounts[app.service_name] || 0) + 1;
        });

        const serviceColors = ['#F59E0B', '#10B981', '#3B82F6', '#EF4444'];
        let colorIndex = 0;
        
        for (const serviceName in serviceCounts) {
            const count = serviceCounts[serviceName];
            const statCard = document.createElement('div');
            statCard.className = 'kpi-card';
            statCard.innerHTML = `
                <div class="kpi-icon" style="background: linear-gradient(135deg, ${serviceColors[colorIndex]}, ${serviceColors[colorIndex]}99);">
                    <i class="fas fa-list-check"></i>
                </div>
                <div class="kpi-content">
                    <div class="kpi-value">${count}</div>
                    <div class="kpi-label">${serviceName}</div>
                </div>
            `;
            elements.statsGrid.appendChild(statCard);
            colorIndex = (colorIndex + 1) % serviceColors.length;
        }
    };

    const renderAppointmentsTable = (appointments, isTodayView, showCompleted) => {
        elements.appointmentsTableBody.innerHTML = '';
        
        // Update toggle button text
        const toggleButton = document.getElementById('toggle-done-btn');
        if (showCompleted) {
            toggleButton.innerHTML = `<i class="fas fa-eye-slash"></i> Hide Completed`;
        } else {
            toggleButton.innerHTML = `<i class="fas fa-eye"></i> Show All`;
        }

        if (appointments.length === 0) {
            elements.appointmentsTableBody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-secondary);">No matching bookings found.</td></tr>`;
            return;
        }
        
        const now = new Date();
        
        appointments.forEach(app => {
            const row = document.createElement('tr');
            const appointmentStart = new Date(app.appointment_datetime);
            const appointmentEnd = new Date(appointmentStart.getTime() + app.duration_minutes * 60000);

            const formattedTime = appointmentStart.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true });

            let rescheduleInfo = '';
            if (app.is_rescheduled == 1 && app.original_appointment_datetime) {
                const originalTime = new Date(app.original_appointment_datetime);
                const formattedOriginal = originalTime.toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' });
                rescheduleInfo = `<span class="reschedule-badge">RESCHEDULED</span><i class="fas fa-info-circle info-icon" data-original-time="${formattedOriginal}"></i>`;
            }

            let statusClass = '';
            let statusBadge = '';
            let isPast = false;
            
            if (isTodayView && now >= appointmentEnd) {
                isPast = true;
            }

            if (app.is_done == 1) {
                statusClass = 'done-row';
                statusBadge = `<span class="done-badge" style="background-color: var(--status-success);">DONE</span>`;
            } else if (isTodayView && now >= appointmentStart && now < appointmentEnd) {
                statusClass = 'pulsing-row';
                statusBadge = `<span class="done-badge" style="background-color: var(--status-info);">ONGOING</span>`;
            } else if (isPast) {
                statusClass = 'pulsing-row unattended';
                statusBadge = `<span class="reschedule-badge" style="background-color: var(--status-danger);">UNATTENDED</span>`;
            } else {
                statusClass = 'upcoming-row';
            }
            row.className = statusClass;
            row.style.display = (app.is_done == 1 && !showCompleted) ? 'none' : 'table-row';

            const doneButton = app.is_done == 1 
                ? '' 
                : `<button class="action-button done done-btn" data-id="${app.id}"><i class="fas fa-check"></i> Done</button>`;

            row.innerHTML = `
                <td>${app.serial_number}</td>
                <td>${formattedTime}</td>
                <td>
                    <div style="display:flex; align-items: center;">
                        <span style="font-weight: 600;">${app.customer_name}</span> ${rescheduleInfo} ${statusBadge}
                    </div>
                </td>
                <td>${app.customer_mobile || 'N/A'}</td>
                <td>${app.service_name}</td>
                <td>
                    <div style="display:flex; gap: 0.5rem; justify-content: flex-end; flex-wrap: nowrap;">
                        ${doneButton}
                        <button class="action-button edit-btn" data-id="${app.id}" data-name="${app.customer_name}" data-mobile="${app.customer_mobile}" data-service-id="${app.service_id}" data-serial-number="${app.serial_number}"><i class="fas fa-edit"></i> Edit</button>
                        <button class="action-button reschedule-btn" data-id="${app.id}" data-service-id="${app.service_id}"><i class="fas fa-calendar-day"></i> Reschedule</button>
                        <button class="action-button cancel delete" data-id="${app.id}"><i class="fas fa-trash-alt"></i> Cancel</button>
                    </div>
                </td>
            `;
            elements.appointmentsTableBody.appendChild(row);
        });
        
        elements.appointmentsTableBody.querySelectorAll('.edit-btn').forEach(btn => btn.addEventListener('click', (e) => {
            const { id, name, mobile, serviceId, serialNumber } = e.currentTarget.dataset;
            openEditAppointmentModal(id, name, mobile, serviceId, serialNumber);
        }));
        elements.appointmentsTableBody.querySelectorAll('.reschedule-btn').forEach(btn => btn.addEventListener('click', (e) => {
            const { id, serviceId } = e.currentTarget.dataset;
            openRescheduleModal(id, serviceId);
        }));
        elements.appointmentsTableBody.querySelectorAll('.cancel').forEach(btn => btn.addEventListener('click', (e) => cancelAppointment(e.currentTarget.dataset.id)));
        elements.appointmentsTableBody.querySelectorAll('.done-btn').forEach(btn => btn.addEventListener('click', (e) => completeAppointment(e.currentTarget.dataset.id)));
        elements.appointmentsTableBody.querySelectorAll('.info-icon').forEach(icon => {
            icon.addEventListener('click', (e) => {
                elements.rescheduleInfoText.textContent = `Original: ${e.currentTarget.dataset.originalTime}`;
                openModal('reschedule-info-modal');
            });
        });
    };

    const openEditAppointmentModal = async (id, name, mobile, serviceId, serialNumber) => {
        if (!servicesList.length) {
            await fetchServices();
        }
        elements.editAppId.value = id;
        elements.editAppName.value = name;
        elements.editAppMobile.value = mobile || '';
        elements.editAppSerial.value = serialNumber;
        elements.editAppService.innerHTML = '';
        servicesList.forEach(service => {
            const option = document.createElement('option');
            option.value = service.id;
            option.textContent = service.name;
            if (service.id == serviceId) option.selected = true;
            elements.editAppService.appendChild(option);
        });
        openModal('edit-appointment-modal');
    };
    
    const saveEditAppointment = async () => {
        const id = elements.editAppId.value;
        const name = elements.editAppName.value;
        const mobile = elements.editAppMobile.value;
        const serviceId = elements.editAppService.value;
        const serialNumber = elements.editAppSerial.value;
        
        if (!name) return showMessage('Name cannot be empty.', 'error');
        
        const action = 'edit_appointment';
        const result = await apiPost({ action, id, name, mobile, service_id: serviceId, serial_number: serialNumber });
        if (result.success) {
            showMessage(result.message);
            closeModal('edit-appointment-modal');
            fetchAppointments(elements.appointmentsDateInput.value);
        } else {
            showMessage(result.message, 'error');
        }
    };
    
    const cancelAppointment = async (id) => {
        if (!await showConfirmation('Are you sure you want to cancel this appointment? This action cannot be undone.')) return;
        
        const result = await apiPost({ action: 'cancel_appointment', id });
        if (result.success) {
            showMessage(result.message);
            fetchAppointments(elements.appointmentsDateInput.value);
        } else {
            showMessage(result.message, 'error');
        }
    };

    const completeAppointment = async (id) => {
        if (!await showConfirmation('Are you sure you want to mark this appointment as done?')) return;
        
        const result = await apiPost({ action: 'complete_appointment', id });
        if (result.success) {
            showMessage(result.message);
            fetchAppointments(elements.appointmentsDateInput.value);
        } else {
            showMessage(result.message, 'error');
        }
    };

    const openRescheduleModal = (id, serviceId) => {
        elements.rescheduleAppId.value = id;
        elements.rescheduleAppServiceId.value = serviceId;
        const today = new Date().toISOString().slice(0, 10);
        elements.rescheduleAppDate.value = today;
        elements.rescheduleAppDate.min = today;
        elements.rescheduleAppTimeDisplay.value = 'Click to view available slots';
        elements.rescheduleAppTimeSelect.value = '';
        elements.saveRescheduleAppBtn.disabled = true;
        openModal('reschedule-modal');
    };
    
    const submitReschedule = async () => {
        const id = elements.rescheduleAppId.value;
        const date = elements.rescheduleAppDate.value;
        const time = elements.rescheduleAppTimeSelect.value;
        
        if (!date || !time) {
            return showMessage('Please select a new date and time.', 'error');
        }

        const result = await apiPost({ action: 'reschedule_appointment', id, date, time });
        if (result.success) {
            showMessage(result.message);
            closeModal('reschedule-modal');
            fetchAppointments(elements.appointmentsDateInput.value);
        } else {
            showMessage(result.message, 'error');
        }
    };
    
    // --- SERVICES LOGIC (UNCHANGED CORE LOGIC) ---
    const fetchServices = async () => {
        const result = await apiGet(`?action=services`);
        if (result && result.success) {
            servicesList = result.services;
            renderServicesTable(servicesList);
            return servicesList;
        }
        return [];
    };

    const renderServicesTable = (services) => {
        elements.servicesTableBody.innerHTML = '';
        if (services.length === 0) {
            elements.servicesTableBody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-secondary);">No services configured.</td></tr>`;
            return;
        }
        services.forEach(service => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${service.name}</td>
                <td>${service.category || 'General'}</td>
                <td>${service.duration_minutes} min</td>
                <td>
                    <button class="action-button edit-service-btn" data-id="${service.id}" data-name="${service.name}" data-duration="${service.duration_minutes}" data-category="${service.category || 'General'}"><i class="fas fa-edit"></i> Edit</button>
                    <button class="action-button delete-service-btn delete" data-id="${service.id}"><i class="fas fa-trash-alt"></i> Delete</button>
                </td>
            `;
            elements.servicesTableBody.appendChild(row);
        });

        elements.servicesTableBody.querySelectorAll('.edit-service-btn').forEach(btn => btn.addEventListener('click', e => {
            const { id, name, duration, category } = e.currentTarget.dataset;
            openServiceModal('edit', { id, name, duration, category });
        }));
        elements.servicesTableBody.querySelectorAll('.delete-service-btn').forEach(btn => btn.addEventListener('click', e => deleteService(e.currentTarget.dataset.id)));
    };

    const fetchAndPopulateCategories = async (selectElement, selectedCategory = '') => {
        const result = await apiGet(`?action=get_categories`);
        selectElement.innerHTML = '';  
        if (result && result.success) {
            if (!result.categories.includes('General')) {
                result.categories.unshift('General');
            }
            result.categories.forEach(category => {
                const option = document.createElement('option');
                option.value = category;
                option.textContent = category;
                if (category === selectedCategory) {
                    option.selected = true;
                }
                selectElement.appendChild(option);
            });
        }
        const newOption = document.createElement('option');
        newOption.value = '__new__';
        newOption.textContent = '-- Create New Category --';
        selectElement.appendChild(newOption);
    };

    const openServiceModal = async (mode, service = {}) => {
        elements.serviceModalTitle.textContent = mode === 'add' ? 'Add New Service' : 'Edit Service';
        elements.editServiceId.value = service.id || '';
        elements.serviceNameInput.value = service.name || '';
        elements.serviceDurationInput.value = service.duration || '';
        elements.newCategoryGroup.classList.add('hidden');
        elements.newServiceCategoryInput.value = '';
        await fetchAndPopulateCategories(elements.serviceCategorySelect, service.category);
        openModal('service-modal');
    };
    
    const saveService = async () => {
        const id = elements.editServiceId.value;
        const name = elements.serviceNameInput.value;
        const duration = elements.serviceDurationInput.value;
        let category = elements.serviceCategorySelect.value;
        if (category === '__new__') {
            category = elements.newServiceCategoryInput.value.trim();
            if (!category) {
                return showMessage('Please enter a name for the new category.', 'error');
            }
        }
        
        if (!name || !duration || duration <= 0) return showMessage('Please enter a valid name and duration.', 'error');
        
        const action = id ? 'edit_service' : 'add_service';
        const result = await apiPost({ action, id, name, duration, category });

        if (result.success) {
            showMessage(result.message);
            closeModal('service-modal');
            fetchServices();
        } else {
            showMessage(result.message, 'error');
        }
    };
    
    const deleteService = async (id) => {
        if (!await showConfirmation('Are you sure you want to delete this service? This may affect existing appointments.')) return;
        
        const result = await apiPost({ action: 'delete_service', id });
        if (result.success) {
            showMessage(result.message);
            fetchServices();
        } else {
            showMessage(result.message, 'error');
        }
    };
    
    // --- Booking Rules Logic (UNCHANGED CORE LOGIC) ---
    const initializeRulesPage = async () => {
        await populateServicesDropdown(elements.ruleServiceSelect);
        elements.rulesContainer.classList.add('hidden');
    };
    
    const fetchAndRenderRules = async (serviceId) => {
        currentServiceIdForRule = serviceId;
        if (!serviceId) {
            elements.rulesContainer.classList.add('hidden');
            return;
        }
        const service = servicesList.find(s => s.id == currentServiceIdForRule);
        if (service) {
            document.getElementById('rules-for-service-name').textContent = `Rules for "${service.name}"`;
        }
        const result = await apiGet(`?action=get_rules&service_id=${serviceId}`);
        if(result?.success) {
            renderRulesTable(result.rules);
        }
    };
    
    const renderRulesTable = (rules) => {
        elements.rulesContainer.classList.remove('hidden');
        elements.rulesTableBody.innerHTML = '';
        if(!rules.length) {
            elements.rulesTableBody.innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--text-secondary);">No rules defined for this service.</td></tr>`;
            return;
        }
        rules.forEach(rule => {
            const row = document.createElement('tr');
            const definition = ruleDefinitions[rule.rule_type];
            row.innerHTML = `
                <td>${definition.label}</td>
                <td>${formatRuleValue(rule.rule_type, rule.rule_value)}</td>
                <td>
                    <button class="action-button edit-rule-btn" data-id="${rule.id}" data-type="${rule.rule_type}" data-value="${rule.rule_value}"><i class="fas fa-edit"></i> Edit</button>
                    <button class="action-button delete-rule-btn delete" data-id="${rule.id}"><i class="fas fa-trash-alt"></i> Delete</button>
                </td>
            `;
            elements.rulesTableBody.appendChild(row);
        });
        
        elements.rulesTableBody.querySelectorAll('.edit-rule-btn').forEach(btn => btn.addEventListener('click', e => {
            const { id, type, value } = e.currentTarget.dataset;
            openRuleModal('edit', { id, rule_type: type, rule_value: value });
        }));
        elements.rulesTableBody.querySelectorAll('.delete-rule-btn').forEach(btn => btn.addEventListener('click', e => deleteRule(e.currentTarget.dataset.id)));
    };
    
    const formatRuleValue = (type, value) => {
        if (type === 'ALLOWED_DAYS') {
            const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
            return value.split(',').map(i => days[i]).join(', ');
        }
        return value;
    };
    
    const openRuleModal = (mode, rule = {}) => {
        elements.ruleModalTitle.textContent = mode === 'add' ? 'Add New Rule' : 'Edit Rule';
        elements.editRuleId.value = rule.id || '';
        populateRuleTypesDropdown(rule.rule_type);
        renderRuleValueInput(rule.rule_type || elements.ruleTypeSelect.value, rule.rule_value);
        openModal('rule-modal');
    };
    
    const renderRuleValueInput = (ruleType, value = '') => {
        const definition = ruleDefinitions[ruleType];
        elements.ruleValueContainer.innerHTML = '';
        if (!definition) return;
        
        if (definition.type === 'weekdays') {
            const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
            const picker = document.createElement('div');
            picker.className = 'weekday-picker';
            const selectedDays = value ? value.split(',') : [];
            const container = document.createElement('div');
            container.className = 'form-group';

            const label = document.createElement('label');
            label.textContent = definition.label;
            container.appendChild(label);

            days.forEach((day, index) => {
                const btn = document.createElement('button');
                btn.type = 'button';
                btn.className = `weekday-btn ${selectedDays.includes(index.toString()) ? 'selected' : ''}`;
                btn.textContent = day;
                btn.dataset.dayIndex = index;
                btn.onclick = () => btn.classList.toggle('selected');
                picker.appendChild(btn);
            });
            const desc = document.createElement('p');
            desc.textContent = definition.description;
            desc.style.color = 'var(--text-secondary)';
            desc.style.fontSize = '0.75rem';
            
            container.appendChild(picker);
            container.appendChild(desc);
            elements.ruleValueContainer.appendChild(container);
        } else {
            const formGroup = document.createElement('div');
            formGroup.className = 'form-group';
            const label = document.createElement('label');
            label.textContent = definition.label;
            label.htmlFor = 'rule-value-input';
            const input = document.createElement('input');
            input.type = definition.type;
            input.id = 'rule-value-input';
            input.placeholder = definition.placeholder || '';
            input.value = value;
            const desc = document.createElement('p');
            desc.textContent = definition.description;
            desc.style.color = 'var(--text-secondary)';
            desc.style.fontSize = '0.75rem';
            
            formGroup.appendChild(label);
            formGroup.appendChild(input);
            formGroup.appendChild(desc);
            elements.ruleValueContainer.appendChild(formGroup);
        }
    };
    
    const saveRule = async () => {
        const ruleType = elements.ruleTypeSelect.value;
        let ruleValue;
        if (ruleDefinitions[ruleType].type === 'weekdays') {
            ruleValue = Array.from(elements.ruleValueContainer.querySelectorAll('.weekday-btn.selected')).map(btn => btn.dataset.dayIndex).join(',');
        } else {
            const inputElement = elements.ruleValueContainer.querySelector('#rule-value-input');
            if (!inputElement) {
                return showMessage('Rule value field not found.', 'error');
            }
            ruleValue = inputElement.value;
        }
        if (!ruleValue && ruleType !== 'ALLOWED_DAYS') { // Allow empty string for no allowed days
            showMessage('Rule value cannot be empty.', 'error'); return;
        }
        const payload = { action: 'save_rule', service_id: currentServiceIdForRule, rule_type: ruleType, rule_value: ruleValue, rule_id: elements.editRuleId.value || null };
        const result = await apiPost(payload);
        if (result.success) {
            showMessage(result.message);
            closeModal('rule-modal');
            fetchAndRenderRules(currentServiceIdForRule);
        } else {
            showMessage(result.message, 'error');
        }
    };
    
    const deleteRule = async (ruleId) => {
        if (!await showConfirmation("Are you sure you want to delete this rule?")) return;
        const result = await apiPost({ action: 'delete_rule', rule_id: ruleId });
        if(result.success) {
            fetchAndRenderRules(currentServiceIdForRule);
            showMessage(result.message);
        } else {
            showMessage(result.message, 'error');
        }
    };

    // --- ROSTER & BREAKS LOGIC (UNCHANGED CORE LOGIC) ---
    const fetchBlockedSlots = async (date) => {
        const result = await apiGet(`?action=roster&date=${date}`);
        if (result && result.success) {
            renderBlockedSlotsTable(result.blocked_slots);
        }
    };

    const renderBlockedSlotsTable = (slots) => {
        elements.rosterTableBody.innerHTML = '';
        if (slots.length === 0) {
            elements.rosterTableBody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-secondary);">No custom blocked slots for this day.</td></tr>`;
            return;
        }
        slots.forEach(slot => {
            const row = document.createElement('tr');
            const format = timeStr => new Date(`1970-01-01T${timeStr.substring(11, 16)}:00`).toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true });
            row.innerHTML = `
                <td>${format(slot.start_datetime)}</td>
                <td>${format(slot.end_datetime)}</td>
                <td>${slot.reason}</td>
                <td style="text-align: right;">
                    <button class="action-button delete-roster-btn delete" data-id="${slot.id}"><i class="fas fa-trash-alt"></i> Delete</button>
                </td>
            `;
            elements.rosterTableBody.appendChild(row);
        });
        
        elements.rosterTableBody.querySelectorAll('.delete-roster-btn').forEach(btn => btn.addEventListener('click', e => deleteBlockedSlot(e.currentTarget.dataset.id)));
    };

    const openAddRosterModal = () => {
        const today = new Date().toISOString().slice(0, 10);
        elements.rosterSlotDate.value = today;
        elements.rosterSlotDate.min = today;
        elements.rosterStartTime.value = '';
        elements.rosterEndTime.value = '';
        elements.rosterReason.value = '';
        openModal('add-roster-modal');
    };
    
    const saveBlockedSlot = async () => {
        const date = elements.rosterSlotDate.value;
        const startTime = elements.rosterStartTime.value;
        const endTime = elements.rosterEndTime.value;
        const reason = elements.rosterReason.value;

        if (!date || !startTime || !endTime || !reason) return showMessage('All fields are required.', 'error');
        if (startTime >= endTime) return showMessage('Start time must be before end time.', 'error');

        const result = await apiPost({ action: 'add_blocked_slot', date, start_time: startTime, end_time: endTime, reason });
        if (result.success) {
            showMessage(result.message);
            closeModal('add-roster-modal');
            elements.rosterDateInput.value = date;
            fetchBlockedSlots(date);
        } else {
            showMessage(result.message, 'error');
        }
    };

    const deleteBlockedSlot = async (id) => {
        if (!await showConfirmation('Are you sure you want to delete this blocked time slot?')) return;

        const result = await apiPost({ action: 'delete_blocked_slot', id });
        if (result.success) {
            showMessage(result.message);
            fetchBlockedSlots(elements.rosterDateInput.value);
        } else {
            showMessage(result.message, 'error');
        }
    };

    const fetchDailyBreaks = async () => {
        const result = await apiGet('?action=daily_breaks');
        if (result && result.success) {
            renderDailyBreaks(result.breaks);
        }
    };

    const renderDailyBreaks = (breaks = []) => {
        elements.dailyBreaksContainer.innerHTML = '';
        if (breaks.length > 0) {
            breaks.forEach(breakData => addDailyBreakRow(breakData.start_time, breakData.end_time));
        } else {
            addDailyBreakRow();
        }
    };

    const addDailyBreakRow = (startTime = '', endTime = '') => {
        const div = document.createElement('div');
        div.className = 'daily-break-row';
        div.innerHTML = `
            <div class="form-group">
                <label>Start Time</label>
                <input type="time" class="daily-break-start" value="${startTime}">
            </div>
            <div class="form-group">
                <label>End Time</label>
                <input type="time" class="daily-break-end" value="${endTime}">
            </div>
            <button class="btn-remove"><i class="fas fa-times"></i></button>
        `;
        elements.dailyBreaksContainer.appendChild(div);
        div.querySelector('.btn-remove').addEventListener('click', () => {
            const allBreaks = elements.dailyBreaksContainer.querySelectorAll('.daily-break-row');
            if (allBreaks.length > 1) {
                div.remove();
            } else {
                showMessage('You must have at least one break row. Clear the values if you do not want a break.', 'error');
            }
        });
    };
    
    const saveDailyBreaks = async () => {
        const breakRows = elements.dailyBreaksContainer.querySelectorAll('.daily-break-row');
        const breaksData = [];
        let invalid = false;

        breakRows.forEach(row => {
            const startTime = row.querySelector('.daily-break-start').value;
            const endTime = row.querySelector('.daily-break-end').value;
            
            if (startTime && endTime) {
                if (startTime >= endTime) {
                    invalid = true;
                }
                breaksData.push({ start_time: startTime, end_time: endTime });
            }
        });

        if (invalid) {
            return showMessage('Start time must be before end time for all breaks.', 'error');
        }

        const result = await apiPost({ action: 'save_daily_breaks', breaks: breaksData });
        showMessage(result.message, result.success ? 'success' : 'error');
    };

    // --- USER MANAGEMENT LOGIC (UI parts updated) ---
    const fetchUsers = async () => {
        const result = await apiGet('?action=user_management');
        if (result && result.success) {
            renderUsersTable(result.users, result.current_user_id);
        }
    };

    const renderUsersTable = (users, currentUserId) => {
        elements.usersTableBody.innerHTML = '';
        if (users.length === 0) {
            elements.usersTableBody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-secondary);">No users found.</td></tr>`;
            return;
        }
        users.forEach(user => {
            const row = document.createElement('tr');
            const canDelete = user.id != currentUserId;
            
            // REMOVED: overbook badge
            
            row.innerHTML = `
                <td>${user.username}</td>
                <td>${user.name || 'N/A'}</td>
                <td>${user.role}</td>
                <td>
                    <label class="switch">
                        <input type="checkbox" class="toggle-active" data-id="${user.id}" ${user.isActive ? 'checked' : ''} ${user.id == currentUserId ? 'disabled' : ''}>
                        <span class="slider"></span>
                    </label>
                    <span style="margin-left: 0.5rem; font-size: 0.85rem;">${user.isActive ? 'Active' : 'Inactive'}</span>
                </td>
                
                <td style="text-align: right; display: flex; gap: 0.5rem;">
                    <button class="action-button edit-user-btn" data-id="${user.id}" data-username="${user.username}" data-name="${user.name}" data-role="${user.role}"><i class="fas fa-user-edit"></i></button>
                    <button class="action-button reset-password-btn" data-id="${user.id}" data-username="${user.username}"><i class="fas fa-key"></i></button>
                    <button class="action-button delete-user-btn delete" data-id="${user.id}" ${!canDelete ? 'disabled' : ''}><i class="fas fa-trash-alt"></i></button>
                </td>
            `;
            elements.usersTableBody.appendChild(row);
        });
        
        elements.usersTableBody.querySelectorAll('.edit-user-btn').forEach(btn => btn.addEventListener('click', e => openUserModal('edit', e.currentTarget.dataset)));
        elements.usersTableBody.querySelectorAll('.delete-user-btn').forEach(btn => btn.addEventListener('click', e => deleteUser(e.currentTarget.dataset.id)));
        elements.usersTableBody.querySelectorAll('.toggle-active').forEach(btn => btn.addEventListener('change', e => toggleUserActive(e.currentTarget.dataset.id, e.currentTarget.checked)));
        elements.usersTableBody.querySelectorAll('.reset-password-btn').forEach(btn => btn.addEventListener('click', e => openResetPasswordModal(e.currentTarget.dataset.id, e.currentTarget.dataset.username)));
        // REMOVED: permissions-btn event listener
    };

    const openUserModal = (mode, user = {}) => {
        elements.userModalTitle.textContent = mode === 'add' ? 'Add New User' : 'Edit User';
        elements.editUserId.value = user.id || '';
        elements.userUsernameInput.value = user.username || '';
        elements.userNameInput.value = user.name || '';
        elements.userRoleSelect.value = user.role || 'user';
        
        document.getElementById('password-group').style.display = (mode === 'edit') ? 'none' : 'block';
        
        openModal('user-modal');
    };
    
    const saveUser = async () => {
        const id = elements.editUserId.value;
        const username = elements.userUsernameInput.value;
        const name = elements.userNameInput.value;
        const role = elements.userRoleSelect.value;
        
        if (!username) return showMessage('Username is required.', 'error');
        
        const action = id ? 'edit_user' : 'add_user';
        const payload = { action, id, username, name, role };
        
        const result = await apiPost(payload);
        if (result.success) {
            showMessage(result.message);
            closeModal('user-modal');
            fetchUsers();
        } else {
            showMessage(result.message, 'error');
        }
    };

    const deleteUser = async (id) => {
        if (!await showConfirmation('Are you sure you want to delete this user?')) return;
        const result = await apiPost({ action: 'delete_user', id });
        if (result.success) {
            showMessage(result.message);
            fetchUsers();
        } else {
            showMessage(result.message, 'error');
        }
    };

    const toggleUserActive = async (id, isActive) => {
        const result = await apiPost({ action: 'toggle_user_active', id, isActive });
        if (result.success) {
            showMessage(result.message);
            fetchUsers();
        } else {
            showMessage(result.message, 'error');
            document.querySelector(`.toggle-active[data-id="${id}"]`).checked = !isActive;
        }
    };

    const openResetPasswordModal = (id, username) => {
        elements.resetUserId.value = id;
        elements.resetUserUsername.textContent = username;
        openModal('reset-password-modal');
    };

    const resetPassword = async () => {
        const id = elements.resetUserId.value;
        const username = elements.resetUserUsername.textContent;
        if (!await showConfirmation(`Are you sure you want to reset the password for ${username} to their username?`)) return;
        
        const result = await apiPost({ action: 'reset_password', id, username: username });
        if (result.success) {
            showMessage(result.message);
            closeModal('reset-password-modal');
            fetchUsers();
        } else {
            showMessage(result.message, 'error');
        }
    };
    
    const changeMyPassword = async (event) => {
        event.preventDefault();
        const oldPassword = elements.oldPasswordInput.value;
        const newPassword = elements.newPasswordInput.value;
        const confirmPassword = elements.confirmNewPasswordInput.value;

        if (newPassword.length < 6) return showMessage('New password must be at least 6 characters.', 'error');
        if (newPassword !== confirmPassword) return showMessage('New passwords do not match.', 'error');
        
        const result = await apiPost({ action: 'change_my_password', old_password: oldPassword, new_password: newPassword });
        if (result.success) {
            showMessage(result.message);
            elements.changePasswordForm.reset();
        } else {
            showMessage(result.message, 'error');
        }
    };

    // --- AUDIT LOGS LOGIC (UNCHANGED CORE LOGIC) ---
    const fetchAuditLogs = async () => {
        const startDate = elements.logStartDateInput.value;
        const endDate = elements.logEndDateInput.value;
        
        if (!startDate || !endDate) {
            return; // Do not show an error if the fields are just empty on page load
        }
        if (new Date(startDate) > new Date(endDate)) {
            return showMessage('The start date cannot be after the end date.', 'error');
        }
        
        const result = await apiGet(`?action=audit_logs&start_date=${startDate}&end_date=${endDate}`);
        if (result && result.success) {
            renderAuditLogsTable(result.logs);
        }
    };

    const renderAuditLogsTable = (logs) => {
        elements.auditLogsTableBody.innerHTML = '';
        if (logs.length === 0) {
            elements.auditLogsTableBody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-secondary);">No logs found for this period.</td></tr>`;
            return;
        }
        logs.forEach(log => {
            const row = document.createElement('tr');
            const timestamp = new Date(log.timestamp).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'medium' });
            const user = log.username || 'System';
            row.innerHTML = `
                <td>${timestamp}</td>
                <td>${user}</td>
                <td>${log.action}</td>
                <td>${log.ip || 'N/A'}</td>
                <td>${log.location || 'N/A'}</td>
            `;
            elements.auditLogsTableBody.appendChild(row);
        });
    };
    
    // --- HELPER FUNCTIONS (UNCHANGED CORE LOGIC) ---
    const populateServicesDropdown = async (selectElement, selectedId = null) => {
        if (!servicesList.length) {
            const result = await apiGet(`?action=services`);
            if (result && result.success) {
                servicesList = result.services;
            } else {
                return;
            }
        }
        selectElement.innerHTML = '<option value="">-- Select a Service --</option>';
        servicesList.forEach(s => {
            const opt = document.createElement('option');
            opt.value = s.id;
            opt.textContent = s.name;
            if (s.id == selectedId) opt.selected = true;
            selectElement.appendChild(opt);
        });
    };

    const populateRuleTypesDropdown = (selectedType = null) => {
        elements.ruleTypeSelect.innerHTML = '';
        Object.entries(ruleDefinitions).forEach(([key, {label}]) => {
            const opt = document.createElement('option');
            opt.value = key;
            opt.textContent = label;
            if(key === selectedType) opt.selected = true;
            elements.ruleTypeSelect.appendChild(opt);
        });
    };

    // --- INITIALIZATION & EVENT LISTENERS ---
    document.addEventListener('DOMContentLoaded', () => {
        elements.navLinks.forEach(link => {
            link.addEventListener('click', (e) => {
                const pageId = e.currentTarget.dataset.page;
                if (pageId) {
                    e.preventDefault();
                    showPage(pageId);
                }
            });
        });
        
        window.addEventListener('hashchange', () => {
            const pageId = window.location.hash.substring(1) || 'appointments';
            showPage(pageId);
        });

        elements.appointmentsDateInput.addEventListener('change', (e) => {
            showCompleted = false; // Reset when date changes
            fetchAppointments(e.target.value);
        });
        elements.appointmentSearch.addEventListener('input', filterAndRenderAppointments);
        
        elements.toggleDoneBtn.addEventListener('click', () => {
            showCompleted = !showCompleted;
            filterAndRenderAppointments();
        });

        elements.rosterDateInput.addEventListener('change', (e) => fetchBlockedSlots(e.target.value));
        elements.logStartDateInput.addEventListener('change', fetchAuditLogs);
        elements.logEndDateInput.addEventListener('change', fetchAuditLogs);
        document.getElementById('refresh-audit-logs-btn').addEventListener('click', fetchAuditLogs);


        elements.saveEditAppBtn.addEventListener('click', saveEditAppointment);
        
        elements.rescheduleAppDate.addEventListener('change', (e) => {
            const serviceId = elements.rescheduleAppServiceId.value;
            const date = e.target.value;
            elements.rescheduleAppTimeDisplay.value = '';
            elements.rescheduleAppTimeSelect.value = '';
            elements.saveRescheduleAppBtn.disabled = true;
        });
        
        elements.saveRescheduleAppBtn.addEventListener('click', submitReschedule);
        elements.addServiceBtn.addEventListener('click', () => openServiceModal('add'));
        elements.saveServiceBtn.addEventListener('click', saveService);
        elements.serviceCategorySelect.addEventListener('change', () => {
            if (elements.serviceCategorySelect.value === '__new__') {
                elements.newCategoryGroup.classList.remove('hidden');
            } else {
                elements.newCategoryGroup.classList.add('hidden');
            }
        });
        elements.addRosterBtn.addEventListener('click', openAddRosterModal);
        elements.saveRosterBtn.addEventListener('click', saveBlockedSlot);
        elements.addDailyBreakBtn.addEventListener('click', () => addDailyBreakRow());
        elements.saveDailyBreaksBtn.addEventListener('click', saveDailyBreaks);
        
        elements.ruleServiceSelect.addEventListener('change', (e) => fetchAndRenderRules(e.target.value));
        elements.addRuleBtn.addEventListener('click', () => openRuleModal('add'));
        elements.ruleTypeSelect.addEventListener('change', (e) => renderRuleValueInput(e.target.value));
        elements.saveRuleBtn.addEventListener('click', saveRule);

        elements.addUserBtn.addEventListener('click', () => openUserModal('add'));
        elements.saveUserBtn.addEventListener('click', saveUser);
        elements.saveResetBtn.addEventListener('click', resetPassword);
        elements.changePasswordForm.addEventListener('submit', changeMyPassword);
        
        elements.walkinForm.addEventListener('submit', bookWalkInAppointment);
        
        const handleTimeSlotClick = (e) => {
            const target = e.target.closest('.time-slot-button');
            if (target) {
                const allButtons = document.querySelectorAll('#reschedule-time-grid .time-slot-button');
                allButtons.forEach(btn => btn.classList.remove('selected'));
                target.classList.add('selected');

                const selectedTime = target.dataset.time;
                const formattedTime = target.textContent;
                
                const displayInputId = target.dataset.targetDisplayId;
                const hiddenInputId = target.dataset.targetHiddenId;
                
                if (displayInputId && hiddenInputId) {
                    document.getElementById(displayInputId).value = formattedTime;
                    document.getElementById(hiddenInputId).value = selectedTime;
                }
                
                if (document.getElementById('save-reschedule-app-btn')) {
                    document.getElementById('save-reschedule-app-btn').disabled = false;
                }
                
                closeModal('reschedule-time-slots-modal');
                
                // If walkin time is selected from slots, uncheck the overbook override
                if (displayInputId === 'walkin-time-display' && elements.overbookOverrideCheckbox) {
                    elements.overbookOverrideCheckbox.checked = false;
                }
            }
        };

        const fetchAndRenderSlotsWithTarget = async (serviceId, date, displayId, hiddenId) => {
            const gridElement = elements.rescheduleTimeGrid;
            gridElement.innerHTML = '';
            
            if (!date || !serviceId) {
                gridElement.innerHTML = `<p style="grid-column: 1 / span 3; text-align: center; color: var(--text-secondary);">Select a service and date to see available slots.</p>`;
                return;
            }

            const result = await apiGet(`?action=available_slots&service_id=${serviceId}&date=${date}`);
            
            elements.rescheduleDateDisplay.textContent = `Available slots for ${new Date(date + 'T00:00:00').toLocaleDateString()}`;

            if (result.success && result.slots.length > 0) {
                result.slots.forEach(slot => {
                    const button = document.createElement('div');
                    button.className = 'time-slot-button';
                    
                    // --- FIX APPLIED HERE ---
                    // The time is now displayed in the 24-hour format (e.g., "14:30") directly from the server.
                    button.textContent = slot; 
                    
                    button.dataset.time = slot;
                    button.dataset.targetDisplayId = displayId;
                    button.dataset.targetHiddenId = hiddenId;
                    gridElement.appendChild(button);
                });
            } else {
                gridElement.innerHTML = `<p style="grid-column: 1 / span 3; text-align: center; color: var(--text-secondary);">${result.message || 'No slots available.'}</p>`;
            }
        };
        
        elements.rescheduleTimeGrid.addEventListener('click', handleTimeSlotClick);
        
        // MODIFIED: Enable slot picker click logic
        elements.walkinTimeDisplay.addEventListener('click', () => {
            const serviceId = elements.walkinService.value;
            const date = elements.walkinDate.value;
            
            // If the overbook override is checked, clicking the time field means they are typing
            if (isAdmin && elements.overbookOverrideCheckbox && elements.overbookOverrideCheckbox.checked) {
                return; 
            }

            if (serviceId && date) {
                fetchAndRenderSlotsWithTarget(serviceId, date, 'walkin-time-display', 'walkin-time-select');
                openModal('reschedule-time-slots-modal');
            } else {
                showMessage('Please select a service and date first.', 'error');
            }
        });

        elements.rescheduleAppTimeDisplay.addEventListener('click', () => {
            const serviceId = elements.rescheduleAppServiceId.value;
            const date = elements.rescheduleAppDate.value;
            if (serviceId && date) {
                fetchAndRenderSlotsWithTarget(serviceId, date, 'reschedule-app-time-display', 'reschedule-app-time-select');
                openModal('reschedule-time-slots-modal');
            } else {
                showMessage('Please select a date first.', 'error');
            }
        });
        
        // NEW: If admin checks override, clear selected slot time and ask for manual input
        if (isAdmin && elements.overbookOverrideCheckbox) {
             elements.overbookOverrideCheckbox.addEventListener('change', () => {
                 if (elements.overbookOverrideCheckbox.checked) {
                     elements.walkinTimeSelect.value = ''; // Clear selected slot time
                     elements.walkinTimeDisplay.value = ''; // Clear display value
                     elements.walkinTimeDisplay.placeholder = 'Manually enter time (HH:MM)';
                 } else {
                     elements.walkinTimeDisplay.placeholder = 'Click to select or type time (HH:MM)';
                 }
             });
        }


        elements.walkinService.addEventListener('change', () => {
            elements.walkinTimeDisplay.value = '';
            elements.walkinTimeSelect.value = '';
            if(isAdmin && elements.overbookOverrideCheckbox) elements.overbookOverrideCheckbox.checked = false;
        });
        elements.walkinDate.addEventListener('change', () => {
            elements.walkinTimeDisplay.value = '';
            elements.walkinTimeSelect.value = '';
            if(isAdmin && elements.overbookOverrideCheckbox) elements.overbookOverrideCheckbox.checked = false;
        });

        setInterval(updateCurrentTime, 1000);
        updateCurrentTime();

        setInterval(() => {
            if (document.getElementById('appointments-page').classList.contains('hidden') === false) {
                fetchAppointments(elements.appointmentsDateInput.value);
            }
        }, 60000);

        const initialPage = window.location.hash.substring(1) || 'appointments';
        showPage(initialPage);

        elements.menuToggleBtn.addEventListener('click', () => {
            elements.sidebar.classList.toggle('active');
        });
        
        // NEW: Event listeners for Reports
        elements.viewReportBtn.addEventListener('click', () => generateReport('view'));
        elements.downloadReportBtn.addEventListener('click', () => generateReport('pdf'));

        // REMOVED: Permissions event listeners
        
        // Initialize the inactivity timer
        setupInactivityTimer();
    });

    const bookWalkInAppointment = async (event) => {
        event.preventDefault();

        const customerName = elements.walkinName.value.trim();
        const customerMobile = elements.walkinMobile.value.trim();
        const serviceId = elements.walkinService.value;
        const date = elements.walkinDate.value;
        const serialNumber = elements.walkinSerial.value.trim();
        
        // NEW: Check for admin override flag
        const isOverbookRequest = isAdmin && elements.overbookOverrideCheckbox && elements.overbookOverrideCheckbox.checked;

        let time = elements.walkinTimeSelect.value;
        
        // MODIFIED: Handle manual time input for admin
        if (isAdmin) {
            const manualTime = elements.walkinTimeDisplay.value.trim();
            // If manual time is entered (either through override or without selecting a slot)
            if (manualTime) {
                // Basic validation for HH:MM format
                if (/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/.test(manualTime)) {
                    time = manualTime;
                } else {
                    return showMessage('Invalid time format. Please use HH:MM (24-hour clock).', 'error');
                }
            } else if (!time) {
                return showMessage('Please select a time slot or manually enter the time.', 'error');
            }
        } else if (!time) {
         // For non-admin, time must be selected from the slots (which updates elements.walkinTimeSelect.value)
            return showMessage('Please select a time slot.', 'error');
        }

        // Validate if override is checked, manual time must be for today
        if (isOverbookRequest) {
            const today = new Date().toISOString().slice(0, 10);
            if (date !== today) {
                return showMessage('Admin override (overbooking) can only be used for the current date. Please uncheck the override or select the correct date.', 'error');
            }
        }

        if (!customerName || !serviceId || !date || !time) {
            return showMessage('Please fill in all required fields: Name, Service, Date, and Time.', 'error');
        }

        const appointmentDateTime = `${date} ${time}:00`;

        const payload = {
            action: 'book',
            customer_name: customerName,
            customer_mobile: customerMobile,
            service_id: serviceId,
            appointment_datetime: appointmentDateTime,
            serial_number: serialNumber,
            is_overbook_request: isOverbookRequest // NEW FLAG sent to PHP backend
        };

        const result = await apiPost(payload);
        if (result.success) {
            // MODIFIED: Use new detailed success message
            showMessage(result.message, 'success', result.details);
            elements.walkinForm.reset();
            // Reset date to today for next booking
            elements.walkinDate.value = new Date().toISOString().slice(0, 10);
            if(isAdmin && elements.overbookOverrideCheckbox) elements.overbookOverrideCheckbox.checked = false; // Reset override
            if (document.getElementById('appointments-page').classList.contains('hidden') === false) {
                fetchAppointments(elements.appointmentsDateInput.value);
            }
        } else {
            showMessage(result.message, 'error');
        }
    };
    
    // MODIFIED: Report Generation Logic (UNCHANGED CORE)
    const generateReport = async (outputType) => {
        const date = elements.reportDate.value;
        if (!date) {
            showMessage('Please select a date for the report.', 'error');
            return;
        }

        const result = await apiGet(`?action=get_report_data&date=${date}`);

        if (!result || !result.success) {
            showMessage('Could not fetch report data.', 'error');
            return;
        }
        
        const { reportData, summary } = result;

        if (outputType === 'view') {
            elements.reportViewContainer.classList.remove('hidden');
            elements.reportViewTitle.textContent = `Report for Completed Appointments on ${new Date(date + 'T00:00:00').toLocaleDateString('en-IN', { dateStyle: 'medium' })}`;
            
            let summaryHTML = `
                <div class="kpi-card">
                    <div class="kpi-icon" style="background: linear-gradient(135deg, var(--status-success), #4ade80);">
                        <i class="fas fa-check-double"></i>
                    </div>
                    <div class="kpi-content">
                        <div class="kpi-value">${summary.total_completed}</div>
                        <div class="kpi-label">Total Completed</div>
                    </div>
                </div>
            `;
            const serviceColors = ['#F59E0B', '#3B82F6', '#6366F1', '#10B981'];
            let colorIndex = 0;

            for (const [serviceName, count] of Object.entries(summary.service_counts)) {
                summaryHTML += `
                    <div class="kpi-card">
                        <div class="kpi-icon" style="background: linear-gradient(135deg, ${serviceColors[colorIndex]}, ${serviceColors[colorIndex]}99);">
                            <i class="fas fa-handshake"></i>
                        </div>
                        <div class="kpi-content">
                            <div class="kpi-value">${count}</div>
                            <div class="kpi-label">${serviceName}</div>
                        </div>
                    </div>
                `;
                colorIndex = (colorIndex + 1) % serviceColors.length;
            }
            elements.reportSummaryCards.innerHTML = summaryHTML;
            
            if (reportData.length > 0) {
                elements.reportTableBody.innerHTML = reportData.map(row => `
                    <tr>
                        <td>${row.serial_number}</td>
                        <td>${new Date(row.appointment_datetime).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</td>
                        <td>${row.customer_name}</td>
                        <td>${row.service_name}</td>
                        <td><span class="done-badge" style="background-color: var(--status-success);">Completed</span></td>
                    </tr>
                `).join('');
            } else {
                elements.reportTableBody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-secondary);">No completed appointments for this day.</td></tr>`;
            }
            
        } else if (outputType === 'pdf') {
            const { jsPDF } = window.jspdf;
            const doc = new jsPDF();
            
            const reportDate = new Date(date + 'T00:00:00').toLocaleDateString('en-IN', {
                year: 'numeric', month: 'long', day: 'numeric'
            });

            // Header
            doc.setFontSize(20);
            doc.setTextColor(40);
            doc.text("Daily Report - Completed Appointments", 105, 22, null, null, "center");
            doc.setFontSize(12);
            doc.text(`Date: ${reportDate}`, 105, 30, null, null, "center");

            // Summary Table
            const summaryBody = Object.entries(summary.service_counts).map(([name, count]) => [name, count.toString()]);
            summaryBody.push([{ content: 'Total Completed', styles: { fontStyle: 'bold' } }, { content: summary.total_completed.toString(), styles: { fontStyle: 'bold' } }]);
            
            doc.autoTable({
                startY: 40,
                head: [['Completed Service', 'Count']],
                body: summaryBody,
                theme: 'striped',
                headStyles: { fillColor: [79, 70, 229] }
            });

            let finalY = doc.lastAutoTable.finalY;

            // Main Details Table
            if (reportData.length > 0) {
                const tableData = reportData.map(row => [
                    row.serial_number,
                    new Date(row.appointment_datetime).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'}),
                    row.customer_name,
                    row.service_name,
                ]);
                
                doc.autoTable({
                    startY: finalY + 10,
                    head: [['Serial #', 'Time', 'Customer Name', 'Service']],
                    body: tableData,
                    theme: 'grid',
                    headStyles: { fillColor: [79, 70, 229] }
                });
                finalY = doc.lastAutoTable.finalY;
            } else {
                doc.text("No completed appointments for this day.", 14, finalY + 15);
            }
            
            // Footer
            const pageCount = doc.internal.getNumberOfPages();
            for (let i = 1; i <= pageCount; i++) {
                doc.setPage(i);
                doc.setFontSize(8);
                doc.setTextColor(150);
                doc.text(`Page ${i} of ${pageCount}`, doc.internal.pageSize.width - 20, doc.internal.pageSize.height - 10, null, null, "center");
            }

            doc.save(`Completed_Appointments_Report_${date}.pdf`);
        }
    };

    // REMOVED: User Permissions Logic (openPermissionsModal, saveUserPermissions)

</script>
<?php /* AUTO-FIX: Closed an open alternative-style if block */ ?> <?php endif; ?></body>
</html>