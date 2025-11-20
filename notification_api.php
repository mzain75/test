<?php
require_once $_SERVER['DOCUMENT_ROOT'] . '/config.php';
require_once DB_PATH;

// Strict error reporting and security settings
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);

header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');

// Centralized error response function
function sendErrorResponse($statusCode, $message)
{
    http_response_code($statusCode);
    echo json_encode(['error' => $message]);
    exit;
}

// Helper function to generate secure tokens
function generateToken($length = 32)
{
    return bin2hex(random_bytes($length));
}

// Validate input function
function validateInput($input, $rules = [])
{
    $errors = [];

    foreach ($rules as $field => $rule) {
        // Check if the field exists in the input
        if (!array_key_exists($field, $input)) {
            if ($rule['required']) {
                $errors[] = "Missing required field: $field";
            }
            continue;
        }

        $value = $input[$field];

        // Check for required fields
        if ($rule['required'] && ($value === null || $value === '')) {
            $errors[] = "Missing required field: $field";
            continue;
        }

        // Additional validation for non-empty values
        if ($value !== null && $value !== '') {
            if (isset($rule['email']) && !filter_var($value, FILTER_VALIDATE_EMAIL)) {
                $errors[] = "Invalid email format for $field";
            }

            if (isset($rule['min_length']) && strlen($value) < $rule['min_length']) {
                $errors[] = "$field must be at least {$rule['min_length']} characters long";
            }
        }
    }

    return $errors;
}

// Main request handling
try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        sendErrorResponse(405, 'Method Not Allowed');
    }

    // Initialize input variable
    $input = [];

    // Check the Content-Type of the request
    if (strpos($_SERVER['CONTENT_TYPE'], 'application/json') === 0) {
        // Handle JSON requests
        $jsonInput = file_get_contents('php://input');
        $input = json_decode($jsonInput, true);
        if ($input === null) {
            sendErrorResponse(400, 'Invalid JSON');
        }
    } elseif (strpos($_SERVER['CONTENT_TYPE'], 'multipart/form-data') === 0) {
        // Handle form data (multipart/form-data)
        $input = $_POST;
    } else {
        sendErrorResponse(400, 'Unsupported Content-Type');
    }

    // Extract action
    $action = $input['action'] ?? '';

    /////////////////////////Get Token///////////////////////////

    function getUserFromToken($pdo, $token)
    {
        $stmt = $pdo->prepare("SELECT id, uid, area_id FROM users WHERE token = ? AND token_expiry > NOW()");
        $stmt->execute([$token]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            sendErrorResponse(401, 'Invalid or expired token');
        }

        return $user;
    }

    ///////////////////////////////////////////////////////

    // 1. Send FCM and Save Notification
    // Function to send FCM notification
    function sendFCMNotification($data)
    {
        $fcmEndpoint = 'https://my.insightguard.co.za/API/send_fcm.php';

        $ch = curl_init($fcmEndpoint);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200) {
            error_log("FCM API Error. Response: " . $response);
            throw new Exception("Failed to send FCM notification");
        }

        return json_decode($response, true);
    }

    // 1. Send FCM and Save Notification
    if ($action === 'send_notification') {
        try {
            $pdo = getDbConnection();

            // Validate input
            if (empty($input['topic']) || empty($input['title']) || empty($input['body'])) {
                sendErrorResponse(400, 'Missing required fields: topic, title, and body are required');
            }

            // Get user from token
            $headers = getallheaders();
            $authHeader = $headers['Authorization'] ?? '';
            if (empty($authHeader) || !preg_match('/^Bearer\s+(.*)$/', $authHeader, $matches)) {
                sendErrorResponse(401, 'Missing or invalid Authorization header');
            }

            $token = $matches[1];
            $user = getUserFromToken($pdo, $token);
            $area_id = $user['area_id'];

            // Convert all data values to strings as required by FCM
            $fcmDataPayload = [];
            if (!empty($input['data'])) {
                foreach ($input['data'] as $key => $value) {
                    if (is_array($value) || is_object($value)) {
                        $fcmDataPayload[$key] = json_encode($value);
                    } else {
                        $fcmDataPayload[$key] = (string)$value; // Convert to string
                    }
                }
            }

            // Prepare FCM data with proper structure
            $fcmData = [
                'topic'        => $input['topic'],
                'notification' => [
                    'title' => $input['title'],
                    'body'  => $input['body']
                ],
                'data'         => $fcmDataPayload
            ];

            // Send FCM notification
            $fcmResponse = sendFCMNotification($fcmData);

            // Save notification to database
            $pdo->beginTransaction();

            try {
                // Insert into notifications table
                $stmt = $pdo->prepare("
                    INSERT INTO notifications
                    (title, body, data, type, target_type, is_deleted, created_at)
                    VALUES (?, ?, ?, ?, ?, 0, NOW())
                ");
                $stmt->execute([
                    $input['title'],
                    $input['body'],
                    json_encode($input['data']),
                    $input['type'] ?? 'fcm',          // Use provided type or default to 'fcm'
                    $input['target_type'] ?? 'specific' // Default target type is 'specific'
                ]);

                $notificationId = $pdo->lastInsertId();

                // Insert into user_notifications for all users whose area_id matches.
                $sql = "
                    INSERT INTO user_notifications (user_uid, area_id, notification_id, is_read, created_at)
                    SELECT uid, area_id, ?, 0, NOW()
                    FROM users
                    WHERE area_id = ?
                ";
                $stmt = $pdo->prepare($sql);
                $stmt->execute([
                    $notificationId,
                    $area_id
                ]);

                $pdo->commit();

                // Send success response
                http_response_code(200);
                echo json_encode([
                    'success'         => true,
                    'notification_id' => $notificationId,
                    'fcm_response'    => $fcmResponse,
                    'message'         => 'Notification sent and saved successfully'
                ]);
                exit;

            } catch (PDOException $e) {
                $pdo->rollBack();
                error_log("Database error in send_notification: " . $e->getMessage());
                sendErrorResponse(500, 'Database error while saving notification');
            }

        } catch (Exception $e) {
            error_log("Send notification error: " . $e->getMessage());
            sendErrorResponse(500, 'Error sending notification: ' . $e->getMessage());
        }
    }


    // 2. Mark Single Notification as Read
    if ($action === 'mark_notification_read') {
        try {
            $pdo = getDbConnection();

            if (empty($input['notification_id'])) {
                sendErrorResponse(400, 'notification_id is required');
            }

            // Get user from token
            $headers = getallheaders();
            $authHeader = $headers['Authorization'] ?? '';

            if (empty($authHeader) || !preg_match('/^Bearer\s+(.*)$/', $authHeader, $matches)) {
                sendErrorResponse(401, 'Missing or invalid Authorization header');
            }

            $token = $matches[1];
            $user = getUserFromToken($pdo, $token);

            // Update notification status - added area_id check
            $stmt = $pdo->prepare("
                UPDATE user_notifications
                SET is_read = 1, read_at = NOW()
                WHERE notification_id = ? AND user_uid = ? AND area_id = ? AND is_read = 0
            ");

            $stmt->execute([$input['notification_id'], $user['uid'], $user['area_id']]);

            http_response_code(200);
            echo json_encode([
                'success' => true,
                'message' => 'Notification marked as read'
            ]);
            exit;
        } catch (Exception $e) {
            error_log("Mark notification read error: " . $e->getMessage());
            sendErrorResponse(500, 'Error marking notification as read');
        }
    }

    // 3. Mark All Notifications as Read
    if ($action === 'mark_all_notifications_read') {
        try {
            $pdo = getDbConnection();

            // Get user from token
            $headers = getallheaders();
            $authHeader = $headers['Authorization'] ?? '';

            if (empty($authHeader) || !preg_match('/^Bearer\s+(.*)$/', $authHeader, $matches)) {
                sendErrorResponse(401, 'Missing or invalid Authorization header');
            }

            $token = $matches[1];
            $user = getUserFromToken($pdo, $token);

            // Update all unread notifications - added area_id check
            $stmt = $pdo->prepare("
                UPDATE user_notifications
                SET is_read = 1, read_at = NOW()
                WHERE user_uid = ? AND area_id = ? AND is_read = 0
            ");

            $stmt->execute([$user['uid'], $user['area_id']]);

            http_response_code(200);
            echo json_encode([
                'success' => true,
                'updated_count' => $stmt->rowCount(),
                'message' => 'All notifications marked as read'
            ]);
            exit;
        } catch (Exception $e) {
            error_log("Mark all notifications read error: " . $e->getMessage());
            sendErrorResponse(500, 'Error marking all notifications as read');
        }
    }

    // 4. Get Notification List
    if ($action === 'get_notifications') {
        try {
            $pdo = getDbConnection();
            // Verify database connection
            if (!$pdo) {
                throw new Exception("Database connection failed");
            }
            // Get user from token
            $headers = getallheaders();
            $authHeader = $headers['Authorization'] ?? '';
            if (empty($authHeader) || !preg_match('/^Bearer\s+(.*)$/', $authHeader, $matches)) {
                throw new Exception("Missing or invalid Authorization header");
            }
            $token = $matches[1];
            $user = getUserFromToken($pdo, $token);
            // Verify user
            if (!$user || empty($user['uid'])) {
                throw new Exception("User not found or unauthorized");
            }
            // Get pagination parameters
            $page = isset($input['page']) ? max(1, intval($input['page'])) : 1;
            $limit = isset($input['limit']) ? max(1, min(100, intval($input['limit']))) : 20;
            $offset = ($page - 1) * $limit;

            // Get type filter parameter
            $types = [];
            if (isset($input['type']) && !empty($input['type'])) {
                if (is_array($input['type'])) {
                    // If multiple types are sent as array
                    $types = array_filter($input['type'], function($type) {
                        return !empty(trim($type));
                    });
                } else {
                    // If single type is sent as string
                    $types = [trim($input['type'])];
                }
            }

            // Build WHERE clause for type filter
            $typeWhereClause = "";
            $typeParams = [];
            if (!empty($types)) {
                $placeholders = str_repeat('?,', count($types) - 1) . '?';
                $typeWhereClause = " AND n.type IN ($placeholders)";
                $typeParams = $types;
            }

            // Get total count - modified to include type filter
            $countSql = "
                SELECT COUNT(*) as total
                FROM user_notifications un
                JOIN notifications n ON un.notification_id = n.notification_id
                WHERE un.user_uid = ? AND un.area_id = ? AND n.is_deleted = 0" . $typeWhereClause;

            $stmt = $pdo->prepare($countSql);
            $countParams = array_merge([$user['uid'], $user['area_id']], $typeParams);
            if (!$stmt->execute($countParams)) {
                throw new Exception("SQL Error: " . json_encode($stmt->errorInfo()));
            }
            $total = $stmt->fetch(PDO::FETCH_ASSOC)['total'];

            // Get notifications - modified to include type filter
            $notificationsSql = "
                SELECT
                    n.notification_id,
                    n.title,
                    n.body,
                    n.data,
                    n.type,
                    n.target_type,
                    n.created_at as notification_created_at,
                    un.is_read,
                    un.read_at,
                    un.area_id,
                    un.created_at as user_notification_created_at
                FROM user_notifications un
                JOIN notifications n ON un.notification_id = n.notification_id
                WHERE un.user_uid = ? AND un.area_id = ? AND n.is_deleted = 0" . $typeWhereClause . "
                ORDER BY un.created_at DESC
                LIMIT ? OFFSET ?";

            $stmt = $pdo->prepare($notificationsSql);

            // Prepare parameters for notifications query
            $notificationParams = array_merge([$user['uid'], $user['area_id']], $typeParams, [$limit, $offset]);

            // Bind parameters with explicit types
            $paramIndex = 1;
            $stmt->bindValue($paramIndex++, $user['uid'], PDO::PARAM_STR);
            $stmt->bindValue($paramIndex++, $user['area_id'], PDO::PARAM_INT);

            // Bind type parameters
            foreach ($typeParams as $type) {
                $stmt->bindValue($paramIndex++, $type, PDO::PARAM_STR);
            }

            $stmt->bindValue($paramIndex++, $limit, PDO::PARAM_INT);
            $stmt->bindValue($paramIndex++, $offset, PDO::PARAM_INT);

            if (!$stmt->execute()) {
                throw new Exception("SQL Error: " . json_encode($stmt->errorInfo()));
            }

            $notifications = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Process notifications
            foreach ($notifications as &$notification) {
                $notification['data'] = json_decode($notification['data'], true);
                $notification['is_read'] = (bool)$notification['is_read'];
                // Convert area_id to integer
                $notification['area_id'] = (int)$notification['area_id'];
            }

            $response = [
                'success' => true,
                'notifications' => $notifications,
                'pagination' => [
                    'total' => (int)$total,
                    'page' => $page,
                    'limit' => $limit,
                    'total_pages' => ceil($total / $limit)
                ],
                'filters' => [
                    'types' => $types // Return applied filters in response
                ]
            ];

            http_response_code(200);
            echo json_encode($response);
            exit;

        } catch (Exception $e) {
            error_log("Get notifications error: " . $e->getMessage() . "\nStack trace: " . $e->getTraceAsString());
            sendErrorResponse(500, 'Error retrieving notifications: ' . $e->getMessage());
        }
    }

    // 5. Get Notification Count
    if ($action === 'get_notification_count') {
        try {
            $pdo = getDbConnection();
            // Verify database connection
            if (!$pdo) {
                throw new Exception("Database connection failed");
            }

            // Get user from token
            $headers = getallheaders();
            $authHeader = $headers['Authorization'] ?? '';
            if (empty($authHeader) || !preg_match('/^Bearer\s+(.*)$/', $authHeader, $matches)) {
                throw new Exception("Missing or invalid Authorization header");
            }
            $token = $matches[1];
            $user = getUserFromToken($pdo, $token);

            // Verify user
            if (!$user || empty($user['uid'])) {
                throw new Exception("User not found or unauthorized");
            }

            // Get total count of all notifications
            $stmt = $pdo->prepare("
                SELECT COUNT(*) as total_count
                FROM user_notifications un
                JOIN notifications n ON un.notification_id = n.notification_id
                WHERE un.user_uid = ? AND un.area_id = ? AND n.is_deleted = 0
            ");
            if (!$stmt->execute([$user['uid'], $user['area_id']])) {
                throw new Exception("SQL Error: " . json_encode($stmt->errorInfo()));
            }
            $totalCount = $stmt->fetch(PDO::FETCH_ASSOC)['total_count'];

            // Get count by type
            $stmt = $pdo->prepare("
                SELECT
                    n.type,
                    COUNT(*) as count
                FROM user_notifications un
                JOIN notifications n ON un.notification_id = n.notification_id
                WHERE un.user_uid = ? AND un.area_id = ? AND n.is_deleted = 0
                GROUP BY n.type
                ORDER BY count DESC
            ");
            if (!$stmt->execute([$user['uid'], $user['area_id']])) {
                throw new Exception("SQL Error: " . json_encode($stmt->errorInfo()));
            }
            $countByType = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Get unread count of all notifications
            $stmt = $pdo->prepare("
                SELECT COUNT(*) as unread_count
                FROM user_notifications un
                JOIN notifications n ON un.notification_id = n.notification_id
                WHERE un.user_uid = ? AND un.area_id = ? AND n.is_deleted = 0 AND un.is_read = 0
            ");
            if (!$stmt->execute([$user['uid'], $user['area_id']])) {
                throw new Exception("SQL Error: " . json_encode($stmt->errorInfo()));
            }
            $totalUnreadCount = $stmt->fetch(PDO::FETCH_ASSOC)['unread_count'];

            // Get unread count by type
            $stmt = $pdo->prepare("
                SELECT
                    n.type,
                    COUNT(*) as unread_count
                FROM user_notifications un
                JOIN notifications n ON un.notification_id = n.notification_id
                WHERE un.user_uid = ? AND un.area_id = ? AND n.is_deleted = 0 AND un.is_read = 0
                GROUP BY n.type
                ORDER BY unread_count DESC
            ");
            if (!$stmt->execute([$user['uid'], $user['area_id']])) {
                throw new Exception("SQL Error: " . json_encode($stmt->errorInfo()));
            }
            $unreadCountByType = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Get read count by type
            $stmt = $pdo->prepare("
                SELECT
                    n.type,
                    COUNT(*) as read_count
                FROM user_notifications un
                JOIN notifications n ON un.notification_id = n.notification_id
                WHERE un.user_uid = ? AND un.area_id = ? AND n.is_deleted = 0 AND un.is_read = 1
                GROUP BY n.type
                ORDER BY read_count DESC
            ");
            if (!$stmt->execute([$user['uid'], $user['area_id']])) {
                throw new Exception("SQL Error: " . json_encode($stmt->errorInfo()));
            }
            $readCountByType = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Get last alert notification (type = "alert_report")
            $stmt = $pdo->prepare("
                SELECT
                    n.notification_id,
                    n.title,
                    n.body,
                    n.data,
                    n.type,
                    n.created_at,
                    n.target_type,
                    un.is_read,
                    un.read_at,
                    un.created_at as user_notification_created_at
                FROM user_notifications un
                JOIN notifications n ON un.notification_id = n.notification_id
                WHERE un.user_uid = ? AND un.area_id = ? AND n.is_deleted = 0 AND n.type = 'alert_report'
                ORDER BY n.created_at DESC
                LIMIT 1
            ");
            if (!$stmt->execute([$user['uid'], $user['area_id']])) {
                throw new Exception("SQL Error: " . json_encode($stmt->errorInfo()));
            }
            $lastAlertNotification = $stmt->fetch(PDO::FETCH_ASSOC);

            // Process data to create comprehensive count structure
            $typeStats = [];

            // Initialize with total counts
            foreach ($countByType as $row) {
                $typeStats[$row['type']] = [
                    'type' => $row['type'],
                    'total_count' => (int)$row['count'],
                    'unread_count' => 0,
                    'read_count' => 0
                ];
            }

            // Add unread counts
            foreach ($unreadCountByType as $row) {
                if (isset($typeStats[$row['type']])) {
                    $typeStats[$row['type']]['unread_count'] = (int)$row['unread_count'];
                }
            }

            // Add read counts
            foreach ($readCountByType as $row) {
                if (isset($typeStats[$row['type']])) {
                    $typeStats[$row['type']]['read_count'] = (int)$row['read_count'];
                }
            }

            // Convert to indexed array and sort by total count
            $typeStatsArray = array_values($typeStats);
            usort($typeStatsArray, function($a, $b) {
                return $b['total_count'] - $a['total_count'];
            });

            // Prepare last alert notification data
            $lastAlert = null;
            if ($lastAlertNotification) {
                $lastAlert = [
                    'notification_id' => (int)$lastAlertNotification['notification_id'],
                    'title' => $lastAlertNotification['title'],
                    'body' => $lastAlertNotification['body'],
                    'data' => $lastAlertNotification['data'],
                    'type' => $lastAlertNotification['type'],
                    'created_at' => $lastAlertNotification['created_at'],
                    'target_type' => $lastAlertNotification['target_type'],
                    'is_read' => (bool)$lastAlertNotification['is_read'],
                    'read_at' => $lastAlertNotification['read_at'],
                    'user_notification_created_at' => $lastAlertNotification['user_notification_created_at']
                ];
            }

            $response = [
                'success' => true,
                'summary' => [
                    'total_notifications' => (int)$totalCount,
                    'total_unread' => (int)$totalUnreadCount,
                    'total_read' => (int)$totalCount - (int)$totalUnreadCount,
                    'total_types' => count($typeStatsArray)
                ],
                'count_by_type' => $typeStatsArray,
                'last_alert_notification' => $lastAlert,
                'timestamp' => date('Y-m-d H:i:s')
            ];

            http_response_code(200);
            echo json_encode($response);
            exit;

        } catch (Exception $e) {
            error_log("Get notification count error: " . $e->getMessage() . "\nStack trace: " . $e->getTraceAsString());
            sendErrorResponse(500, 'Error retrieving notification count: ' . $e->getMessage());
        }
    }

    // If no valid action is found
    sendErrorResponse(400, 'Invalid action specified');
} catch (Exception $e) {
    error_log("API error: " . $e->getMessage());
    sendErrorResponse(500, 'Internal server error');
}
