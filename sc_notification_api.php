<?php
require_once $_SERVER['DOCUMENT_ROOT'] . '/config.php';
require_once DB_PATH;

// Strict error reporting and security settings
header("Access-Control-Allow-Origin: *"); // Allow all origins, adjust for production
header("Access-Control-Allow-Methods: POST, GET, OPTIONS"); // Allowed methods
header("Access-Control-Allow-Headers: Content-Type, Authorization"); // Add any custom headers if needed
header("Access-Control-Allow-Credentials: true"); // Allow credentials if required

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    // Respond to preflight requests with a 200 OK
    http_response_code(200);
    exit;
}

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

        if (isset($rule['type'])) {
            if ($rule['type'] === 'integer' && !is_numeric($value)) {
                $errors[] = "Field $field must be a valid integer";
                continue;
            }
            if ($rule['type'] === 'string' && !is_string($value)) {
                $errors[] = "Field $field must be a string";
                continue;
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

    function getAuthToken()
    {
        // Check for Authorization header
        $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['AUTHORIZATION'] ?? null;

        // If not found, check if it's in another format
        if (!$auth) {
            $headers = getallheaders();
            $auth = $headers['Authorization'] ?? $headers['authorization'] ?? null;
        }

        // Remove 'Bearer ' if present
        if ($auth && strpos(strtolower($auth), 'bearer ') === 0) {
            $auth = substr($auth, 7);
        }

        return $auth;
    }

    function verifyAdminToken($token)
    {
        try {
            $pdo = getDbConnection();

            $stmt = $pdo->prepare("
            SELECT id, access_token, token_expiry
            FROM security_company_users
            WHERE access_token = ?
        ");
            $stmt->execute([$token]);
            $admin = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$admin) {
                error_log("No security_company_user found with token: $token");
                return false;
            }

            if (strtotime($admin['token_expiry']) < time()) {
                error_log("Token expired for security_company_user ID: {$admin['id']}");
                return false;
            }

            return true;
        } catch (Exception $e) {
            error_log("Token verification error: " . $e->getMessage());
            return false;
        }
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

    ///////////////////////////////////////////////////////////////////
    // Get Areas for SC User
    if ($action === 'get_areas') {
        try {
            $adminToken = getAuthToken();
            if (!$adminToken) {
                sendErrorResponse(401, 'No authorization token provided');
            }
            if (!verifyAdminToken($adminToken)) {
                sendErrorResponse(401, 'Invalid or expired token');
            }

            $pdo = getDbConnection();

            // Get SC user's company ID
            $stmt = $pdo->prepare("
            SELECT security_company_id
            FROM security_company_users
            WHERE access_token = ?
        ");
            $stmt->execute([$adminToken]);
            $scUser = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$scUser || empty($scUser['security_company_id'])) {
                sendErrorResponse(403, 'No company assigned to this security company user');
            }

            $companyId = $scUser['security_company_id'];

            // Fetch areas assigned to this security company
            $stmt = $pdo->prepare("
            SELECT a.id as area_id, a.name as area_name
            FROM areas a
            INNER JOIN security_areas sa ON a.id = sa.area_id
            WHERE sa.company_id = ?
            ORDER BY a.name ASC
        ");
            $stmt->execute([$companyId]);
            $areas = $stmt->fetchAll(PDO::FETCH_ASSOC);

            http_response_code(200);
            echo json_encode([
                'success' => true,
                'data' => $areas,
                'count' => count($areas)
            ]);
            exit;
        } catch (Exception $e) {
            error_log("Get areas error: " . $e->getMessage());
            sendErrorResponse(500, 'Error fetching areas: ' . $e->getMessage());
        }
    }

    // 1. Send FCM and Save Notification
    if ($action === 'send_notification') {
        try {
            $adminToken = getAuthToken();
            if (!$adminToken) {
                error_log("No token found. Headers: " . print_r(getallheaders(), true));
                sendErrorResponse(401, 'No authorization token provided');
            }
            if (!verifyAdminToken($adminToken)) {
                error_log("Invalid token: $adminToken");
                sendErrorResponse(401, 'Invalid or expired token');
            }
            $pdo = getDbConnection();

            // Validate input
            if (empty($input['topic']) || empty($input['title']) || empty($input['body'])) {
                sendErrorResponse(400, 'Missing required fields: topic, title, and body are required');
            }

            // Convert all data values to strings as required by FCM
            // Skip title and body from data payload to avoid duplicate notifications
            $fcmDataPayload = [];
            if (!empty($input['data'])) {
                foreach ($input['data'] as $key => $value) {
                    // Skip title and body to avoid duplicate notifications
                    if ($key === 'title' || $key === 'body') {
                        continue;
                    }

                    if (is_array($value) || is_object($value)) {
                        $fcmDataPayload[$key] = json_encode($value);
                    } else {
                        $fcmDataPayload[$key] = (string)$value; // Convert to string
                    }
                }
            }

            // Prepare FCM data with proper structure (same as notification_api.php)
            $fcmData = [
                'topic'        => $input['topic'],
                'notification' => [
                    'title' => $input['title'],
                    'body'  => $input['body']
                ],
                'data'         => $fcmDataPayload  // All values now converted to strings (excluding title/body)
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
                    $input['type'] ?? 'fcm',  // Use provided type or default to 'fcm'
                    $input['target_type'] ?? 'specific'  // Default to 'specific' as topic is now dynamic
                ]);
                $notificationId = $pdo->lastInsertId();

                // Check if area_id is provided
                $areaId = $input['area_id'] ?? null;

                // Insert into user_notifications table
                $stmt = $pdo->prepare("
                INSERT INTO user_notifications
                (user_uid, notification_id, area_id, is_read, created_at)
                SELECT uid, ?, ?, 0, NOW()
                FROM users
                WHERE area_id = ?
            ");
                $stmt->execute([$notificationId, $areaId, $areaId]);

                $pdo->commit();

                // Send success response
                http_response_code(200);
                echo json_encode([
                    'success' => true,
                    'notification_id' => $notificationId,
                    'fcm_response' => $fcmResponse,
                    'message' => 'Notification sent and saved successfully'
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

    ///////////////////////////////////////////////////////////////////
    if ($action === 'upload_file') {
        try {
            $adminToken = getAuthToken();
            if (!$adminToken) {
                error_log("No token found. Headers: " . print_r(getallheaders(), true));
                sendErrorResponse(401, 'No authorization token provided');
            }

            if (!verifyAdminToken($adminToken)) {
                error_log("Invalid token: $adminToken");
                sendErrorResponse(401, 'Invalid or expired token');
            }

            // Get database connection and validate the token
            $pdo = getDbConnection();

            // Check if a file was uploaded via multipart/form-data
            if (!isset($_FILES['file'])) {
                sendErrorResponse(400, 'No file uploaded');
            }

            $file = $_FILES['file'];
            if ($file['error'] !== UPLOAD_ERR_OK) {
                sendErrorResponse(400, 'File upload error: ' . $file['error']);
            }

            // Validate file extension
            $allowedExtensions = ['doc', 'docs', 'docx', 'pdf', 'jpg', 'png'];
            $fileExtension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
            if (!in_array($fileExtension, $allowedExtensions)) {
                sendErrorResponse(400, 'Invalid file type. Allowed types: doc, docs, pdf, jpg, png');
            }

            // Define the destination directory using __DIR__
            $destinationDir = __DIR__ . '/../API/AlertFiles/';

            // Create directory if it doesn't exist
            if (!is_dir($destinationDir)) {
                if (!mkdir($destinationDir, 0755, true)) {
                    error_log("Failed to create directory: " . $destinationDir);
                    sendErrorResponse(500, 'Failed to create destination directory');
                }
            }

            // Ensure directory is writable
            if (!is_writable($destinationDir)) {
                error_log("Directory not writable: " . $destinationDir);
                sendErrorResponse(500, 'Destination directory is not writable');
            }

            // Generate a unique file name
            $newFileName = uniqid() . '.' . $fileExtension;
            $destinationPath = $destinationDir . $newFileName;

            // Move the uploaded file to the destination directory
            if (!move_uploaded_file($file['tmp_name'], $destinationPath)) {
                error_log("Failed to move file to: " . $destinationPath);
                sendErrorResponse(500, 'Failed to move uploaded file');
            }

            // Construct the file URL
            $fileUrl = 'https://my.insightguard.co.za/API/AlertFiles/' . $newFileName;

            echo json_encode([
                'message' => 'File uploaded successfully',
                'file_url' => $fileUrl
            ]);
            exit;
        } catch (Exception $e) {
            error_log("File upload error: " . $e->getMessage());
            sendErrorResponse(500, 'Error uploading file: ' . $e->getMessage());
        }
    }

    ////////////////////////////////////////////////////////////////
    if ($action === 'get_notifications') {
        $token = getAuthToken();
        if (!$token || !verifyAdminToken($token)) {
            sendErrorResponse(401, 'Unauthorized');
        }

        // Validate input
        $validationRules = [
            'type' => ['required' => true],
            'page' => ['required' => false, 'type' => 'integer'],
            'limit' => ['required' => false, 'type' => 'integer'],
            'area_id' => ['required' => false, 'type' => 'string']
        ];

        $validationErrors = validateInput($input, $validationRules);
        if (!empty($validationErrors)) {
            sendErrorResponse(400, implode(', ', $validationErrors));
        }

        try {
            $pdo = getDbConnection();
            $type = $input['type'];

            error_log("Getting notifications for type: $type");

            // Get SC user's company ID
            $stmt = $pdo->prepare("
            SELECT security_company_id
            FROM security_company_users
            WHERE access_token = ?
        ");
            $stmt->execute([$token]);
            $scUser = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$scUser || empty($scUser['security_company_id'])) {
                sendErrorResponse(403, 'No company assigned to this security company user');
            }

            $companyId = $scUser['security_company_id'];

            // Get all area IDs assigned to this security company
            $stmt = $pdo->prepare("
            SELECT area_id
            FROM security_areas
            WHERE company_id = ?
        ");
            $stmt->execute([$companyId]);
            $areaResults = $stmt->fetchAll(PDO::FETCH_COLUMN);

            if (empty($areaResults)) {
                sendErrorResponse(403, 'No areas assigned to this security company');
            }

            $assignedAreas = $areaResults;

            error_log("SC assigned areas: " . implode(', ', $assignedAreas));

            // Area filter validation
            $areaFilter = isset($input['area_id']) && !empty($input['area_id']) ? trim($input['area_id']) : null;

            // Validate that the requested area is in SC's assigned areas
            if ($areaFilter && !in_array($areaFilter, $assignedAreas)) {
                sendErrorResponse(403, 'You do not have access to this area');
            }

            // Optional: Add search capability
            $searchTerm = isset($input['search']) && !empty($input['search']) ? trim($input['search']) : null;

            // Pagination parameters with defaults
            $page = isset($input['page']) && is_numeric($input['page']) && $input['page'] > 0 ? (int)$input['page'] : 1;
            $limit = isset($input['limit']) && is_numeric($input['limit']) && $input['limit'] > 0 ? (int)$input['limit'] : 20;

            // Ensure limit doesn't exceed maximum
            $maxLimit = 100;
            $limit = min($limit, $maxLimit);

            // Calculate offset
            $offset = ($page - 1) * $limit;

            error_log("Pagination: page=$page, limit=$limit, offset=$offset");
            if ($areaFilter) {
                error_log("Filtering by area: $areaFilter");
            }
            if ($searchTerm) {
                error_log("Search term: $searchTerm");
            }

            // Create placeholders for area filtering
            $areaPlaceholders = implode(',', array_fill(0, count($assignedAreas), '?'));

            // Build count query
            $countQuery = "
            SELECT COUNT(DISTINCT n.notification_id) as total
            FROM notifications n
            INNER JOIN user_notifications un ON n.notification_id = un.notification_id
            WHERE n.type = ?
            AND n.is_deleted = 0
            AND un.area_id IN ($areaPlaceholders)
        ";

            // Build execute parameters for count
            $countParams = array_merge([$type], $assignedAreas);

            // Add area filter if provided
            if ($areaFilter) {
                $countQuery .= " AND un.area_id = ?";
                $countParams[] = $areaFilter;
            }

            // Add search filter if provided
            if ($searchTerm) {
                $countQuery .= " AND (n.title LIKE ? OR n.body LIKE ?)";
                $searchParam = "%{$searchTerm}%";
                $countParams[] = $searchParam;
                $countParams[] = $searchParam;
            }

            // Execute count query
            $countStmt = $pdo->prepare($countQuery);
            $countStmt->execute($countParams);
            $totalRecords = $countStmt->fetch(PDO::FETCH_ASSOC)['total'];

            error_log("Total records found: $totalRecords");

            // Calculate pagination info
            $totalPages = $totalRecords > 0 ? ceil($totalRecords / $limit) : 0;
            $hasNextPage = $page < $totalPages;
            $hasPrevPage = $page > 1;

            // Build main query
            $query = "
            SELECT DISTINCT
                n.notification_id,
                n.title,
                n.body,
                n.data,
                n.type,
                n.created_at,
                n.target_type,
                n.is_deleted,
                un.area_id
            FROM notifications n
            INNER JOIN user_notifications un ON n.notification_id = un.notification_id
            WHERE n.type = ?
            AND n.is_deleted = 0
            AND un.area_id IN ($areaPlaceholders)
        ";

            // Build execute parameters for main query
            $queryParams = array_merge([$type], $assignedAreas);

            // Add area filter if provided
            if ($areaFilter) {
                $query .= " AND un.area_id = ?";
                $queryParams[] = $areaFilter;
            }

            // Add search filter if provided
            if ($searchTerm) {
                $query .= " AND (n.title LIKE ? OR n.body LIKE ?)";
                $queryParams[] = $searchParam;
                $queryParams[] = $searchParam;
            }

            $query .= " ORDER BY n.created_at DESC LIMIT $limit OFFSET $offset";

            // Execute main query
            $stmt = $pdo->prepare($query);
            $stmt->execute($queryParams);
            $notifications = $stmt->fetchAll(PDO::FETCH_ASSOC);

            error_log("Retrieved " . count($notifications) . " notifications");

            // Initialize area names array
            $areaNames = [];

            // Add area names to notifications
            if (!empty($notifications)) {
                // Get all unique area_ids from notifications
                $notificationAreaIds = array_unique(array_column($notifications, 'area_id'));

                // Fetch area names only if there are area IDs
                if (!empty($notificationAreaIds)) {
                    $areaPlaceholdersForNames = implode(',', array_fill(0, count($notificationAreaIds), '?'));
                    $areaStmt = $pdo->prepare("
                    SELECT id as area_id, name as area_name
                    FROM areas
                    WHERE id IN ($areaPlaceholdersForNames)
                ");
                    $areaStmt->execute($notificationAreaIds);
                    $areaNames = $areaStmt->fetchAll(PDO::FETCH_KEY_PAIR);
                }
            }

            // Process notifications
            foreach ($notifications as &$notification) {
                try {
                    // Handle title encoding - only if not null
                    if ($notification['title'] !== null) {
                        $notification['title'] = preg_replace('/[\x00-\x1F\x80-\xFF]/', '', $notification['title']);
                        if (!mb_check_encoding($notification['title'], 'UTF-8')) {
                            $notification['title'] = utf8_encode($notification['title']);
                        }
                    }

                    // Handle body encoding - only if not null
                    if ($notification['body'] !== null) {
                        $notification['body'] = preg_replace('/[\x00-\x1F\x80-\xFF]/', '', $notification['body']);
                        if (!mb_check_encoding($notification['body'], 'UTF-8')) {
                            $notification['body'] = utf8_encode($notification['body']);
                        }
                    }

                    // Parse JSON data safely
                    if (!empty($notification['data']) && $notification['data'] !== null) {
                        $decodedData = json_decode($notification['data'], true);
                        if (json_last_error() === JSON_ERROR_NONE && is_array($decodedData)) {
                            // Fix encoding in data fields
                            if (isset($decodedData['title']) && $decodedData['title'] !== null) {
                                $decodedData['title'] = preg_replace('/[\x00-\x1F\x80-\xFF]/', '', $decodedData['title']);
                                if (!mb_check_encoding($decodedData['title'], 'UTF-8')) {
                                    $decodedData['title'] = utf8_encode($decodedData['title']);
                                }
                            }
                            if (isset($decodedData['body']) && $decodedData['body'] !== null) {
                                $decodedData['body'] = preg_replace('/[\x00-\x1F\x80-\xff]/', '', $decodedData['body']);
                                if (!mb_check_encoding($decodedData['body'], 'UTF-8')) {
                                    $decodedData['body'] = utf8_encode($decodedData['body']);
                                }
                            }
                            $notification['data'] = $decodedData;
                        } else {
                            error_log("JSON decode error for notification ID {$notification['notification_id']}: " . json_last_error_msg());
                            $notification['data'] = null;
                        }
                    } else {
                        $notification['data'] = null;
                    }

                    // Add area information
                    $notification['area_id'] = isset($notification['area_id']) ? (string)$notification['area_id'] : null;
                    $notification['area_name'] = isset($areaNames[$notification['area_id']]) ? $areaNames[$notification['area_id']] : 'Unknown Area';
                    $notification['is_deleted'] = (int)$notification['is_deleted'];
                } catch (Exception $e) {
                    error_log("Error processing notification ID {$notification['notification_id']}: " . $e->getMessage());
                    $notification['data'] = null;
                    $notification['area_name'] = 'Unknown Area';
                }
            }

            $response = [
                'success' => true,
                'data' => $notifications,
                'filters' => [
                    'type' => $type,
                    'area_id' => $areaFilter,
                    'search' => $searchTerm
                ],
                'pagination' => [
                    'current_page' => $page,
                    'per_page' => $limit,
                    'total_records' => (int)$totalRecords,
                    'total_pages' => $totalPages,
                    'has_next_page' => $hasNextPage,
                    'has_prev_page' => $hasPrevPage,
                    'next_page' => $hasNextPage ? $page + 1 : null,
                    'prev_page' => $hasPrevPage ? $page - 1 : null
                ],
                'count' => count($notifications)
            ];

            http_response_code(200);
            echo json_encode($response, JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR);
        } catch (Exception $e) {
            error_log("Get notifications error: " . $e->getMessage());
            error_log("Stack trace: " . $e->getTraceAsString());
            sendErrorResponse(500, 'Failed to fetch notifications: ' . $e->getMessage());
        }
        exit;
    }

    ////////////////////////////////////////////////////////////////
    if ($action === 'delete_notification') {
        $token = getAuthToken();
        if (!$token || !verifyAdminToken($token)) {
            sendErrorResponse(401, 'Unauthorized');
        }

        // Validate input
        $validationRules = [
            'notification_id' => ['required' => true, 'type' => 'integer']
        ];

        $validationErrors = validateInput($input, $validationRules);
        if (!empty($validationErrors)) {
            sendErrorResponse(400, implode(', ', $validationErrors));
        }

        try {
            $pdo = getDbConnection();
            $notificationId = $input['notification_id'];

            error_log("Attempting to delete notification ID: $notificationId");

            // Start transaction for data consistency
            $pdo->beginTransaction();
            error_log("Transaction started");

            // First check if notification exists
            $checkStmt = $pdo->prepare("
            SELECT notification_id
            FROM notifications
            WHERE notification_id = ?
        ");
            $checkStmt->execute([$notificationId]);
            $notification = $checkStmt->fetch(PDO::FETCH_ASSOC);

            if (!$notification) {
                error_log("Notification not found with ID: $notificationId");
                $pdo->rollback();
                sendErrorResponse(404, 'Notification not found');
            }

            error_log("Notification found, proceeding with deletion");

            // Delete from user_notifications table first (foreign key constraint)
            $deleteUsersNotificationStmt = $pdo->prepare("
            DELETE FROM user_notifications
            WHERE notification_id = ?
        ");
            $deleteUsersNotificationResult = $deleteUsersNotificationStmt->execute([$notificationId]);
            $usersNotificationDeletedCount = $deleteUsersNotificationStmt->rowCount();

            error_log("Users notification delete result: " . ($deleteUsersNotificationResult ? 'success' : 'failed'));
            error_log("Users notification deleted count: $usersNotificationDeletedCount");

            // Delete from notifications table
            $deleteNotificationStmt = $pdo->prepare("
            DELETE FROM notifications
            WHERE notification_id = ?
        ");
            $deleteNotificationResult = $deleteNotificationStmt->execute([$notificationId]);
            $notificationDeletedCount = $deleteNotificationStmt->rowCount();

            error_log("Notification delete result: " . ($deleteNotificationResult ? 'success' : 'failed'));
            error_log("Notification deleted count: $notificationDeletedCount");

            if ($deleteNotificationResult && $notificationDeletedCount > 0) {
                // Commit transaction
                $pdo->commit();
                error_log("Transaction committed successfully");

                http_response_code(200);
                echo json_encode([
                    'success' => true,
                    'message' => 'Notification deleted permanently',
                    'notification_id' => $notificationId,
                    'user_notifications_deleted' => $usersNotificationDeletedCount,
                    'notification_deleted' => $notificationDeletedCount
                ]);
            } else {
                error_log("Delete operation failed - rolling back transaction");
                $pdo->rollback();
                sendErrorResponse(500, 'Failed to delete notification from main table');
            }
        } catch (Exception $e) {
            // Rollback transaction on error
            if ($pdo->inTransaction()) {
                $pdo->rollback();
                error_log("Transaction rolled back due to exception");
            }
            error_log("Delete notification error: " . $e->getMessage());
            error_log("Stack trace: " . $e->getTraceAsString());
            sendErrorResponse(500, 'Database error during deletion: ' . $e->getMessage());
        }
        exit;
    }

    // If no valid action is found
    sendErrorResponse(400, 'Invalid action specified');
} catch (Exception $e) {
    error_log("API error: " . $e->getMessage());
    sendErrorResponse(500, 'Internal server error');
}
