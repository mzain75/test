<?php
header('Content-Type: application/json');
error_reporting(E_ALL);
ini_set('display_errors', 1);

class FCMService {
    private $projectId;
    private $serviceAccountPath;
    private $accessToken;

    public function __construct($projectId, $serviceAccountPath) {
        $this->projectId = $projectId;
        $this->serviceAccountPath = $serviceAccountPath;
        $this->accessToken = null;
    }

    private function generateAccessToken() {
        try {
            if (!file_exists($this->serviceAccountPath)) {
                throw new Exception('Service account JSON file not found at: ' . $this->serviceAccountPath);
            }

            $serviceAccount = json_decode(file_get_contents($this->serviceAccountPath), true);
            if (!$serviceAccount) {
                throw new Exception('Failed to parse service account JSON: ' . json_last_error_msg());
            }

            // Create JWT header
            $header = json_encode([
                'typ' => 'JWT',
                'alg' => 'RS256',
                'kid' => $serviceAccount['private_key_id']
            ]);

            // Create JWT claim set
            $time = time();
            $claim = json_encode([
                'iss' => $serviceAccount['client_email'],
                'scope' => 'https://www.googleapis.com/auth/firebase.messaging',
                'aud' => 'https://oauth2.googleapis.com/token',
                'exp' => $time + 3600,
                'iat' => $time
            ]);

            // Encode header and claim
            $base64Header = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
            $base64Claim = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($claim));

            // Create signature using private key
            $privateKey = str_replace('\n', "\n", $serviceAccount['private_key']);
            $key = openssl_pkey_get_private($privateKey);
            if (!$key) {
                throw new Exception('Failed to load private key: ' . openssl_error_string());
            }

            openssl_sign(
                $base64Header . '.' . $base64Claim,
                $signature,
                $key,
                'SHA256'
            );
            $base64Signature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));

            // Create JWT
            $jwt = $base64Header . '.' . $base64Claim . '.' . $base64Signature;

            // Exchange JWT for access token
            $response = $this->makeRequest(
                'https://oauth2.googleapis.com/token',
                'POST',
                [
                    'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                    'assertion' => $jwt
                ]
            );

            if (isset($response['access_token'])) {
                $this->accessToken = $response['access_token'];
                return $this->accessToken;
            }

            throw new Exception('Failed to get access token from Google: ' . json_encode($response));
        } catch (Exception $e) {
            error_log('Token generation error: ' . $e->getMessage());
            throw $e;
        }
    }

    public function sendMessage($messageData) {
        try {
            if (!$this->accessToken) {
                $this->generateAccessToken();
            }

            $endpoint = "https://fcm.googleapis.com/v1/projects/{$this->projectId}/messages:send";

            // Validate message data
            $messages = $this->prepareMessages($messageData);

            // Send multiple messages and collect responses
            $responses = [];
            foreach ($messages as $message) {
                try {
                    $response = $this->makeRequest(
                        $endpoint,
                        'POST',
                        ['message' => $message],
                        [
                            'Authorization: Bearer ' . $this->accessToken,
                            'Content-Type: application/json'
                        ]
                    );
                    $responses[] = $response;
                } catch (Exception $e) {
                    $responses[] = [
                        'error' => $e->getMessage(),
                        'message_details' => $message
                    ];
                }
            }

            return $responses;
        } catch (Exception $e) {
            error_log('Send message error: ' . $e->getMessage());
            throw $e;
        }
    }

    private function prepareMessages($messageData) {
        $messages = [];

        // Validate input
        if (empty($messageData['token']) &&
            empty($messageData['tokens']) &&
            empty($messageData['topic'])) {
            throw new Exception('No valid message target (token/tokens/topic) provided');
        }

        // Single token
        if (!empty($messageData['token'])) {
            $messages[] = $this->prepareSingleMessage($messageData, $messageData['token']);
        }

        // Multiple tokens
        if (!empty($messageData['tokens'])) {
            foreach ($messageData['tokens'] as $token) {
                $messages[] = $this->prepareSingleMessage($messageData, $token);
            }
        }

        // Topic
        if (!empty($messageData['topic'])) {
            $messages[] = $this->prepareTopicMessage($messageData);
        }

        return $messages;
    }

    private function prepareSingleMessage($messageData, $token) {
        $message = [
            'token' => $token
        ];

        // Add notification payload
        if (!empty($messageData['notification'])) {
            $message['notification'] = [
                'title' => $messageData['notification']['title'] ?? '',
                'body' => $messageData['notification']['body'] ?? ''
            ];
        }

        // Add data payload - ensure all values are strings
        if (!empty($messageData['data'])) {
            $message['data'] = [];
            foreach ($messageData['data'] as $key => $value) {
                if (is_array($value) || is_object($value)) {
                    $message['data'][$key] = json_encode($value);
                } else {
                    $message['data'][$key] = (string)$value; // Cast to string
                }
            }
        }

        return $message;
    }

    private function prepareTopicMessage($messageData) {
        $message = [
            'topic' => $messageData['topic']
        ];

        // Add notification payload
        if (!empty($messageData['notification'])) {
            $message['notification'] = [
                'title' => $messageData['notification']['title'] ?? '',
                'body' => $messageData['notification']['body'] ?? ''
            ];
        }

        // Add data payload - ensure all values are strings
        if (!empty($messageData['data'])) {
            $message['data'] = [];
            foreach ($messageData['data'] as $key => $value) {
                if (is_array($value) || is_object($value)) {
                    $message['data'][$key] = json_encode($value);
                } else {
                    $message['data'][$key] = (string)$value; // Cast to string
                }
            }
        }

        return $message;
    }

    private function makeRequest($url, $method = 'POST', $data = [], $headers = []) {
        $curl = curl_init();

        $defaultHeaders = ['Content-Type: application/json'];
        $headers = array_merge($defaultHeaders, $headers);

        curl_setopt_array($curl, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => '',
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2
        ]);

        if (!empty($data)) {
            curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($data));
        }

        $response = curl_exec($curl);
        $err = curl_error($curl);
        $httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);

        curl_close($curl);

        if ($err) {
            throw new Exception('cURL Error: ' . $err);
        }

        // Parse response
        $parsedResponse = json_decode($response, true);

        // Check for HTTP errors or FCM-specific errors
        if ($httpCode !== 200 || isset($parsedResponse['error'])) {
            throw new Exception('FCM Error: ' .
                ($parsedResponse['error']['message'] ?? 'Unknown error') .
                ' (HTTP Code: ' . $httpCode . ')'
            );
        }

        return $parsedResponse;
    }
}

// Main API Endpoint Handler
try {
    // Get JSON input
    $jsonInput = file_get_contents('php://input');
    $data = json_decode($jsonInput, true);

    // Validate input
    if (!$data) {
        throw new Exception('Invalid JSON input');
    }

    // Validate Authorization Header (Optional but recommended)
    $headers = getallheaders();
    if (empty($headers['Authorization'])) {
        // Optional: Only validate if you want to restrict access
        // sendErrorResponse(401, 'Access token is required');
    }

    // Initialize FCM service
    $projectId = 'insight-guard-c8c1b';
    $serviceAccountPath = __DIR__ . '/ig.json';

    $fcm = new FCMService($projectId, $serviceAccountPath);

    // Send message
    $responses = $fcm->sendMessage($data);

    // Prepare response
    $response = [
        'success' => true,
        'message' => 'Notification sent successfully',
        'fcm_responses' => $responses
    ];

    // Add testing mode indicator if needed
    if (defined('TESTING_MODE') && TESTING_MODE) {
        $response['testing_mode'] = true;
    }

    // Send response
    echo json_encode($response);
    exit;

} catch (Exception $e) {
    error_log("FCM Send Notification Error: " . $e->getMessage());

    // Send error response
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
    exit;
}
