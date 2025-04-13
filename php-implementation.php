<?php
/**
 * 
 * @param string $certPath Đường dẫn đến file certificate (.pem)
 * @param string $wwdrPath Đường dẫn đến file Apple WWDR CA G3 (.pem)
 * @return array Kết quả kiểm tra
 */
function checkCertOCSPWithPost($certPath, $wwdrPath) {
    $tempDir = sys_get_temp_dir();
    $ocspRequestPath = $tempDir . '/ocsp_request_' . uniqid() . '.der';
    $ocspResponsePath = $tempDir . '/ocsp_response_' . uniqid() . '.der';
    
    try {
        $createReqCmd = sprintf(
            'openssl ocsp -issuer %s -cert %s -reqout %s 2>&1',
            escapeshellarg($wwdrPath),
            escapeshellarg($certPath),
            escapeshellarg($ocspRequestPath)
        );
        
        exec($createReqCmd, $createReqOutput, $createReqCode);
        
        if ($createReqCode !== 0 || !file_exists($ocspRequestPath)) {
            throw new Exception("Không thể tạo OCSP request");
        }
        $ocspRequest = file_get_contents($ocspRequestPath);
        $ocspUrl = "http://ocsp.apple.com/ocsp03-wwdrg301";
        
        $ch = curl_init($ocspUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/ocsp-request',
            'Accept: application/ocsp-response',
            'Host: ocsp.apple.com'
        ]);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $ocspRequest);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        
        $ocspResponse = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);
        
        if ($httpCode != 200 || empty($ocspResponse)) {
            throw new Exception("Không nhận được phản hồi OCSP hợp lệ: HTTP $httpCode, Error: $curlError");
        }
        
        file_put_contents($ocspResponsePath, $ocspResponse);
        $parseRespCmd = sprintf(
            'openssl ocsp -issuer %s -cert %s -respin %s -text -noverify 2>&1',
            escapeshellarg($wwdrPath),
            escapeshellarg($certPath),
            escapeshellarg($ocspResponsePath)
        );
        
        exec($parseRespCmd, $parseRespOutput, $parseRespCode);
        
        if ($parseRespCode !== 0) {
            throw new Exception("Không thể phân tích phản hồi OCSP");
        }
        
        $response = implode("\n", $parseRespOutput);
        $revocationPatterns = [
            '/Revocation Time: (.+)/',
            '/[Cc]ertificate [Ss]tatus: revoked/',
            '/[Cc]ert[Ss]tatus: revoked/',
            '/[Rr]evoked/'
        ];
        
        $isRevoked = false;
        $revokeTime = null;
        
        foreach ($revocationPatterns as $pattern) {
            if (preg_match($pattern, $response, $matches)) {
                $isRevoked = true;
                if (isset($matches[1])) {
                    $revokeTime = $matches[1];
                }
                break;
            }
        }
        
        return [
            'success' => true,
            'is_revoked' => $isRevoked,
            'revoke_time' => $revokeTime,
            'response' => $response
        ];
        
    } catch (Exception $e) {
        return [
            'success' => false,
            'error' => $e->getMessage()
        ];
    } finally {
        // Cler
        if (file_exists($ocspRequestPath)) {
            @unlink($ocspRequestPath);
        }
        if (file_exists($ocspResponsePath)) {
            @unlink($ocspResponsePath);
        }
    }
}

// demo
if (php_sapi_name() === 'cli') {
    if ($argc < 3) {
        echo "Sử dụng: php " . $argv[0] . " <đường_dẫn_certificate.pem> <đường_dẫn_AppleWWDRCAG3.pem>\n";
        exit(1);
    }

    $certPath = $argv[1];
    $wwdrPath = $argv[2];
    
    if (!file_exists($certPath)) {
        echo "Lỗi: Không tìm thấy file certificate tại: $certPath\n";
        exit(1);
    }
    
    if (!file_exists($wwdrPath)) {
        echo "Lỗi: Không tìm thấy file WWDR CA tại: $wwdrPath\n";
        exit(1);
    }
    
    $result = checkCertOCSPWithPost($certPath, $wwdrPath);
    
    if ($result['success']) {
        if ($result['is_revoked']) {
            echo "Chứng chỉ đã bị thu hồi\n";
            if (!empty($result['revoke_time'])) {
                echo "Thời gian thu hồi: " . $result['revoke_time'] . "\n";
            }
        } else {
            echo "Chứng chỉ còn hiệu lực\n";
        }
    } else {
        echo "Lỗi kiểm tra: " . $result['error'] . "\n";
    }
}
