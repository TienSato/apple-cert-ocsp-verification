# apple-cert-ocsp-verification
Phương pháp kiểm tra chứng chỉ Apple thông qua OCSP POST, Check P12
# Phương pháp kiểm tra chứng chỉ Apple thông qua OCSP POST

Thư viện này cung cấp phương pháp chính xác để kiểm tra trạng thái thu hồi của chứng chỉ Apple Developer thông qua giao thức OC
# Phương pháp kiểm tra chứng chỉ Apple thông qua OCSP POST

Thư viện này cung cấp phương pháp chính xác để kiểm tra trạng thái thu hồi của chứng chỉ Apple Developer thông qua giao thức OCSP (Online Certificate Status Protocol).

## Vấn đề

Khi sử dụng phương pháp OCSP thông thường để kiểm tra chứng chỉ Apple, nhiều trường hợp sẽ không phát hiện chính xác tình trạng thu hồi. Nguyên nhân là do:

1. Phương pháp OCSP trực tiếp có thể trả về kết quả không đầy đủ
2. Định dạng phản hồi của Apple có thể thay đổi
3. Một số chứng chỉ bị thu hồi nhưng không được cập nhật trong CRL (Certificate Revocation List) công khai

## Giải pháp

Sử dụng phương pháp OCSP POST thay vì kiểm tra OCSP trực tiếp, đảm bảo kết quả chính xác hơn trong việc xác định chứng chỉ bị thu hồi.

## Cách hoạt động

1. Tạo OCSP request từ chứng chỉ cần kiểm tra
2. Gửi request đến máy chủ OCSP của Apple thông qua phương thức POST
3. Nhận và phân tích phản hồi OCSP
4. Kiểm tra phản hồi với nhiều pattern khác nhau để xác định chính xác trạng thái thu hồi

## Các file trong repository

Repository này bao gồm các tệp sau:

- **README.md**: Tài liệu hướng dẫn
- **php-implementation.php**: Triển khai trong PHP
- **nodejs-implementation.js**: Triển khai trong Node.js
- **python-implementation.py**: Triển khai trong Python
- **AppleWWDRCAG3.pem**: File chứng chỉ gốc của Apple WWDR CA G3

## Yêu cầu

### PHP
- PHP 7.0 hoặc cao hơn
- Cài đặt OpenSSL
- Cài đặt PHP cURL extension

### Node.js
- Node.js 12 hoặc cao hơn
- Dependencies:
  - axios
  - uuid

### Python
- Python 3.6 hoặc cao hơn
- Dependencies:
  - requests

## Hướng dẫn sử dụng

### PHP

```php
<?php
require_once('php-implementation.php');

$certPath = '/path/to/certificate.pem';
$wwdrPath = '/path/to/AppleWWDRCAG3.pem';

$result = checkCertOCSPWithPost($certPath, $wwdrPath);

if ($result['success']) {
    if ($result['is_revoked']) {
        echo "Chứng chỉ đã bị thu hồi";
        if (!empty($result['revoke_time'])) {
            echo " vào thời gian: " . $result['revoke_time'];
        }
    } else {
        echo "Chứng chỉ còn hiệu lực";
    }
} else {
    echo "Lỗi kiểm tra: " . $result['error'];
}
?>
```

### Node.js

```javascript
const { checkCertOCSPWithPost } = require('./nodejs-implementation');

async function main() {
    const certPath = '/path/to/certificate.pem';
    const wwdrPath = '/path/to/AppleWWDRCAG3.pem';
    
    try {
        const result = await checkCertOCSPWithPost(certPath, wwdrPath);
        
        if (result.success) {
            if (result.is_revoked) {
                console.log("Chứng chỉ đã bị thu hồi");
                if (result.revoke_time) {
                    console.log("Thời gian thu hồi:", result.revoke_time);
                }
            } else {
                console.log("Chứng chỉ còn hiệu lực");
            }
        } else {
            console.error("Lỗi kiểm tra:", result.error);
        }
    } catch (error) {
        console.error("Lỗi:", error.message);
    }
}

main();
```

### Python

```python
from python_implementation import check_cert_ocsp_with_post

cert_path = '/path/to/certificate.pem'
wwdr_path = '/path/to/AppleWWDRCAG3.pem'

result = check_cert_ocsp_with_post(cert_path, wwdr_path)

if result['success']:
    if result['is_revoked']:
        print("Chứng chỉ đã bị thu hồi")
        if result['revoke_time']:
            print(f"Thời gian thu hồi: {result['revoke_time']}")
    else:
        print("Chứng chỉ còn hiệu lực")
else:
    print(f"Lỗi kiểm tra: {result['error']}")
```

## Sử dụng từ dòng lệnh

### PHP
php php-implementation.php /path/to/certificate.pem /path/to/AppleWWDRCAG3.pem

### Node.js
node nodejs-implementation.js /path/to/certificate.pem /path/to/AppleWWDRCAG3.pem

### Python
# Kiểm tra file PEM
python python-implementation.py check-pem /path/to/certificate.pem /path/to/AppleWWDRCAG3.pem

# Kiểm tra file P12
python python-implementation.py check-p12 /path/to/certificate.p12 password /path/to/AppleWWDRCAG3.pem

## Lưu ý 

1. Đảm bảo OpenSSL đã được cài đặt trên hệ thống
2. Trước khi kiểm tra, bạn cần trích xuất chứng chỉ từ file P12 sang định dạng PEM
   openssl pkcs12 -in certificate.p12 -passin pass:YOUR_PASSWORD -nokeys -clcerts -legacy -out certificate.pem
3. Với OpenSSL 3.x, luôn sử dụng tham số `-legacy` khi làm việc với chứng chỉ P12
4. Kiểm tra kết quả với nhiều pattern khác nhau để đảm bảo phát hiện chính xác chứng chỉ bị thu hồi
