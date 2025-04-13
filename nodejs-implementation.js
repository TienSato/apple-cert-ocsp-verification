const fs = require('fs').promises;
const { execSync } = require('child_process');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const os = require('os');

/**
 * Kiểm tra chứng chỉ Apple thông qua OCSP POST
 * 
 * @param {string} certPath Đường dẫn đến file certificate (.pem)
 * @param {string} wwdrPath Đường dẫn đến file Apple WWDR CA G3 (.pem)
 * @returns {Promise<Object>} Kết quả kiểm tra
 */
async function checkCertOCSPWithPost(certPath, wwdrPath) {
    const tempDir = os.tmpdir();
    const ocspRequestPath = path.join(tempDir, `ocsp_request_${uuidv4()}.der`);
    const ocspResponsePath = path.join(tempDir, `ocsp_response_${uuidv4()}.der`);
    
    try {
        // Tạo OCSP request
        const createReqCmd = `openssl ocsp -issuer "${wwdrPath}" -cert "${certPath}" -reqout "${ocspRequestPath}"`;
        
        try {
            execSync(createReqCmd, { stdio: 'pipe' });
        } catch (error) {
            throw new Error(`Không thể tạo OCSP request: ${error.message}`);
        }
        
        const ocspRequest = await fs.readFile(ocspRequestPath);
        const ocspUrl = "http://ocsp.apple.com/ocsp03-wwdrg301";
        
        let response;
        try {
            response = await axios.post(ocspUrl, ocspRequest, {
                headers: {
                    'Content-Type': 'application/ocsp-request',
                    'Accept': 'application/ocsp-response',
                    'Host': 'ocsp.apple.com'
                },
                responseType: 'arraybuffer',
                timeout: 30000
            });
        } catch (error) {
            throw new Error(`Không nhận được phản hồi OCSP hợp lệ: ${error.message}`);
        }
        await fs.writeFile(ocspResponsePath, response.data);
        const parseRespCmd = `openssl ocsp -issuer "${wwdrPath}" -cert "${certPath}" -respin "${ocspResponsePath}" -text -noverify`;
        
        let ocspResponse;
        try {
            ocspResponse = execSync(parseRespCmd, { stdio: 'pipe', encoding: 'utf8' });
        } catch (error) {
            throw new Error(`Không thể phân tích phản hồi OCSP: ${error.message}`);
        }
        const revocationPatterns = [
            /Revocation Time: (.+)/,
            /[Cc]ertificate [Ss]tatus: revoked/,
            /[Cc]ert[Ss]tatus: revoked/,
            /[Rr]evoked/
        ];
        
        let isRevoked = false;
        let revokeTime = null;
        
        for (const pattern of revocationPatterns) {
            const matches = pattern.exec(ocspResponse);
            if (matches) {
                isRevoked = true;
                if (matches[1]) {
                    revokeTime = matches[1];
                }
                break;
            }
        }
        
        return {
            success: true,
            is_revoked: isRevoked,
            revoke_time: revokeTime,
            response: ocspResponse
        };
        
    } catch (error) {
        return {
            success: false,
            error: error.message
        };
    } finally {
        // clear
        try {
            await fs.unlink(ocspRequestPath).catch(() => {});
            await fs.unlink(ocspResponsePath).catch(() => {});
        } catch (e) {
            // skip
        }
    }
}

//demo
async function main() {
    if (require.main === module) {
        const args = process.argv.slice(2);
        
        if (args.length < 2) {
            console.log("Sử dụng: node " + path.basename(__filename) + " <đường_dẫn_certificate.pem> <đường_dẫn_AppleWWDRCAG3.pem>");
            process.exit(1);
        }
        
        const certPath = args[0];
        const wwdrPath = args[1];
        
        try {
            await fs.access(certPath);
            await fs.access(wwdrPath);
        } catch (error) {
            console.error("Lỗi: Không tìm thấy file. Hãy kiểm tra đường dẫn");
            process.exit(1);
        }
        
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
}

// run
main();

// Exp
module.exports = { checkCertOCSPWithPost };
