#!/usr/bin/env python3
import os
import tempfile
import uuid
import subprocess
import requests
import re
import sys
import argparse
from typing import Dict, Any, Optional, Union

def check_cert_ocsp_with_post(cert_path: str, wwdr_path: str) -> Dict[str, Any]:
    """
    Kiểm tra chứng chỉ Apple thông qua OCSP POST
    
    Args:
        cert_path (str): Đường dẫn đến file certificate (.pem)
        wwdr_path (str): Đường dẫn đến file Apple WWDR CA G3 (.pem)
        
    Returns:
        dict: Kết quả kiểm tra
    """
    temp_dir = tempfile.gettempdir()
    ocsp_request_path = os.path.join(temp_dir, f'ocsp_request_{uuid.uuid4()}.der')
    ocsp_response_path = os.path.join(temp_dir, f'ocsp_response_{uuid.uuid4()}.der')
    
    try:
        # Tạo OCSP request
        create_req_cmd = [
            'openssl', 'ocsp', 
            '-issuer', wwdr_path, 
            '-cert', cert_path, 
            '-reqout', ocsp_request_path
        ]
        
        try:
            subprocess.run(create_req_cmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            raise Exception(f"Không thể tạo OCSP request: {e.stderr}")
        
        # Đọc OCSP 
        with open(ocsp_request_path, 'rb') as f:
            ocsp_request_data = f.read()
        ocsp_url = "http://ocsp.apple.com/ocsp03-wwdrg301"
        
        try:
            response = requests.post(
                ocsp_url,
                data=ocsp_request_data,
                headers={
                    'Content-Type': 'application/ocsp-request',
                    'Accept': 'application/ocsp-response',
                    'Host': 'ocsp.apple.com'
                },
                timeout=30
            )
            
            if response.status_code != 200:
                raise Exception(f"HTTP error: {response.status_code}")
                
        except requests.RequestException as e:
            raise Exception(f"Không nhận được phản hồi OCSP hợp lệ: {str(e)}")
        
        # Lưu phản hồi OCSP
        with open(ocsp_response_path, 'wb') as f:
            f.write(response.content)
        
        # Phân tích phản hồi OCSP
        parse_resp_cmd = [
            'openssl', 'ocsp', 
            '-issuer', wwdr_path, 
            '-cert', cert_path, 
            '-respin', ocsp_response_path, 
            '-text', '-noverify'
        ]
        
        try:
            result = subprocess.run(parse_resp_cmd, check=True, capture_output=True, text=True)
            ocsp_response = result.stdout
        except subprocess.CalledProcessError as e:
            raise Exception(f"Không thể phân tích phản hồi OCSP: {e.stderr}")
                revocation_patterns = [
            r'Revocation Time: (.+)',
            r'[Cc]ertificate [Ss]tatus: revoked',
            r'[Cc]ert[Ss]tatus: revoked',
            r'[Rr]evoked'
        ]
        
        is_revoked = False
        revoke_time = None
        
        for pattern in revocation_patterns:
            match = re.search(pattern, ocsp_response)
            if match:
                is_revoked = True
                if match.groups():
                    revoke_time = match.group(1)
                break
        
        return {
            'success': True,
            'is_revoked': is_revoked,
            'revoke_time': revoke_time,
            'response': ocsp_response
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }
    finally:
        # claer
        if os.path.exists(ocsp_request_path):
            os.unlink(ocsp_request_path)
        if os.path.exists(ocsp_response_path):
            os.unlink(ocsp_response_path)

def extract_p12_to_pem(p12_path: str, password: str, output_path: str = None) -> Optional[str]:
    """
    Trích xuất chứng chỉ từ file P12 sang định dạng PEM
    
    Args:
        p12_path (str): Đường dẫn đến file P12
        password (str): Mật khẩu của file P12
        output_path (str, optional): Đường dẫn đến file output.
        
    Returns:
        str: Đường dẫn đến file PEM đã trích xuất
    """
    if output_path is None:
        output_path = os.path.join(tempfile.gettempdir(), f'cert_{uuid.uuid4()}.pem')
    
    try:
        cmd = [
            'openssl', 'pkcs12',
            '-in', p12_path,
            '-passin', f'pass:{password}',
            '-nokeys', '-clcerts',
            '-legacy',  # Cần thiết cho OpenSSL 3.x
            '-out', output_path
        ]
        
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        return output_path
    except subprocess.CalledProcessError as e:
        print(f"Lỗi khi trích xuất P12: {e.stderr}")
        return None

def main():
    parser = argparse.ArgumentParser(description='Kiểm tra trạng thái thu hồi của chứng chỉ Apple')
    subparsers = parser.add_subparsers(dest='command', help='Lệnh')
    
    # Parser cho lệnh check-pem
    check_pem_parser = subparsers.add_parser('check-pem', help='Kiểm tra file PEM')
    check_pem_parser.add_argument('cert_path', help='Đường dẫn đến file certificate (.pem)')
    check_pem_parser.add_argument('wwdr_path', help='Đường dẫn đến file Apple WWDR CA G3 (.pem)')
    
    # Parser cho lệnh check-p12
    check_p12_parser = subparsers.add_parser('check-p12', help='Kiểm tra file P12')
    check_p12_parser.add_argument('p12_path', help='Đường dẫn đến file certificate (.p12)')
    check_p12_parser.add_argument('password', help='Mật khẩu của file P12')
    check_p12_parser.add_argument('wwdr_path', help='Đường dẫn đến file Apple WWDR CA G3 (.pem)')
    
    args = parser.parse_args()
    
    if args.command == 'check-pem':
        if not os.path.exists(args.cert_path):
            print(f"Lỗi: Không tìm thấy file certificate tại: {args.cert_path}")
            return 1
            
        if not os.path.exists(args.wwdr_path):
            print(f"Lỗi: Không tìm thấy file WWDR CA tại: {args.wwdr_path}")
            return 1
            
        result = check_cert_ocsp_with_post(args.cert_path, args.wwdr_path)
    
    elif args.command == 'check-p12':
        if not os.path.exists(args.p12_path):
            print(f"Lỗi: Không tìm thấy file P12 tại: {args.p12_path}")
            return 1
            
        if not os.path.exists(args.wwdr_path):
            print(f"Lỗi: Không tìm thấy file WWDR CA tại: {args.wwdr_path}")
            return 1
        
        # cover P12 sang PEM
        pem_path = extract_p12_to_pem(args.p12_path, args.password)
        if not pem_path:
            print("Lỗi: Không thể trích xuất chứng chỉ từ file P12")
            return 1
        
        try:
            result = check_cert_ocsp_with_post(pem_path, args.wwdr_path)
        finally
            if os.path.exists(pem_path):
                os.unlink(pem_path)
    
    else:
        parser.print_help()
        return 1
    
    if result['success']:
        if result['is_revoked']:
            print("Chứng chỉ đã bị thu hồi")
            if result['revoke_time']:
                print(f"Thời gian thu hồi: {result['revoke_time']}")
        else:
            print("Chứng chỉ còn hiệu lực")
    else:
        print(f"Lỗi kiểm tra: {result['error']}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
