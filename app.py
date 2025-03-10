import os
import re
import json
import base64
import tempfile
import hashlib
import xml.etree.ElementTree as ET
import requests
from flask import Flask, request, jsonify, render_template, send_file
from werkzeug.utils import secure_filename
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from PyPDF2 import PdfReader
from mistralai import Mistral

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload size
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Hàm tiện ích từ ứng dụng gốc
def load_rsa_private_key_from_xml(xml_str):
    """Tải khóa RSA riêng tư từ định dạng XML"""
    root = ET.fromstring(xml_str)
    def get_int(tag):
        text = root.find(tag).text
        return int.from_bytes(base64.b64decode(text), 'big')
    n = get_int('Modulus')
    e = get_int('Exponent')
    d = get_int('D')
    p = get_int('P')
    q = get_int('Q')
    key = RSA.construct((n, e, d, p, q))
    return key

def decrypt_api_key(encrypted_key_base64, rsa_private_key):
    """Giải mã API key đã được mã hóa"""
    try:
        cipher = PKCS1_v1_5.new(rsa_private_key)
        encrypted_data = base64.b64decode(encrypted_key_base64)
        decrypted = cipher.decrypt(encrypted_data, None)
        
        if not decrypted:
            raise ValueError("Giải mã thất bại")
        return decrypted.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Lỗi giải mã API key: {str(e)}")

def get_mineru_token():
    """Lấy API key từ GitHub"""
    PRIVATE_KEY_XML = """<RSAKeyValue>
<Modulus>pWVItQwZ7NCPcBhSL4rqJrwh4OQquiPVtqTe4cqxO7o+UjYNzDPfLkfKAvR8k9ED4lq2TU11zEj8p2QZAM7obUlK4/HVexzfZd0qsXlCy5iaWoTQLXbVdzjvkC4mkO5TaX3Mpg/+p4oZjk1iS68tQFmju5cT19dcsPh554ICk8U=</Modulus>
<Exponent>AQAB</Exponent>
<P>0ZWwsKa9Vw9BJAsRaW4eV60i6Z+R6z9LNSgjNn4pYH2meZtGUbmJVowRv7EM5sytouB5EMru7sQbRHEQ7nrwSw==</P>
<Q>ygZQWNkUgfHhHBataXvYLxWgPB5UZTWogN8Mb33LT4rq7I5P1GX3oWtYF2AdmChX8Lq3Ms/A/jBhqYomhYOiLw==</Q>
<DP>qS9VOsTfA3Bk/VuR6rHh/JTfIgiWGnk1lOuZwVuGu0WzJWebFE3Z9+uKSFv8NjPz1w+tq0imKEhWWqGLMXg8kQ==</DP>
<DQ>UCtXQRrMB5EL6tCY+k4aCP1E+/ZxOUSk3Jcm4SuDPcp71WnYBgp8zULCz2vl8pa35yDBSFmnVXevmc7n4H3PIw==</DQ>
<InverseQ>Qm9RjBhxANWyIb8I28vjGz+Yb9CnunWxpHWbfRo1vF+Z38WB7dDgLsulAXMGrUPQTeG6K+ot5moeZ9ZcAc1Hzw==</InverseQ>
<D>F9lU9JY8HsOsCzPWlfhn7xHtqKn95z1HkcCQSuqZR82BMwWMU8efBONhI6/xTrcy4i7GXrsuozhbBiAO4ujy5qPytdFemLuqjwFTyvllkcOy3Kbe0deczxnPPCwmSMVKsYInByJoBP3JYoyVAj4bvY3UqZJtw+2u/OIOhoBe33k=</D>
</RSAKeyValue>"""
    
    try:
        rsa_private_key = load_rsa_private_key_from_xml(PRIVATE_KEY_XML)
        github_url = "https://raw.githubusercontent.com/thayphuctoan/pconvert/refs/heads/main/ocr-pdf"
        response = requests.get(github_url, timeout=10)
        response.raise_for_status()
        
        encrypted_keys = [line.strip() for line in response.text.splitlines() if line.strip()]
        if not encrypted_keys:
            raise ValueError("Không tìm thấy API key đã mã hóa")
        
        token = decrypt_api_key(encrypted_keys[0], rsa_private_key)
        if not token:
            raise ValueError("API key giải mã rỗng")
        return token
    except Exception as e:
        raise Exception(f"Lỗi lấy API key: {str(e)}")

def count_pdf_pages(file_path):
    """Đếm số trang trong file PDF"""
    try:
        with open(file_path, 'rb') as file:
            pdf = PdfReader(file)
            return len(pdf.pages)
    except Exception as e:
        app.logger.error(f"Lỗi khi đếm số trang PDF: {str(e)}")
        return -1

def check_activation(hardware_id):
    """Kiểm tra xem hardware ID có được kích hoạt không"""
    try:
        url = "https://raw.githubusercontent.com/thayphuctoan/pconvert/refs/heads/main/convert-special-1"
        response = requests.get(url, timeout=(10, 30))
        
        if response.status_code == 200:
            valid_ids = response.text.strip().split('\n')
            if hardware_id in valid_ids:
                return True
        return False
    except Exception as e:
        app.logger.error(f"Lỗi khi kiểm tra kích hoạt: {str(e)}")
        return False

def process_ocr(file_path):
    """Xử lý OCR cho file PDF"""
    try:
        # Lấy API key
        api_key = get_mineru_token()
        client = Mistral(api_key=api_key)
        
        # Upload file
        with open(file_path, 'rb') as f:
            file_content = f.read()
            
        uploaded_pdf = client.files.upload(
            file={
                "file_name": os.path.basename(file_path),
                "content": file_content,
            },
            purpose="ocr"
        )
        
        # Lấy signed URL
        signed_url = client.files.get_signed_url(file_id=uploaded_pdf.id)
        
        # Xử lý OCR
        ocr_response = client.ocr.process(
            model="mistral-ocr-latest",
            document={
                "type": "document_url",
                "document_url": signed_url.url,
            },
            include_image_base64=True
        )
        
        # Phân tích kết quả
        result_data = {
            "text": "",
            "images": {}
        }
        
        if hasattr(ocr_response, 'pages'):
            for page in ocr_response.pages:
                if hasattr(page, 'markdown') and page.markdown:
                    result_data["text"] += page.markdown + "\n\n"
                elif hasattr(page, 'text') and page.text:
                    result_data["text"] += page.text + "\n\n"
                
                if hasattr(page, 'images') and page.images:
                    for img in page.images:
                        if hasattr(img, 'id') and hasattr(img, 'image_base64'):
                            result_data["images"][img.id] = img.image_base64
        
        # Làm sạch văn bản
        cleaned_text = result_data["text"]
        cleaned_text = re.sub(r'OCRPageObject\(.*?\)', '', cleaned_text)
        cleaned_text = re.sub(r'OCRPageDimensions\(.*?\)', '', cleaned_text)
        cleaned_text = re.sub(r'images=\[\]', '', cleaned_text)
        cleaned_text = re.sub(r'index=\d+', '', cleaned_text)
        
        # Tiền xử lý
        cleaned_text = re.sub(r'(Câu\s+\d+\.?[:]?)', r'\n\n\1', cleaned_text)
        cleaned_text = re.sub(r'(Bài\s+\d+\.?[:]?)', r'\n\n\1', cleaned_text)
        cleaned_text = re.sub(r'([A-D]\.)', r'\n\1', cleaned_text)
        
        # Chuẩn hóa tham chiếu hình ảnh
        for img_id in result_data["images"].keys():
            pattern = r'!\[.*?\]\(.*?' + re.escape(img_id) + r'.*?\)'
            cleaned_text = re.sub(pattern, f'[HÌNH: {img_id}]', cleaned_text)
            
            pattern = r'!{1,2}\[' + re.escape(img_id) + r'\]'
            cleaned_text = re.sub(pattern, f'[HÌNH: {img_id}]', cleaned_text)
            
            pattern = r'(?<![a-zA-Z0-9\-\.])' + re.escape(img_id) + r'(?![a-zA-Z0-9\-\.])'
            cleaned_text = re.sub(pattern, f'[HÌNH: {img_id}]', cleaned_text)
        
        result_data["text"] = cleaned_text
        return result_data
    
    except Exception as e:
        app.logger.error(f"Lỗi trong quá trình OCR: {str(e)}")
        raise

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    # Kiểm tra hardware ID và kích hoạt
    hardware_id = request.form.get('hardware_id')
    if not hardware_id or not check_activation(hardware_id):
        return jsonify({
            'success': False,
            'error': 'Phần mềm chưa được kích hoạt hoặc Hardware ID không hợp lệ.'
        }), 403
    
    # Kiểm tra file
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'Không có file nào được tải lên'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'Chưa chọn file'}), 400
    
    if file and file.filename.lower().endswith('.pdf'):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Kiểm tra số trang
        page_count = count_pdf_pages(file_path)
        if page_count > 100:
            os.remove(file_path)  # Xóa file
            return jsonify({
                'success': False, 
                'error': f'File có {page_count} trang, vượt quá giới hạn 100 trang.'
            }), 400
        elif page_count <= 0:
            os.remove(file_path)
            return jsonify({
                'success': False, 
                'error': 'Không thể đọc file PDF, vui lòng kiểm tra lại.'
            }), 400
        
        try:
            # Xử lý OCR
            result = process_ocr(file_path)
            
            # Lưu kết quả vào một file tạm thời để tải xuống sau này
            result_path = os.path.join(app.config['UPLOAD_FOLDER'], f"result_{os.path.splitext(filename)[0]}.json")
            with open(result_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False)
            
            # Trả về kết quả
            return jsonify({
                'success': True,
                'filename': filename,
                'page_count': page_count,
                'text': result['text'],
                'image_count': len(result['images']),
                'result_id': os.path.basename(result_path)
            })
            
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
        finally:
            # Xóa file tạm thời
            if os.path.exists(file_path):
                os.remove(file_path)
                
    return jsonify({'success': False, 'error': 'Loại file không được hỗ trợ, chỉ chấp nhận PDF'}), 400

@app.route('/api/hardware-id', methods=['POST'])
def get_hardware_id():
    """API để tạo hardware ID từ thông tin gửi lên"""
    data = request.json
    if not data or not all(k in data for k in ('cpu_id', 'bios_serial', 'motherboard_serial')):
        return jsonify({'success': False, 'error': 'Thiếu thông tin phần cứng'}), 400
    
    combined_info = f"{data['cpu_id']}|{data['bios_serial']}|{data['motherboard_serial']}"
    hardware_id = hashlib.md5(combined_info.encode()).hexdigest().upper()
    formatted_id = '-'.join([hardware_id[i:i+8] for i in range(0, len(hardware_id), 8)])
    formatted_id = formatted_id + "-Premium"
    
    return jsonify({
        'success': True,
        'hardware_id': formatted_id,
        'activated': check_activation(formatted_id)
    })

@app.route('/results/<result_id>', methods=['GET'])
def get_result(result_id):
    """Lấy kết quả OCR đã lưu trước đó"""
    result_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(result_id))
    if not os.path.exists(result_path):
        return jsonify({'success': False, 'error': 'Không tìm thấy kết quả'}), 404
    
    with open(result_path, 'r', encoding='utf-8') as f:
        result = json.load(f)
    
    return jsonify({
        'success': True,
        'text': result['text'],
        'image_count': len(result['images'])
    })

@app.route('/images/<result_id>/<image_id>', methods=['GET'])
def get_image(result_id, image_id):
    """Lấy hình ảnh từ kết quả OCR"""
    result_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(result_id))
    if not os.path.exists(result_path):
        return jsonify({'success': False, 'error': 'Không tìm thấy kết quả'}), 404
    
    with open(result_path, 'r', encoding='utf-8') as f:
        result = json.load(f)
    
    if image_id not in result['images']:
        return jsonify({'success': False, 'error': 'Không tìm thấy hình ảnh'}), 404
    
    # Lưu hình ảnh vào file tạm và gửi về
    img_data = result['images'][image_id]
    if "," in img_data:
        img_data = img_data.split(",", 1)[1]
    
    temp_img_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_{image_id}")
    with open(temp_img_path, 'wb') as f:
        f.write(base64.b64decode(img_data))
    
    @app.after_request
    def cleanup(response):
        if os.path.exists(temp_img_path):
            os.remove(temp_img_path)
        return response
    
    return send_file(temp_img_path, mimetype='image/jpeg')

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
