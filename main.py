from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename
import os
import numpy as np
from PIL import Image
from datetime import datetime
from tiny_rc4 import cipher_to_text, tinyrc4_keystream, rc4_encrypt, rc4_decrypt, parse_key

app = Flask(__name__, static_url_path='/static')
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
app.config['OUTPUT_FOLDER'] = os.path.join(BASE_DIR, 'output')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'bmp'}

# Tạo thư mục
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['OUTPUT_FOLDER'], exist_ok=True)
#hàm kiểm tra file có hợp lệ không (cái này tôi copy từ stackoverflow nên là thừa nhận luôn đi-)
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def rc4_process_image(input_path, output_path, key):
    img = Image.open(input_path)
    has_alpha = img.mode == 'RGBA'
    if has_alpha: 
        #mỗi pixel thì có 3 kênh là R G B (hệ RGB), ngoài ra còn có kênh alpha A để biểu thị độ trong suốt của pixel đó (hệ RGBA)
        #nếu ảnh có alpha channel thì tách riêng alpha ra để giữ nguyên, chỉ xử lý 3 kênh còn lại
        #tức là mình chỉ xử lý phần RGB của ảnh, còn phần alpha thì giữ nguyên để đảm bảo ảnh sau khi mã hóa/giải mã vẫn giữ được độ trong suốt nếu có
        #nếu mà không tách riêng alpha thì sau khi mã hóa rồi giải mã lại thì ảnh sẽ không được như ban đầu
        #còn cách khác là mã hóa cả kênh alpha nữa nhưng mà thôi giữ nguyên cho đơn giản
        alpha = img.split()[3]
        img_rgb = img.convert('RGB')
        img_array = np.array(img_rgb)
    else:
        img_array = np.array(img.convert('RGB'))
    original_shape = img_array.shape
    flat_data = img_array.flatten()
    # Sinh keystream
    keystream, steps = tinyrc4_keystream(key, len(flat_data))
    # XOR để mã hóa/giải mã
    processed = np.array([
        flat_data[i] ^ keystream[i] 
        for i in range(len(flat_data))
    ], dtype=np.uint8)
    processed_img = Image.fromarray(
        processed.reshape(original_shape), 'RGB'
    )
    if has_alpha:
        processed_img.putalpha(alpha)
    processed_img.save(output_path, format='PNG')
    print(f"Saved: {output_path}")
    return steps[:100] #trả về 100 bước đầu tiên

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    cipher_text = None
    decrypted = None    
    steps = []
    image_result = None
    image_steps = []
    if request.method == 'POST':
        #mã hóa hoặc giải mã plaintext
        if 'plaintext' in request.form and request.form['plaintext']:
            plaintext = request.form['plaintext']
            key_input = request.form["key"]
            try:
                key = parse_key(key_input)
                cipher, ks, steps = rc4_encrypt(plaintext, key)
                cipher_text = cipher_to_text(cipher) 
                result = cipher
                decrypted = rc4_decrypt(cipher, key)
            except Exception as e:
                steps = [f"Error: {str(e)}"]
        #mã hóa ảnh
        elif 'image' in request.files:
            file = request.files['image']
            if file and file.filename and allowed_file(file.filename):
                try:
                    key_str = request.form.get('key')
                    key = parse_key(key_str) #chuyển key từ chuỗi "2,1,3" thành list [2,1,3]
                    mode = request.form.get('mode', 'encrypt')
                    # Lưu file
                    filename = secure_filename(file.filename).replace(' ', '_') #loại bỏ dấu cách và ký tự đặc biệt để tránh lỗi khi lưu file
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S') #thêm timestamp để tránh trùng tên file khi upload nhiều ảnh cùng tên
                    
                    input_filename = f'{timestamp}_input_{filename}'
                    output_filename = f'{timestamp}_{mode}_{filename}'
                    input_path = os.path.join(app.config['UPLOAD_FOLDER'], input_filename)
                    output_path = os.path.join(app.config['OUTPUT_FOLDER'], output_filename)
                    # Lưu ảnh upload
                    file.save(input_path)
                    print(f"Uploaded: {input_path}")
                    # Xử lý ảnh
                    image_steps = rc4_process_image(input_path, output_path, key)
                    # Lưu kết quả để hiển thị
                    image_result = {
                        'input': input_filename,
                        'output': output_filename,
                        'mode': mode
                    }
                except Exception as e:
                    image_steps = [f"Error: {str(e)}"]
                    import traceback
                    traceback.print_exc()
            else:
                image_steps = ["Error: Chưa chọn ảnh hoặc file không hợp lệ"]
    return render_template(
        'index.html',
        result=result,
        cipher_text=cipher_text,
        decrypted=decrypted,
        steps=steps,
        
        
        image_result=image_result,
        image_steps=image_steps, key = key
    )

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))

@app.route('/output/<filename>')
def output_file(filename):
    return send_file(os.path.join(app.config['OUTPUT_FOLDER'], filename))

@app.route('/download/<filename>')
def download(filename):
    path = os.path.join(app.config['OUTPUT_FOLDER'], filename)
    if os.path.exists(path):
        return send_file(path, as_attachment=True, download_name=filename)
    return "File not found", 404

if __name__ == '__main__':
    app.run(debug=True)