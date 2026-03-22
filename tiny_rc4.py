from flask import Flask, render_template, request
app = Flask(__name__,static_url_path='/static')

#hàm lấy ra key từ chuỗi nhập vào, 2,1,3 hay [2,1,3] hay (2,1,3) hay 2 1 3 đều được
def parse_key(key_input):
    key_str = str(key_input).strip() #chuyển key_input thành chuỗi và loại bỏ khoảng trắng ở đầu và cuối
    # Loại bỏ ngoặc
    key_str = key_str.replace('[', '').replace(']', '')
    key_str = key_str.replace('{', '').replace('}', '')
    key_str = key_str.replace('(', '').replace(')', '')
    # Thay space thành dấu phẩy
    key_str = key_str.replace(' ', ',')
    # Split và parse (sau khi xóa hết dấu ngoặc và thay space thành dấu phẩy, key_str sẽ chỉ còn là một chuỗi số cách nhau bởi dấu phẩy, ví dụ "2,1,3")
    key_parts = [k.strip() for k in key_str.split(',') if k.strip()]
    key = [int(k) for k in key_parts] #ép lại thành số nguyên và lấy ra list key
    return key
#tạo khóa dòng
def tinyrc4_keystream(key, n):
    # key = [int(k.strip()) for k in key.split(',')] #nhập
    # key = [int(k) for k in key]
    
    key = parse_key(key)
    S = list(range(8)) #khởi tạo dãy S từ 0 đến 7 (S là cố định theo dãy 01234567 )
    T = [key[i % len(key)] for i in range(8)] #tạo dãy T bằng cách lặp lại key cho đủ 8 phần tử (ví dụ key là 2,1,3 thì sẽ là 2,1,3,2,1,3,2,1)
    j = 0
    steps = []
    #giai đoạn khởi tạo
    for i in range(8):
        j = (j + S[i] + T[i]) % 8
        S[i], S[j] = S[j], S[i]
        steps.append(f"KSA Step {i}: S = {S}") #hoán vị S dựa theo key
    i = 0
    j = 0
    keystream = []
    #giai đoạn sinh số (sinh keystream từ key đã khởi tạo) (để XOR với plaintext)
    for step in range(n):
        i = (i + 1) % 8
        j = (j + S[i]) % 8
        S[i], S[j] = S[j], S[i]
        t = (S[i] + S[j]) % 8
        k = S[t]
        
        #vì k chỉ có giá trị từ 0 đến 7 nên để mở rộng thành byte (0-255) thì nhân với 255/7, tức là k=0 sẽ cho ra 0, k=7 sẽ cho ra 255, các giá trị trung gian sẽ được trải đều trong khoảng này
        keystream.append((k*255)//7) #nếu đổi thành chỉ append(k) thôi thì nó sẽ ảnh hưởng đến mã hóa ảnh vì k chỉ có 8 giá trị nên sẽ không đủ để XOR với pixel (0 đến 255), còn nếu nhân lên thì sẽ trải đều hơn
        steps.append(f"PRGA Step {step}: k = {k}")
    return keystream, steps
#mã hóa plaintext
def rc4_encrypt(data, key):
    ks, steps = tinyrc4_keystream(key, len(data))
    result = []
    for i, c in enumerate(data):
        result.append(ord(c) ^ ks[i]) #XOR plaintext với keystream để tạo cipher text 
        #(slide của thầy là mỗi ký tự 3 bit thôi, nhưng trong đây tôi dùng 8 bit theo hệ mã ascii luôn)
    return result, ks, steps
#giải mã ciphertext
def rc4_decrypt(cipher, key):
    ks, _ = tinyrc4_keystream(key, len(cipher))
    result = ""
    for i, c in enumerate(cipher):
        result += chr(c ^ ks[i]) #XOR ngược lại cipher text với keystream để giải mã thành plaintext ban đầu
    return result
def cipher_to_text(cipher_list):
    try:
        result = ""
        for c in cipher_list:
            if 0 <= c <= 255:
                result += chr(c)
            else:
                result += f"[{c}]"  # Hiển thị số nếu ngoài khoảng (tức là chỉ convert trong bộ mã ASCII thôi)
        return result
    except Exception as e:
        return f"Error: {str(e)}"
@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    cipher_text = None
    decrypted = None    
    steps = []
    key = None
    if request.method == "POST":
        if "plaintext" in request.form:
            plaintext = request.form["plaintext"]
            key_input = request.form["key"]
            try:
                key = parse_key(key_input)
                cipher, ks, steps = rc4_encrypt(plaintext, key)
                cipher_text = cipher_to_text(cipher) 
                result = cipher
                decrypted = rc4_decrypt(cipher, key)
            except Exception as e:
                steps = [f"Error: {str(e)}"]
    return render_template(
        "tiny_rc4_only.html",
        result=result,
        cipher_text=cipher_text,
        decrypted=decrypted,
        steps=steps, key = key
    )
if __name__ == "__main__":
    app.run(debug=True)