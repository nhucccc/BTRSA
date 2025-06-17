📁 SECURE FILE TRANSFER APP (RSA Digital Signature)

Ứng dụng truyền file bảo mật có xác thực chữ ký số RSA, được xây dựng bằng Python + Flask + HTML + TailwindCSS.


🚀 Tính năng chính:

✅ Đăng ký, đăng nhập, đăng xuất

✅ Gửi file kèm chữ ký số RSA cho người dùng khác

✅ Nhận, xác minh chữ ký file đã gửi

✅ Tải xuống file gốc hoặc chữ ký

✅ Giao diện đơn giản, đẹp với TailwindCSS

✅ Lưu người dùng và lịch sử vào file .json

✅ Không dùng database hay framework frontend phức tạp

🛠️ Công nghệ sử dụng
Python 3

Flask

HTML + TailwindCSS (CDN)

Thư viện rsa để ký/kiểm tra chữ ký số

JSON lưu dữ liệu (users.json, history.json)

Tương thích với Visual Studio Code

- Cài đặt thư viện:
pip install flask rsa
- Chạy ứng dụng:
python app.py
- Truy cập trình duyệt:
http://127.0.0.1:5000/

🔐 Bảo mật

Mỗi người dùng khi đăng ký được cấp 1 cặp khóa RSA (512-bit hoặc cao hơn).

File được ký bằng private key của người gửi.

Người nhận xác minh bằng public key của người gửi.

File .sig chứa chữ ký sẽ được gửi kèm file gốc.

📸 Giao diện đăng ký 

![Giao diện Đăng ký](https://github.com/nhucccc/BTRSA/blob/main/rsa1.png)

📸 Giao diện đăng nhập

![Giao diện Đăng nhập](https://github.com/nhucccc/BTRSA/blob/main/rsa2.png)

📸 Giao diện mẫu

Gửi file	Nhận & xác minh

![Giao diện gửi file và xác minh](https://github.com/nhucccc/BTRSA/blob/main/rsa3.png)


📸 Lịch sử truyền file

![Giao diện Lịch sử truyền file](https://github.com/nhucccc/BTRSA/blob/main/rsa4.png)


📝 License
MIT License. Dự án được xây dựng với mục đích học tập và nghiên cứu.








