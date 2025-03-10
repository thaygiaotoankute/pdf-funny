FROM python:3.10-slim

WORKDIR /app

# Cài đặt các dependencies cần thiết
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Sao chép requirements.txt trước để tận dụng docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Sao chép tất cả code vào container
COPY . .

# Tạo thư mục uploads
RUN mkdir -p uploads

# Expose port cần thiết
EXPOSE 8080

# Thiết lập command để chạy ứng dụng
CMD gunicorn app:app --bind 0.0.0.0:$PORT
