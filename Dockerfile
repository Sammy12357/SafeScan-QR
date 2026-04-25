# Use a lightweight Python image
FROM python:3.11-slim

# Install the missing QR library
RUN apt-get update && apt-get install -y libzbar0

# Set up the folder
WORKDIR /app
COPY . .

# Install your Python libraries
RUN pip install --no-cache-dir -r requirements.txt

# Start the server
CMD uvicorn hackabull:qr_app --host 0.0.0.0 --port $PORT