# Network File Sharing (C++ + Docker) — XOR Encryption

This project provides a simple **client–server file sharing** application written in **C++17**.  
It supports **login authentication**, **file listing**, **download (GET)**, **upload (PUT)**, and a lightweight **XOR encryption** layer for transfer.

Everything is containerized with **Docker** and orchestrated with **Docker Compose** for an easy, reproducible demo.

---

## 📦 Structure

```
.
├── server.cpp
├── client.cpp
├── users.txt
├── server_files/
│   ├── sample.txt
│   └── uploads/
├── Dockerfile.server
├── Dockerfile.client
└── docker-compose.yml
```

---

## 🚀 Quick Start

> Requirements: Docker + Docker Compose

```bash
# Build images
docker-compose build

# Start both containers (server & client)
docker-compose up -d

# See running containers
docker ps

# Open an interactive shell into the client container
docker exec -it file_client bash

# Run the client
./client
# When prompted for IP, press Enter to use default: file_server
# Port: 8080
# Login using a user from users.txt (e.g., alice / alice123)
```

To watch the server logs:
```bash
docker logs -f file_server
```

Stop and clean up:
```bash
docker-compose down
```

---

## 🧪 Try It

Inside the client:
1. Choose **1** to LIST files on the server (you should see `sample.txt`).
2. Choose **2** to GET (download) `sample.txt`.
3. Choose **3** to PUT (upload) any local file from client container to the server.  
   Uploaded files will appear in `server_files/uploads/` inside the server container.

---

## 🔒 Notes on Security

- The XOR scheme is **not secure** cryptography; it’s a lightweight obfuscation used for instructional purposes only.  
- For production, replace with TLS (OpenSSL) or libsodium and store password **hashes** instead of plain text.

---

## 🛠️ Local (Non-Docker) Build (Optional)

```bash
# Server
g++ -std=c++17 -O2 -Wall server.cpp -o server
./server

# Client
g++ -std=c++17 -O2 -Wall client.cpp -o client
./client
```

---

## 📚 Protocol Cheat Sheet

All control messages use a simple framed protocol:
- **send_line / recv_line**: `uint32_t length (network byte order)` + raw bytes (no trailing newline).  
- File transfer uses a **uint64_t size** (big-endian), followed by XOR-encrypted binary chunks.

Commands after authentication:
- `LIST` → returns `OK` + newline-separated file names
- `GET <filename>` → returns `OK` + file bytes (XOR)
- `PUT <filename>` → returns `OK` then expects incoming file bytes (XOR)
- `QUIT` → returns `BYE` and closes

---

## 🧩 Troubleshooting

- **Client can't resolve `file_server`:** In a non-Compose setup, use the server’s IP (e.g., `127.0.0.1`) instead.
- **Port conflicts:** Change `8080:8080` in `docker-compose.yml`.
- **No files listed:** Ensure `server_files/` exists and contains files (`sample.txt` included).

---

## ✅ Credits

Built for a Capstone assignment: Linux Socket Programming + Docker.
