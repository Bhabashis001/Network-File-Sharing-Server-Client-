// client.cpp (C++17)
// Network File Sharing Client with simple XOR "encryption"
// Build: g++ -std=c++17 -O2 -Wall client.cpp -o client
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

static const uint8_t XOR_KEY = 0x5A;

bool send_all(int fd, const void* data, size_t len) {
    const char* p = (const char*)data;
    while (len > 0) {
        ssize_t s = send(fd, p, len, 0);
        if (s <= 0) return false;
        p += s;
        len -= (size_t)s;
    }
    return true;
}

bool recv_all(int fd, void* data, size_t len) {
    char* p = (char*)data;
    while (len > 0) {
        ssize_t r = recv(fd, p, len, 0);
        if (r <= 0) return false;
        p += r;
        len -= (size_t)r;
    }
    return true;
}

bool send_line(int fd, const std::string& s) {
    uint32_t n = htonl((uint32_t)s.size());
    if (!send_all(fd, &n, sizeof(n))) return false;
    if (!send_all(fd, s.data(), s.size())) return false;
    return true;
}

bool recv_line(int fd, std::string& out) {
    uint32_t n = 0;
    if (!recv_all(fd, &n, sizeof(n))) return false;
    n = ntohl(n);
    out.assign(n, '\0');
    if (n == 0) return true;
    if (!recv_all(fd, out.data(), n)) return false;
    return true;
}

void xor_in_place(std::vector<char>& buf, size_t n) {
    for (size_t i = 0; i < n; ++i) buf[i] ^= XOR_KEY;
}

// byte order helpers (portable 64-bit conversions)
uint64_t host_to_be64(uint64_t host) {
    uint32_t hi = htonl((uint32_t)(host >> 32));
    uint32_t lo = htonl((uint32_t)(host & 0xFFFFFFFFULL));
    return ( (uint64_t)lo << 32 ) | hi;
}
uint64_t be64_to_host(uint64_t be) {
    uint32_t lo = ntohl((uint32_t)(be >> 32));
    uint32_t hi = ntohl((uint32_t)(be & 0xFFFFFFFFULL));
    return ( (uint64_t)hi << 32 ) | lo;
}

bool recv_file_encrypted(int fd, const std::string& path) {
    uint64_t size_be = 0;
    if (!recv_all(fd, &size_be, sizeof(size_be))) return false;
    uint64_t size = be64_to_host(size_be);

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;

    std::vector<char> buf(64 * 1024);
    uint64_t left = size;
    uint64_t done = 0;

    while (left > 0) {
        size_t chunk = (size_t)std::min<uint64_t>(buf.size(), left);
        if (!recv_all(fd, buf.data(), chunk)) return false;
        xor_in_place(buf, chunk);
        out.write(buf.data(), (std::streamsize)chunk);
        left -= chunk;
        done += chunk;
        std::cout << "\rDownloaded " << done << " / " << size << " bytes" << std::flush;
    }
    std::cout << "\n";
    return true;
}

bool send_file_encrypted(int fd, const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;

    in.seekg(0, std::ios::end);
    uint64_t size = (uint64_t)in.tellg();
    in.seekg(0, std::ios::beg);

    uint64_t size_be = host_to_be64(size);
    if (!send_all(fd, &size_be, sizeof(size_be))) return false;

    std::vector<char> buf(64 * 1024);
    uint64_t done = 0;

    while (in) {
        in.read(buf.data(), (std::streamsize)buf.size());
        std::streamsize got = in.gcount();
        if (got <= 0) break;
        xor_in_place(buf, (size_t)got);
        if (!send_all(fd, buf.data(), (size_t)got)) return false;
        done += (uint64_t)got;
        std::cout << "\rUploaded " << done << " / " << size << " bytes" << std::flush;
    }
    std::cout << "\n";
    return true;
}

int main() {
    std::string server_ip = "file_server"; // default for Docker Compose
    int port = 8080;

    std::cout << "Server IP [" << server_ip << "]: ";
    std::string ip_in; std::getline(std::cin, ip_in);
    if (!ip_in.empty()) server_ip = ip_in;

    std::cout << "Port [" << port << "]: ";
    std::string port_in; std::getline(std::cin, port_in);
    if (!port_in.empty()) port = std::stoi(port_in);

    int cfd = socket(AF_INET, SOCK_STREAM, 0);
    if (cfd < 0) { perror("socket"); return 1; }

    sockaddr_in srv{};
    srv.sin_family = AF_INET;
    srv.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip.c_str(), &srv.sin_addr) <= 0) {
        std::cerr << "Invalid IP or hostname resolution failed.\n";
        return 1;
    }

    if (connect(cfd, (sockaddr*)&srv, sizeof(srv)) < 0) {
        perror("connect"); return 1;
    }

    // ---- AUTH ----
    std::string user, pass;
    std::cout << "Login: "; std::getline(std::cin, user);
    std::cout << "Password: "; std::getline(std::cin, pass);

    std::ostringstream auth;
    auth << "AUTH " << user << " " << pass;
    if (!send_line(cfd, auth.str())) { std::cerr << "Send failed\n"; return 1; }

    std::string resp;
    if (!recv_line(cfd, resp)) { std::cerr << "No auth response\n"; return 1; }
    if (resp != "AUTH_OK") {
        std::cerr << "Authentication failed.\n"; return 1;
    }
    std::cout << "Authentication successful.\n";

    // ---- Menu loop ----
    while (true) {
        std::cout <<
            "\n1) List server files\n"
            "2) Download (GET)\n"
            "3) Upload (PUT)\n"
            "4) Quit\n"
            "Choose: ";
        std::string ch; std::getline(std::cin, ch);

        if (ch == "1") {
            if (!send_line(cfd, "LIST")) { std::cerr << "send error\n"; break; }
            if (!recv_line(cfd, resp)) { std::cerr << "recv error\n"; break; }
            if (resp != "OK") { std::cerr << "Server error: " << resp << "\n"; continue; }
            if (!recv_line(cfd, resp)) { std::cerr << "recv error\n"; break; }
            std::cout << "\n--- Files on server ---\n" << resp << "-----------------------\n";
        }
        else if (ch == "2") {
            std::string fname;
            std::cout << "Enter filename to download: ";
            std::getline(std::cin, fname);
            if (fname.empty()) continue;

            std::ostringstream cmd; cmd << "GET " << fname;
            if (!send_line(cfd, cmd.str())) { std::cerr << "send error\n"; break; }
            if (!recv_line(cfd, resp)) { std::cerr << "recv error\n"; break; }

            if (resp != "OK") {
                std::cerr << "Server: " << resp << "\n"; continue;
            }
            std::string outpath = fname; // save locally with same name
            std::cout << "Downloading to '" << outpath << "'...\n";
            if (!recv_file_encrypted(cfd, outpath)) {
                std::cerr << "Download failed.\n"; break;
            }
            std::cout << "Download complete.\n";
        }
        else if (ch == "3") {
            std::string path;
            std::cout << "Enter local file path to upload: ";
            std::getline(std::cin, path);
            if (path.empty()) continue;

            // Derive filename part
            std::string fname = path;
            auto pos = fname.find_last_of("/\\");
            if (pos != std::string::npos) fname = fname.substr(pos + 1);

            std::ostringstream cmd; cmd << "PUT " << fname;
            if (!send_line(cfd, cmd.str())) { std::cerr << "send error\n"; break; }
            if (!recv_line(cfd, resp)) { std::cerr << "recv error\n"; break; }
            if (resp != "OK") { std::cerr << "Server: " << resp << "\n"; continue; }

            std::cout << "Uploading '" << fname << "'...\n";
            if (!send_file_encrypted(cfd, path)) {
                std::cerr << "Upload failed.\n"; break;
            }
            std::cout << "Upload complete.\n";
        }
        else if (ch == "4") {
            send_line(cfd, "QUIT");
            if (recv_line(cfd, resp) && resp == "BYE") {
                std::cout << "Goodbye!\n";
            }
            break;
        }
        else {
            std::cout << "Invalid choice.\n";
        }
    }

    close(cfd);
    return 0;
}
