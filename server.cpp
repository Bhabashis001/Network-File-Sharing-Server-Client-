// server.cpp (C++17)
// Network File Sharing Server with simple XOR "encryption"
// Build: g++ -std=c++17 -O2 -Wall server.cpp -o server
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstdint>

static const int PORT = 8080;
static const uint8_t XOR_KEY = 0x5A;           // Simple XOR "encryption"
static const std::string ROOT_DIR = "server_files";
static const std::string UPLOAD_DIR = "server_files/uploads";
static const std::string USERS_FILE = "users.txt";

int listen_fd = -1;

void handle_sigint(int) {
    if (listen_fd != -1) close(listen_fd);
    std::cerr << "\nServer shutting down...\n";
    std::_Exit(0);
}

// ---- byte order helpers (portable 64-bit conversions without <endian.h>) ----
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

// ---- small helpers ----
bool ensure_dirs() {
    // make sure ROOT_DIR and UPLOAD_DIR exist
    if (mkdir(ROOT_DIR.c_str(), 0755) && errno != EEXIST) return false;
    if (mkdir(UPLOAD_DIR.c_str(), 0755) && errno != EEXIST) return false;
    return true;
}

void xor_in_place(std::vector<char>& buf, size_t n) {
    for (size_t i = 0; i < n; ++i) buf[i] ^= XOR_KEY;
}

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

// Line protocol: uint32 length (network order) + bytes
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

// very basic filename sanitizer: reject path traversal and slashes
bool safe_filename(const std::string& name) {
    return !name.empty() &&
           name.find("..") == std::string::npos &&
           name.find('/') == std::string::npos &&
           name.find('\\') == std::string::npos;
}

bool check_auth(const std::string& user, const std::string& pass) {
    std::ifstream in(USERS_FILE);
    if (!in) return false;
    std::string line;
    while (std::getline(in, line)) {
        auto pos = line.find(':');
        if (pos == std::string::npos) continue;
        std::string u = line.substr(0, pos);
        std::string p = line.substr(pos + 1);
        if (u == user && p == pass) return true;
    }
    return false;
}

std::string list_files() {
    std::ostringstream oss;
    DIR* dir = opendir(ROOT_DIR.c_str());
    if (!dir) return "ERR: cannot open server_files\n";
    struct dirent* de;
    while ((de = readdir(dir)) != nullptr) {
        std::string n = de->d_name;
        if (n == "." || n == ".." || n == "uploads") continue;
        oss << n << "\n";
    }
    closedir(dir);
    return oss.str();
}

bool send_file_encrypted(int fd, const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;

    // get size
    in.seekg(0, std::ios::end);
    uint64_t size = (uint64_t)in.tellg();
    in.seekg(0, std::ios::beg);

    uint64_t size_be = host_to_be64(size);
    if (!send_all(fd, &size_be, sizeof(size_be))) return false;

    std::vector<char> buf(64 * 1024);
    while (in) {
        in.read(buf.data(), (std::streamsize)buf.size());
        std::streamsize got = in.gcount();
        if (got <= 0) break;
        xor_in_place(buf, (size_t)got);
        if (!send_all(fd, buf.data(), (size_t)got)) return false;
    }
    return true;
}

bool recv_file_encrypted(int fd, const std::string& path) {
    uint64_t size_be = 0;
    if (!recv_all(fd, &size_be, sizeof(size_be))) return false;
    uint64_t size = be64_to_host(size_be);

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;

    std::vector<char> buf(64 * 1024);
    uint64_t left = size;
    while (left > 0) {
        size_t chunk = (size_t)std::min<uint64_t>(buf.size(), left);
        if (!recv_all(fd, buf.data(), chunk)) return false;
        xor_in_place(buf, chunk);
        out.write(buf.data(), (std::streamsize)chunk);
        left -= chunk;
    }
    return true;
}

void handle_client(int cfd, sockaddr_in cliaddr) {
    char ip[64];
    inet_ntop(AF_INET, &cliaddr.sin_addr, ip, sizeof(ip));
    std::cout << "Client connected from " << ip << ":" << ntohs(cliaddr.sin_port) << "\n";

    // 1) AUTH
    // Expect: "AUTH <user> <pass>"
    std::string line;
    if (!recv_line(cfd, line)) { close(cfd); return; }

    {
        std::istringstream iss(line);
        std::string cmd, user, pass;
        iss >> cmd >> user >> pass;
        if (cmd != "AUTH" || user.empty() || pass.empty() || !check_auth(user, pass)) {
            send_line(cfd, "AUTH_FAIL");
            close(cfd);
            std::cout << "Auth failed for client.\n";
            return;
        }
        send_line(cfd, "AUTH_OK");
        std::cout << "Auth OK for user: " << user << "\n";
    }

    // Command loop
    while (true) {
        if (!recv_line(cfd, line)) break;
        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;

        if (cmd == "LIST") {
            auto data = list_files();
            send_line(cfd, "OK");
            send_line(cfd, data); // newline-separated list
        }
        else if (cmd == "GET") {
            std::string fname; iss >> fname;
            if (!safe_filename(fname)) { send_line(cfd, "ERR BadName"); continue; }
            std::string path = ROOT_DIR + "/" + fname;
            std::ifstream test(path, std::ios::binary);
            if (!test.good()) { send_line(cfd, "ERR NotFound"); continue; }
            send_line(cfd, "OK");
            if (!send_file_encrypted(cfd, path)) { break; }
        }
        else if (cmd == "PUT") {
            std::string fname; iss >> fname;
            if (!safe_filename(fname)) { send_line(cfd, "ERR BadName"); continue; }
            std::string path = UPLOAD_DIR + "/" + fname;
            send_line(cfd, "OK");
            if (!recv_file_encrypted(cfd, path)) { break; }
        }
        else if (cmd == "QUIT") {
            send_line(cfd, "BYE");
            break;
        }
        else {
            send_line(cfd, "ERR UnknownCmd");
        }
    }

    close(cfd);
    std::cout << "Client disconnected.\n";
}

int main() {
    std::signal(SIGINT, handle_sigint);
    if (!ensure_dirs()) {
        std::cerr << "Failed to ensure directories.\n";
        return 1;
    }

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(listen_fd, (sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(listen_fd, 8) < 0) { perror("listen"); return 1; }

    std::cout << "Server listening on port " << PORT << "...\n";

    while (true) {
        sockaddr_in cli{};
        socklen_t len = sizeof(cli);
        int cfd = accept(listen_fd, (sockaddr*)&cli, &len);
        if (cfd < 0) { perror("accept"); continue; }
        // Simple sequential handling (one client at a time).
        handle_client(cfd, cli);
    }
}
