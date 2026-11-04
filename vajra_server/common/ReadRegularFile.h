#pragma once

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <string>

namespace vajra_common {

inline constexpr std::size_t kDefaultMaxFileBytes = 256 * 1024 * 1024;

// Reads a whole configuration or ruleset file whose path is set by the operator
// (a command-line argument or environment variable). Checks and reads through one
// descriptor, so the file checked is the file read. Only regular files are accepted:
// O_NONBLOCK stops a FIFO from hanging startup. Symlinks are followed because
// container config mounts rely on them. Throws std::runtime_error on failure.
inline std::string read_regular_file(const std::string& path, std::size_t max_bytes = kDefaultMaxFileBytes) {
    const int fd = ::openat(AT_FDCWD, path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        throw std::runtime_error(std::strerror(errno));
    }

    struct Closer {
        int fd;
        ~Closer() { ::close(fd); }
    } closer{fd};

    struct stat info {};
    if (::fstat(fd, &info) != 0) {
        throw std::runtime_error(std::strerror(errno));
    }
    if (!S_ISREG(info.st_mode)) {
        throw std::runtime_error("not a regular file");
    }

    std::string contents;
    char chunk[64 * 1024];
    for (;;) {
        const ssize_t got = ::read(fd, chunk, sizeof(chunk));
        if (got < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error(std::strerror(errno));
        }
        if (got == 0) return contents;
        if (static_cast<std::size_t>(got) > max_bytes - contents.size()) {
            throw std::runtime_error("file is larger than the allowed size");
        }
        contents.append(chunk, static_cast<std::size_t>(got));
    }
}

}  // namespace vajra_common
