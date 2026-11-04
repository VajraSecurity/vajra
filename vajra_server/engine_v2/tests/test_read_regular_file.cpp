#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

#include "../../common/ReadRegularFile.h"
#include "catch2/catch.hpp"

namespace {

struct TempDir {
    std::filesystem::path path;
    TempDir() {
        std::string name = (std::filesystem::temp_directory_path() / "vajra_read_file_XXXXXX").string();
        REQUIRE(::mkdtemp(name.data()) != nullptr);
        path = name;
    }
    ~TempDir() { std::filesystem::remove_all(path); }
};

void write_file(const std::filesystem::path& path, const std::string& contents) {
    std::ofstream out(path, std::ios::binary);
    out << contents;
}

}  // namespace

TEST_CASE("read_regular_file returns the whole file", "[read_regular_file]") {
    TempDir dir;
    const std::string contents(200 * 1024, 'x');
    write_file(dir.path / "big", contents);
    CHECK(vajra_common::read_regular_file((dir.path / "big").string()) == contents);
}

TEST_CASE("read_regular_file reads an empty file", "[read_regular_file]") {
    TempDir dir;
    write_file(dir.path / "empty", "");
    CHECK(vajra_common::read_regular_file((dir.path / "empty").string()).empty());
}

TEST_CASE("read_regular_file follows symlinks", "[read_regular_file]") {
    TempDir dir;
    write_file(dir.path / "real", "data");
    std::filesystem::create_symlink(dir.path / "real", dir.path / "link");
    CHECK(vajra_common::read_regular_file((dir.path / "link").string()) == "data");
}

TEST_CASE("read_regular_file refuses anything else", "[read_regular_file]") {
    TempDir dir;
    CHECK_THROWS_AS(vajra_common::read_regular_file((dir.path / "missing").string()), std::runtime_error);
    CHECK_THROWS_AS(vajra_common::read_regular_file(dir.path.string()), std::runtime_error);

    const auto fifo = dir.path / "fifo";
    REQUIRE(::mkfifo(fifo.c_str(), 0600) == 0);
    CHECK_THROWS_AS(vajra_common::read_regular_file(fifo.string()), std::runtime_error);
}

TEST_CASE("read_regular_file enforces the size limit", "[read_regular_file]") {
    TempDir dir;
    write_file(dir.path / "file", "12345");
    CHECK(vajra_common::read_regular_file((dir.path / "file").string(), 5) == "12345");
    CHECK_THROWS_AS(vajra_common::read_regular_file((dir.path / "file").string(), 4), std::runtime_error);
}
