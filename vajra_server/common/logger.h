#ifndef FLEET_LOGGER_H
#define FLEET_LOGGER_H

#define BOOST_LOG_DYN_LINK 1

#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <iostream>
#include <sstream>

namespace logging = boost::log;
namespace keywords = boost::log::keywords;

inline void init_logging(const std::string& logfile, unsigned char log_level, long long log_size,
                          bool console_output = false)
{
    logging::register_simple_formatter_factory<logging::trivial::severity_level, char>("Severity");

    static constexpr const char* kLogFormat =
        "[%TimeStamp%] [%ThreadID%] [%Severity%] [%ProcessID%] [%LineID%] %Message%";

    logging::add_file_log(
            keywords::file_name = logfile,
            keywords::format = kLogFormat,
            keywords::open_mode = std::ios_base::app,
            keywords::auto_flush = true,
            keywords::rotation_size = log_size,
            keywords::time_based_rotation = logging::sinks::file::rotation_at_time_point(0,0,0)
    );

    // Optional second sink, mirroring the file sink to stdout (captured by
    // systemd/journalctl when running as a service). Deliberately NOT given
    // its own keywords::filter -- with none set, a sink defers to the
    // process-wide filter set below via logging::core::get()->set_filter(),
    // so console output obeys the exact same log_level threshold as the
    // file, never a separate/looser one. Off by default (log_configuration
    // .console_output in config.json) since continuous per-request debug
    // output to the journal is real noise/volume on a busy fleet -- an
    // operator opts in deliberately.
    if (console_output)
    {
        logging::add_console_log(
                std::cout,
                keywords::format = kLogFormat
        );
    }

    switch (log_level)
    {
        case 0:
            logging::core::get()->set_filter(logging::trivial::severity >= logging::trivial::trace);
            break;
        case 1:
            logging::core::get()->set_filter(logging::trivial::severity >= logging::trivial::debug);
            break;
        case 2:
            logging::core::get()->set_filter(logging::trivial::severity >= logging::trivial::info);
            break;
        case 3:
            logging::core::get()->set_filter(logging::trivial::severity >= logging::trivial::warning);
            break;
        case 4:
            logging::core::get()->set_filter(logging::trivial::severity >= logging::trivial::error);
            break;
        case 5:
            logging::core::get()->set_filter(logging::trivial::severity >= logging::trivial::fatal);
            break;
        default:
            logging::core::get()->set_filter(logging::trivial::severity >= logging::trivial::warning);
    };

    logging::add_common_attributes();
}

constexpr inline const char* __filename(const char* path)
{
    const char* file = path;
    while (*path) {
        if (*path++ == '/') {
            file = path;
        }
    }
    return file;
}

inline std::string srcref(const char* filename, int line)
{
    std::stringstream ss;
    ss << "[" << filename << ":" << line << "] ";
    return ss.str();
}

#define __FILENAME__ __filename(__FILE__)
#define __SRCREF__ srcref(__FILENAME__, __LINE__)

#endif //FLEET_LOGGER_H
