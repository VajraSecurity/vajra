#ifndef FLEET_THREADPOOL_H
#define FLEET_THREADPOOL_H

#include <boost/asio.hpp>
#include <boost/thread.hpp>

class Thread {
public:
    Thread(boost::asio::io_context &ctx): ctx_(ctx) {}
    void park();
private:
    boost::asio::io_context& ctx_;
};

class ThreadPool {
private:
    boost::asio::io_context io_context_;
    std::vector<std::unique_ptr<boost::thread>> threads_of_ctrl_;
    std::vector<std::unique_ptr<Thread>> user_threads_;
    int pool_size_;
public:
    ThreadPool(int size = boost::thread::hardware_concurrency()):threads_of_ctrl_(size),
                                                                 user_threads_(size),
                                                                 pool_size_(size) {}
    void start();
    void stop();
    void post(std::function<void()>);
};

#endif //FLEET_THREADPOOL_H
