#include "ThreadPool.h"
#include "logger.h"

void Thread::park() {
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work{boost::asio::make_work_guard(ctx_)};
    // io_context::run() lets an exception thrown by a posted handler
    // propagate out of run() rather than swallowing it. Left unguarded, that
    // exception would unwind straight out of this function -- the entry
    // point of a boost::thread -- which calls std::terminate() and crashes
    // the entire process over a single bad posted task. Catch, log, and call
    // run() again (the documented Boost.Asio pattern for this exact
    // situation) so this worker keeps processing the remaining work instead.
    for (;;) {
        try {
            ctx_.run();
            break;  // returned normally: no more work, or stop() was called
        } catch (const std::exception& e) {
            BOOST_LOG_TRIVIAL(error) << "ThreadPool worker: unhandled exception from a posted task: "
                                      << e.what();
        } catch (...) {
            BOOST_LOG_TRIVIAL(error) << "ThreadPool worker: unknown unhandled exception from a posted task";
        }
    }
}

void ThreadPool::post(std::function<void()> fn)
{
    try {
        boost::asio::post(io_context_, fn);
    } catch (const std::exception& e) {
        // Fire-and-forget dispatch API (void return, no failure contract for
        // callers to check) -- logging is the best available signal if the
        // post itself throws (e.g. allocation failure), consistent with the
        // rest of this class not propagating worker-side failures to callers.
        BOOST_LOG_TRIVIAL(error) << "ThreadPool::post: failed to enqueue task: " << e.what();
    }
}

void ThreadPool::start()
{
    for (auto i = 0; i < pool_size_; ++i)
    {
        try {
            user_threads_[i] = std::make_unique<Thread>(io_context_);
            threads_of_ctrl_[i] = std::make_unique<boost::thread>(&Thread::park, user_threads_[i].get());
        } catch (const std::exception& e) {
            BOOST_LOG_TRIVIAL(fatal) << "ThreadPool::start: failed to create worker " << i << ": "
                                      << e.what();
            throw;
        }
    }
}

void ThreadPool::stop()
{
    io_context_.stop();
    for (auto i = 0; i < pool_size_; ++i)
    {
        try {
            if (threads_of_ctrl_[i]) threads_of_ctrl_[i]->join();
        } catch (const std::exception& e) {
            // Log and keep joining the rest -- one thread's join() failing
            // must not leave the others un-joined (resource/shutdown-hang risk).
            BOOST_LOG_TRIVIAL(error) << "ThreadPool::stop: failed to join worker " << i << ": "
                                      << e.what();
        }
    }
}