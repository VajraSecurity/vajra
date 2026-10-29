#include "KafkaProducerManager.h"

// Static member initialization
std::unique_ptr<KafkaProducerManager> KafkaProducerManager::instance_ = nullptr;
std::mutex KafkaProducerManager::instance_mutex_;
