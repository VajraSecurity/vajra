#ifndef FLEET_RULEBUILDERENGINE_H
#define FLEET_RULEBUILDERENGINE_H

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "../3rdparty/json.hpp"
#include "../common/EdrDataTypes.h"
#include "../common/ConnectionPool.h"

class Rule_Builder {
private:
    std::shared_ptr<ConnectionPool> pool;
    std::shared_ptr<ConnectionPool> conn_pool;
public:
    Rule_Builder(std::shared_ptr<ConnectionPool>);

    void run();
    [[noreturn]] void run_rule_builder();

};

#endif //FLEET_RULEBUILDERENGINE_H