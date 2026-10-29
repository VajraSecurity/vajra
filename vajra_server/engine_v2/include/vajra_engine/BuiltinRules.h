#ifndef VAJRA_ENGINE_BUILTIN_RULES_H
#define VAJRA_ENGINE_BUILTIN_RULES_H

#include <vector>

#include "vajra_engine/Rule.h"

namespace vajra_engine {

// Small starter ruleset used when no VAJRA_ENGINE_RULES ruleset file is
// configured: a shell-exec anchor (100, no_log) chaining into a
// download-piped-into-shell rule (101), a Linux reverse-shell signature
// (110), two Windows LOLBin signatures (200, 210), and a deny-listed-IP rule
// (300) driven by the engine's ListStore -- the same primitive the
// threat-intel/IOC feed work will populate. Intentionally broad starter
// signatures meant to be tuned or replaced via VAJRA_ENGINE_RULES.
std::vector<Rule> builtin_rules();

}  // namespace vajra_engine

#endif  // VAJRA_ENGINE_BUILTIN_RULES_H
