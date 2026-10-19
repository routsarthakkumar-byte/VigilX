#include "Resource.h"
#include "Exceptions.h"

Resource::Resource(const std::string& id, const std::string& name, Sensitivity s)
    : id_(id), name_(name), sensitivity_(s) {
    if (name.empty()) throw InvalidInputException("resource name cannot be empty");
}

std::string Resource::describe() const {
    return "[" + id_ + "] " + typeName() + ": " + name_ + " (sensitivity " + toString(sensitivity_) + ")";
}

std::ostream& operator<<(std::ostream& os, const Resource& r) { return os << r.describe(); }
