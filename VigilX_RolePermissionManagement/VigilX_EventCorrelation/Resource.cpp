#include "Resource.h"
#include <iostream>
using namespace std;
Resource::Resource(int id, const string& name, const string& level) : resourceID(id), resourceName(name), classification(level) {}
int Resource::getResourceID() const { return resourceID; }
string Resource::getResourceName() const { return resourceName; }
string Resource::getClassification() const { return classification; }
void Resource::display() const { cout << "\nResource ID    : " << resourceID << "\nResource Name  : " << resourceName << "\nClassification : " << classification << '\n'; }
