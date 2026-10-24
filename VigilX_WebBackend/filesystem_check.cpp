#include <filesystem>
int main(){std::error_code ec; bool e=std::filesystem::exists("credentials.txt", ec); return ec ? 1 : (e ? 0 : 0);}
