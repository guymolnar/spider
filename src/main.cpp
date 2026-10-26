#include "NfqCapture.hpp"

#include <iostream>
#include <stdexcept>

int main()
{
    try
    {
        NfqCapture nfq(0);
        nfq.run();
    }
    catch (const std::exception& e)
    {
        std::cerr << "startup failed: " << e.what() << '\n';
        return 1;
    }
}