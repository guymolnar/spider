#include "PcapCapture.hpp"
#include "NfqCapture.hpp"
#include <iostream>
#include <stdexcept>
#include <thread>

int main()
{
    try
    {
        NfqCapture nfq(0);
        PcapCapture pcap("eth0");

        std::thread nfqThread(&NfqCapture::run, &nfq);
        std::thread pcapThread(&PcapCapture::run, &pcap);

        nfqThread.join();
        pcapThread.join();
    }
    catch (const std::exception& e)
    {
        std::cerr << "startup failed: " << e.what() << '\n';
        return 1;
    }
}