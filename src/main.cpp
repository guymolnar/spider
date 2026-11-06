#include "PcapCapture.hpp"
#include "NfqCapture.hpp"
#include "Engine.hpp"
#include <iostream>
#include <stdexcept>
#include <thread>

int main(int argc, char* argv[])
{
    if(argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " <interface>\n";
        return 1;
    }
    try
    {
        Engine engine;

        NfqCapture nfq(0, engine);
        PcapCapture pcap(std::string(argv[1]), engine);

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