#include "PcapCapture.hpp"
#include "NfqCapture.hpp"
#include "Engine.hpp"
#include <iostream>
#include <stdexcept>
#include <thread>
#include "Logger.hpp"

int main(int argc, char* argv[])
{
    if(argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " <interface>\n";
        return 1;
    }
    try
    {
        Logger logger("/var/log/spider.log");
        Engine engine(logger);

        NfqCapture nfq(0, engine, logger);
        PcapCapture pcap(std::string(argv[1]), engine, logger);

        logger.log(std::string("spider started on ") + argv[1]);

        std::thread nfqThread(&NfqCapture::run, &nfq);
        std::thread pcapThread(&PcapCapture::run, &pcap);

        nfqThread.join();
        pcapThread.join();

        logger.log("spider stopped");
    }
    catch (const std::exception& e)
    {
        std::cerr << "startup failed: " << e.what() << '\n';
        return 1;
    }
}