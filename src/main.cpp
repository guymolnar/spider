#include "PcapCapture.hpp"
#include "NfqCapture.hpp"
#include "StateManager.hpp"
#include "IcmpFloodDetector.hpp"
#include <iostream>
#include <stdexcept>
#include <thread>

int main()
{
    try
    {
        StateManager sm;
        PacketCounter& counter = sm.makeCounter(std::chrono::seconds(1));
        IcmpFloodDetector icmp(counter, 100);
        sm.startCleanup();
        NfqCapture nfq(0, &icmp);
        PcapCapture pcap("eth0", &icmp);

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