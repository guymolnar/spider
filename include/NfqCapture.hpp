#pragma once

struct nfq_handle;
struct nfq_q_handle;
class IcmpFloodDetector;

class NfqCapture
{
public:
    NfqCapture(int queueNum, IcmpFloodDetector* detector = nullptr);
    ~NfqCapture();

    NfqCapture(const NfqCapture&) = delete;
    NfqCapture& operator=(const NfqCapture&) = delete;

    void run();

private:
    nfq_handle* _handle = nullptr;
    nfq_q_handle* _queueHandle = nullptr;
    IcmpFloodDetector* _detector = nullptr;     // not owned, main keeps it alive
};
