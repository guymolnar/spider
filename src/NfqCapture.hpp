#pragma once

struct nfq_handle;
struct nfq_q_handle;

class NfqCapture
{
public:
    explicit NfqCapture(int queueNum);
    ~NfqCapture();

    NfqCapture(const NfqCapture&) = delete;
    NfqCapture& operator=(const NfqCapture&) = delete;

    void run();

private:
    nfq_handle* _handle = nullptr;
    nfq_q_handle* _queueHandle = nullptr;
};