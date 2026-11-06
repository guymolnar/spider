#include <cstdint>
#include <cerrno>
#include <cstdio>
#include <arpa/inet.h>
#include <sys/socket.h>

#define _LINUX_IN_H
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <stdexcept>
#include "NfqCapture.hpp"
#include "Engine.hpp"


static int onPacket(nfq_q_handle* qh, nfgenmsg*, nfq_data* nfa, void* user)
{
    auto* engine = static_cast<Engine*>(user);
    nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph)
    {
        return 0;
    }
    uint32_t id = ntohl(ph->packet_id);

    unsigned char* data;
    int len = nfq_get_payload(nfa, &data);

    uint32_t verdict = NF_ACCEPT;
    if (len > 0 && engine->process(data, static_cast<size_t>(len), Source::Inline) == Verdict::DROP)
    {
        verdict = NF_DROP;
    }

    return nfq_set_verdict(qh, id, verdict, 0, nullptr);
}


NfqCapture::NfqCapture(int queueNum, Engine& engine)
{
    _handle = nfq_open();
    if (!_handle)
    {
        throw std::runtime_error("nfq_open failed (are you root?)");
    }
    _queueHandle = nfq_create_queue(_handle, queueNum, &onPacket, &engine);
    if (!_queueHandle)
    {
        nfq_close(_handle);
        throw std::runtime_error("nfq_create_queue failed (queue already taken?)");
    }

    if (nfq_set_mode(_queueHandle, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        nfq_destroy_queue(_queueHandle);
        nfq_close(_handle);
        throw std::runtime_error("nfq_set_mode failed");
    }
    if(nfq_set_queue_maxlen(_queueHandle, 4096) < 0)
    {
        nfq_destroy_queue(_queueHandle);
        nfq_close(_handle);
        throw std::runtime_error("nfq_set_queue_maxlen failed");
    }
    if(nfq_set_queue_flags(_queueHandle, NFQA_CFG_F_FAIL_OPEN, 1) < 0)
    {
        nfq_destroy_queue(_queueHandle);
        nfq_close(_handle);
        throw std::runtime_error("nfq_set_queue_flags failed");
    }
}

NfqCapture::~NfqCapture()
{
    if (_queueHandle)
    {
        nfq_destroy_queue(_queueHandle);
    
    }    
    if (_handle)
    {
        nfq_close(_handle);
    }
}

void NfqCapture::run()
{
    int fd = nfq_fd(_handle);
    char buf[65536];

    while (true)
    {
        int n = recv(fd, buf, sizeof(buf), 0);
        if (n >= 0)
        {
            nfq_handle_packet(_handle, buf, n);
            continue;
        }
        if (errno == ENOBUFS) //checking for overflow
        {
            std::fprintf(stderr, "[nfq] queue overflow, packets lost\n");
            continue;
        }
        else
        {
            std::perror("recv");
            break;
        }
    }
}