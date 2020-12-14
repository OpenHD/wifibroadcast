//
// Created by consti10 on 02.12.20.
//

#ifndef WIFIBROADCAST_FEC_HPP
#define WIFIBROADCAST_FEC_HPP

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <errno.h>
#include <string>
#include <vector>
#include <string.h>
#include "wifibroadcast.hpp"
#include <stdexcept>
#include <iostream>
#include <functional>
#include <map>
#include "HelperSources/TimeHelper.hpp"
#include "HelperSources/FixedSizeVector.h"

extern "C"{
#include "ExternalCSources/fec.h"
}

// c++ wrapper for the FEC library
// If K and N were known at compile time we could make this much cleaner !
class FEC{
public:
    explicit FEC(int k, int n) : FEC_K(k), FEC_N(n){
        if(FEC_K != 0){
            fec_p = fec_new(FEC_K, FEC_N);
        }
    }
    ~FEC(){
        if(fec_p!= nullptr){
            fec_free(fec_p);
        }
    }
    void fecEncode(const uint8_t** src,uint8_t ** fecs, size_t sz)const{
        fec_encode(fec_p,src,fecs,sz);
    }
    // c++ - style declaration
    void fecEncode2(const std::vector<std::array<uint8_t,MAX_FEC_PAYLOAD>>& inpkts,std::vector<std::array<uint8_t,MAX_FEC_PAYLOAD>>& outpkts,std::size_t size){
        // create the right pointers for in and out
    }
    void fecDecode(const uint8_t** inpkts, uint8_t** outpkts, const unsigned*  index, size_t sz)const{
        fec_decode(fec_p,inpkts,outpkts,index,sz);
    }
public:
    const int FEC_K;  // RS number of primary fragments in block default 8
    const int FEC_N;  // RS total number of fragments in block default 12
private:
    fec_t *fec_p=nullptr;
};

// Takes a continuous stream of packets and
// encodes them via FEC such that they can be decoded by FECDecoder
// The encoding is slightly different from traditional FEC. It
// a) makes sure to send out data packets immediately
// b) Handles packets of size up to N instead of packets of exact size N
// Due to b) the packet size has to be written into the first two bytes of each data packet. See https://github.com/svpcom/wifibroadcast/issues/67
// use FEC_K==0 to completely skip FEC for the lowest latency possible
class FECEncoder : private FEC{
public:
    typedef std::function<void(const WBDataPacket &wbDataPacket)> OUTPUT_DATA_CALLBACK;
    OUTPUT_DATA_CALLBACK outputDataCallback;

    explicit FECEncoder(int k, int n) : FEC(k,n) {
        block = new uint8_t *[FEC_N];
        for (int i = 0; i < FEC_N; i++) {
            block[i] = new uint8_t[MAX_FEC_PAYLOAD];
        }
    }

    ~FECEncoder() {
        for (int i = 0; i < FEC_N; i++) {
            delete block[i];
        }
        delete block;
    }
private:
    uint64_t block_idx = 0; //block_idx << 8 + fragment_idx = nonce (64bit)
    uint8_t fragment_idx = 0;
    uint8_t **block;
    //std::vector<std::array<uint8_t,MAX_FEC_PAYLOAD>> block; nah leave it in c style since fec is also c
    size_t max_packet_size = 0;
    //
public:
    void encodePacket(const uint8_t *buf, size_t size) {
        assert(size <= MAX_PAYLOAD_SIZE);
        // Use FEC_K==0 to completely disable FEC
        if(FEC_K == 0) {
            const auto nonce=WBDataHeader::calculateNonce(block_idx,fragment_idx);
            WBDataPacket wbDataPacket{nonce, buf, size};
            outputDataCallback(wbDataPacket);
            block_idx++;
            return;
        }
        FECDataHeader dataHeader(size);
        // write the size of the data part into each packet.
        // This is needed for the 'up to n bytes' workaround
        memcpy(block[fragment_idx], &dataHeader, sizeof(dataHeader));
        // write the actual data
        memcpy(block[fragment_idx] + sizeof(dataHeader), buf, size);
        // zero out the remaining bytes such that FEC always sees zeroes
        // same is done on the rx. These zero bytes are never transmitted via wifi
        const auto writtenDataSize= sizeof(FECDataHeader) + size;
        memset(block[fragment_idx]+writtenDataSize, '\0', MAX_FEC_PAYLOAD-writtenDataSize);

        // send FEC data packet immediately before calculating the FECs
        send_block_fragment(sizeof(dataHeader) + size);
        // the packet size for FEC encoding is determined by calculating the max of all primary fragments in this block.
        // Since the rest of the bytes are zeroed out we can run FEC with dynamic packet size.
        // As long as the deviation in packet size of primary fragments isn't too high the loss in raw bandwidth is negligible
        // Note,the loss in raw bandwidth comes from the size of the FEC secondary packets, which always has to be the max of all primary fragments
        // Not from the primary fragments, they are transmitted without the "zeroed out" part
        max_packet_size = std::max(max_packet_size, sizeof(dataHeader) + size);
        fragment_idx += 1;

        //std::cout<<"Fragment index is "<<(int)fragment_idx<<"FEC_K"<<(int)FEC_K<<"\n";
        if (fragment_idx < FEC_K) {
            return;
        }
        // once enough data has been buffered, create and send all the FEC packets
        fecEncode((const uint8_t **) block, block + FEC_K, max_packet_size);

        while (fragment_idx < FEC_N) {
            send_block_fragment(max_packet_size);
            fragment_idx += 1;
        }
        block_idx += 1;
        fragment_idx = 0;
        max_packet_size = 0;
    }

    // returns true if the block_idx has reached its maximum
    // You want to send a new session key in this case
    bool resetOnOverflow() {
        if (block_idx > WBDataHeader::MAX_BLOCK_IDX) {
            block_idx = 0;
            return true;
        }
        return false;
    }
private:
    // construct WB FEC data, either DATA blocks or FEC blocks
    // then forward via the callback
    void send_block_fragment(const std::size_t packet_size) const {
        const auto nonce=WBDataHeader::calculateNonce(block_idx,fragment_idx);
        const uint8_t *dataP = block[fragment_idx];
        WBDataPacket packet{nonce, dataP, packet_size};
        outputDataCallback(packet);
    }
};

class RxRingItem{
public:
    explicit RxRingItem(const FEC& fec): fec(fec),fragment_map(fec.FEC_N,FragmentStatus::UNAVAILABLE),fragments(fec.FEC_N),originalSizeOfFragments(fec.FEC_N){
    }
    ~RxRingItem()= default;
public:
    // call this once the decoder is done with this item and uses it for a different block
    void repurpose(const uint64_t new_block_idx= 0){
        block_idx = new_block_idx;
        send_fragment_idx = 0;
        availableFragmentsCount = 0;
        clearFragmentMap();
    }
    // mark every fragment as not yet received
    void clearFragmentMap(){
        std::fill(fragment_map.begin(),fragment_map.end(),FragmentStatus::UNAVAILABLE);
    }
    // returns true if the fragment at position fragmentIdx has been already received
    bool hasFragment(const uint8_t fragmentIdx)const{
        return fragment_map[fragmentIdx]==AVAILABLE;
    }
    // copy the fragment data and mark it as available
    // you should check if it is already available with hasFragment() to avoid storing a fragment multiple times
    // when using multiple RX cards
    void addFragment(const uint8_t fragment_idx, const uint8_t* data,const std::size_t dataLen){
        // write the data (doesn't matter if FEC data or correction packet)
        memcpy(fragments[fragment_idx].data(),data,dataLen);
        // set the rest to zero such that FEC works
        memset(fragments[fragment_idx].data()+dataLen, '\0', MAX_FEC_PAYLOAD-dataLen);
        // mark it as available
        fragment_map[fragment_idx] = RxRingItem::AVAILABLE;
        availableFragmentsCount ++;
        originalSizeOfFragments[fragment_idx]=dataLen;
    }
    // if fragmentIdx<FEC_K this is a primary fragment
    // else this is a secondary fragment
    const uint8_t* getFragment(const uint8_t fragmentIdx)const {
        return fragments[fragmentIdx].data();
    }
    // TODO documentation
    void applyFec(){
        unsigned index[fec.FEC_K];
        uint8_t *in_blocks[fec.FEC_K];
        uint8_t *out_blocks[fec.FEC_N - fec.FEC_K];
        int j = fec.FEC_K;
        int ob_idx = 0;
        std::size_t tmpMaxPacketSize=0;
        for (int i = 0; i < fec.FEC_K; i++) {
            if (fragment_map[i]) {
                in_blocks[i] = fragments[i].data();
                index[i] = i;
            } else {
                for (; j < fec.FEC_N; j++) {
                    if (fragment_map[j]) {
                        tmpMaxPacketSize=originalSizeOfFragments[j];
                        in_blocks[i] = fragments[j].data();
                        out_blocks[ob_idx++] = fragments[i].data();
                        index[i] = j;
                        j++;
                        break;
                    }
                }
            }
        }
        /*assert(tmpMaxPacketSize!=0);
        // TODO why did he originally use MAX_FEC_PAYLOAD here ?
        // fec.fecDecode((const uint8_t **) in_blocks, out_blocks, index, MAX_FEC_PAYLOAD);
        fec.fecDecode((const uint8_t **) in_blocks, out_blocks, index, tmpMaxPacketSize);*/
        if(tmpMaxPacketSize!=0){
            fec.fecDecode((const uint8_t **) in_blocks, out_blocks, index, tmpMaxPacketSize);
        }else{
            fec.fecDecode((const uint8_t **) in_blocks, out_blocks, index, MAX_FEC_PAYLOAD);
        }
    }
private:
    //reference to the FEC decoder (needed for k,n)
    const FEC& fec;
public:
    // the block idx marks which block this element currently refers to
    uint64_t block_idx=0;
    // TODO what is this
    uint8_t send_fragment_idx=0;
    // TODO what is this
    uint8_t availableFragmentsCount=0;
private:
    // for each fragment (via fragment_idx) store if it has been received yet
    enum FragmentStatus{UNAVAILABLE=0,AVAILABLE=1};
    std::vector<FragmentStatus> fragment_map;
    // holds all the data for all received fragments (if fragment_map says UNAVALIABLE at this position, content is undefined)
    std::vector<std::array<uint8_t,MAX_FEC_PAYLOAD>> fragments;
    // holds the original size for all received fragments
    std::vector<std::size_t> originalSizeOfFragments;
};

static inline int modN(int x, int base) {
    return (base + (x % base)) % base;
}


// Takes a continuous stream of packets (data and fec correction packets) and
// processes them such that the output is exactly (or as close as possible) to the
// Input stream fed to FECEncoder.
// Most importantly, it also handles re-ordering of packets
class FECDecoder : public FEC{
public:
    static constexpr auto RX_RING_SIZE = 40;
    typedef std::function<void(const uint8_t * payload,std::size_t payloadSize)> SEND_DECODED_PACKET;
    SEND_DECODED_PACKET callback;

    explicit FECDecoder(int k, int n) : FEC(k,n) {
        for(int i=0;i<RX_RING_SIZE;i++){
            rx_ring[i]=std::make_unique<RxRingItem>(*this);
        }
    }
    ~FECDecoder() = default;
    AvgCalculator avgLatencyPacketInQueue;
private:
    std::map<uint64_t,std::chrono::steady_clock::time_point> timePointPacketEnteredRxRing;
    uint64_t seq = 0;
    std::array<std::unique_ptr<RxRingItem>,RX_RING_SIZE> rx_ring;
    int rx_ring_front = 0; // current packet
    int rx_ring_alloc = 0; // number of allocated entries
    uint64_t last_known_block = ((uint64_t) -1);  //id of last known block
    // TODO documentation
    // copy paste from svpcom
    int rx_ring_push() {
        if (rx_ring_alloc < RX_RING_SIZE) {
            int idx = modN(rx_ring_front + rx_ring_alloc, RX_RING_SIZE);
            rx_ring_alloc += 1;
            return idx;
        }

        // override existing data
        const int idx = rx_ring_front;

        /*
          Ring overflow. This means that there are more unfinished blocks than ring size
          Possible solutions:
          1. Increase ring size. Do this if you have large variance of packet travel time throught WiFi card or network stack.
             Some cards can do this due to packet reordering inside, diffent chipset and/or firmware or your RX hosts have different CPU power.
          2. Reduce packet injection speed or try to unify RX hardware.
        */
        std::cerr<<"override block "<<rx_ring[idx]->block_idx<<" with "<< rx_ring[idx]->availableFragmentsCount<<" fragments\n";

        rx_ring_front = modN(rx_ring_front + 1, RX_RING_SIZE);
        return idx;
    }
    // TODO documentation
    // copy paste from svpcom
    int get_block_ring_idx(const uint64_t block_idx) {
        // check if block is already in the ring
        for (int i = rx_ring_front, c = rx_ring_alloc; c > 0; i = modN(i + 1, FECDecoder::RX_RING_SIZE), c--) {
            if (rx_ring[i]->block_idx == block_idx) return i;
        }

        // check if block is already known and not in the ring then it is already processed
        if (last_known_block != (uint64_t) -1 && block_idx <= last_known_block) {
            return -1;
        }

        int new_blocks = (int) std::min(last_known_block != (uint64_t) -1 ? block_idx - last_known_block : 1,
                                        (uint64_t) FECDecoder::RX_RING_SIZE);
        assert (new_blocks > 0);

        last_known_block = block_idx;
        int ring_idx = -1;

        for (int i = 0; i < new_blocks; i++) {
            ring_idx = rx_ring_push();
            const auto newBlockIdx=block_idx + i + 1 - new_blocks;
            rx_ring[ring_idx]->repurpose(newBlockIdx);
        }
        return ring_idx;
    }
    // this one calls the callback with reconstructed data and payload in order
    void send_packet(const int ring_idx,const uint8_t fragment_idx){
        const RxRingItem& rxRingItem=*rx_ring[ring_idx].get();
        const uint8_t* primaryFragment=rxRingItem.getFragment(fragment_idx);
        const FECDataHeader *packet_hdr = (FECDataHeader *)primaryFragment;

        const uint8_t *payload = primaryFragment + sizeof(FECDataHeader);
        const uint16_t packet_size = packet_hdr->get();
        const uint64_t packet_seq = rxRingItem.block_idx * FEC_K + fragment_idx;

        const auto tmp=WBDataHeader::calculateNonce(rxRingItem.block_idx,fragment_idx);
        auto search = timePointPacketEnteredRxRing.find(tmp);
        if(search != timePointPacketEnteredRxRing.end()){
            // found time point for this fragment
            const auto latency=std::chrono::steady_clock::now()-search->second;
            timePointPacketEnteredRxRing.erase(search);
            avgLatencyPacketInQueue.add(latency);
            //std::cout<<"avgLatencyPacketInQueue "<<avgLatencyPacketInQueue.getAvgReadable()<<"\n";
        }else{
            //std::cout<<"Cannot calc latency (fec corrected packet)\n";
        }

        if (packet_seq > seq + 1) {
            const auto packetsLost=(packet_seq - seq - 1);
            std::cerr<<packetsLost<<"packets lost\n";
            count_p_lost += packetsLost;
        }

        seq = packet_seq;

        if (packet_size > MAX_PAYLOAD_SIZE) {
            // this should never happen !
            std::cerr<<"corrupted packet on FECDecoder out "<<seq;
        } else {
            callback(payload,packet_size);
        }
    }
public:
    // call on new session key !
    void reset() {
        rx_ring_front = 0;
        rx_ring_alloc = 0;
        last_known_block = (uint64_t) -1;
        seq = 0;
        for (int ring_idx = 0; ring_idx < FECDecoder::RX_RING_SIZE; ring_idx++) {
            rx_ring[ring_idx]->repurpose();
        }
    }
    // returns false if the packet is bad (which should never happen !)
    bool processPacket(const WBDataHeader& wblockHdr,const std::vector<uint8_t>& decrypted){
        assert(wblockHdr.packet_type==WFB_PACKET_DATA);
        // Use FEC_K==0 to completely disable FEC
        if(FEC_K == 0) {
            callback(decrypted.data(),decrypted.size());
            return true;
        }
        timePointPacketEnteredRxRing.insert({wblockHdr.nonce, std::chrono::steady_clock::now()});
        const uint64_t block_idx=wblockHdr.getBlockIdx();
        const uint8_t fragment_idx=wblockHdr.getFragmentIdx();

        // Should never happen due to generating new session key on tx side
        if (block_idx > WBDataHeader::MAX_BLOCK_IDX) {
            std::cerr<<"block_idx overflow\n";
            return false;
        }
        // fragment index must be in the range [0,...,FEC_N[
        if (fragment_idx >= FEC_N) {
            std::cerr<<"invalid fragment_idx:"<<fragment_idx<<"\n";
            return false;
        }

        const int ring_idx = get_block_ring_idx(block_idx);

        //printf("got 0x%lx %d, ring_idx=%d\n", block_idx, fragment_idx, ring_idx);

        //ignore already processed blocks
        if (ring_idx < 0) return true;

        RxRingItem *p = rx_ring[ring_idx].get();
        if(p->hasFragment(fragment_idx)){
            // return early (ignore already processed fragments)
            return true;
        }else{
            p->addFragment(fragment_idx, decrypted.data(), decrypted.size());
        }

        if (ring_idx == rx_ring_front) {
            // check if any packets without gaps
            while (p->send_fragment_idx < FEC_K && p->hasFragment(p->send_fragment_idx)) {
                send_packet(ring_idx, p->send_fragment_idx);
                p->send_fragment_idx += 1;
            }
        }

        // or we can reconstruct gaps via FEC
        if (p->send_fragment_idx < FEC_K && p->availableFragmentsCount == FEC_K) {
            //printf("do fec\n");
            p->applyFec();
            while (p->send_fragment_idx < FEC_K) {
                count_p_fec_recovered += 1;
                send_packet(ring_idx, p->send_fragment_idx);
                p->send_fragment_idx += 1;
            }
        }

        if (p->send_fragment_idx == FEC_K) {
            int nrm = modN(ring_idx - rx_ring_front, FECDecoder::RX_RING_SIZE);
            for (int i = 0; i <= nrm; i++) {
                rx_ring_front = modN(rx_ring_front + 1, FECDecoder::RX_RING_SIZE);
                rx_ring_alloc -= 1;
            }
            assert(rx_ring_alloc >= 0);
        }
        return true;
    }
protected:
    uint32_t count_p_fec_recovered=0;
    uint32_t count_p_lost=0;
};


#endif //WIFIBROADCAST_FEC_HPP
