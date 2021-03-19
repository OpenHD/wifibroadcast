//
// Created by consti10 on 19.03.21.
//

#ifndef WIFIBROADCAST_FEC_H
#define WIFIBROADCAST_FEC_H

#include <vector>
#include <array>
#include "ExternalCSources/fec/fec.h"
//#include "ExternalCSources/fecz/fec.h"


// c++ wrapper around fec library

/**
 * @param fragmentSize size of each fragment in this block
 * @param primaryFragments list of pointers to memory for primary fragments
 * @param secondaryFragments list of pointers to memory for secondary fragments (fec fragments)
 * Using the data from @param primaryFragments constructs as many secondary fragments as @param secondaryFragments holds
 */
void fec_encode(unsigned int fragmentSize,
                const std::vector<uint8_t*>& primaryFragments,
                const std::vector<uint8_t*>& secondaryFragments){
    fec_encode(fragmentSize, (unsigned char**)primaryFragments.data(), primaryFragments.size(), (unsigned char**)secondaryFragments.data(), secondaryFragments.size());
    /*auto tmp=fec_new(primaryFragments.size(),primaryFragments.size()+secondaryFragments.size());
    fec_encode(tmp,(const gf**)primaryFragments.data(),(gf**)secondaryFragments.data(),fragmentSize);
    fec_free(tmp);*/
}

/**
 * @param fragmentSize size of each fragment in this block
 * @param primaryFragments list of pointers to memory for primary fragments
 * @param secondaryFragments list of pointers to memory for secondary fragments (fec fragments)
 * @param indicesMissingPrimaryFragments list of the indices of missing primary fragments
 * @param indicesAvailableSecondaryFragments list of the indices of secondaryFragments that are used to reconstruct missing primary fragments
 * Reconstructs all missing primary fragments using the available secondary fragments.
 */
void fec_decode(unsigned int fragmentSize,
                std::vector<uint8_t*>& primaryFragments,
                std::vector<uint8_t*>& secondaryFragments,
                const std::vector<unsigned int>& indicesMissingPrimaryFragments,
                const std::vector<unsigned int>& indicesAvailableSecondaryFragments){
    assert(indicesMissingPrimaryFragments.size() <= indicesAvailableSecondaryFragments.size());
    fec_decode(fragmentSize, (unsigned char**)primaryFragments.data(), primaryFragments.size(), (unsigned char**)secondaryFragments.data(),
               (unsigned int*)indicesAvailableSecondaryFragments.data(), (unsigned int*)indicesMissingPrimaryFragments.data(), indicesMissingPrimaryFragments.size());

    /*auto tmp=fec_new(primaryFragments.size(),primaryFragments.size()+secondaryFragments.size());
    std::vector<uint8_t*> block=primaryFragments;
    for(const auto el:secondaryFragments){
        block.push_back(el);
    }
    fec_decode(tmp,b)*/
}
template<std::size_t S>
static std::vector<uint8_t*> convertToP(std::vector<std::array<uint8_t,S>>& buff){
    std::vector<uint8_t*> ret(buff.size());
    for(int i=0;i<ret.size();i++){
        ret[i]=buff[i].data();
    }
    return ret;
}

template<std::size_t S>
void fec_encode2(unsigned int fragmentSize,std::vector<std::array<uint8_t,S>>& pf,std::vector<std::array<uint8_t,S>>& sf){
    auto pfp=convertToP(pf);
    auto sfp=convertToP(sf);
    fec_encode(fragmentSize,pfp,sfp);
}

template<std::size_t S>
void fec_decode2(unsigned int fragmentSize,std::vector<std::array<uint8_t,S>>& pf,std::vector<std::array<uint8_t,S>>& sf,
                const std::vector<unsigned int>& indicesMissingPrimaryFragments,
                const std::vector<unsigned int>& indicesAvailableSecondaryFragments){
    auto pfp=convertToP(pf);
    auto sfp=convertToP(sf);
    fec_decode(fragmentSize, pfp, sfp, indicesMissingPrimaryFragments, indicesAvailableSecondaryFragments);
}

template<std::size_t S>
void fec_decode3(unsigned int fragmentSize,std::vector<std::array<uint8_t,S>>& pf,std::vector<std::array<uint8_t,S>>& sf,
                 const std::vector<unsigned int>& indicesAvailablePrimaryFragments,
                 const std::vector<unsigned int>& indicesAvailableSecondaryFragments){
    const auto nMissingPrimaryFragments=pf.size()-indicesAvailablePrimaryFragments.size();
    std::vector<unsigned int> indicesMissingPrimaryFragments;
    for(unsigned int i=0;i<pf.size();i++){
        auto found= indicesAvailablePrimaryFragments.end() != std::find(indicesAvailablePrimaryFragments.begin(), indicesAvailablePrimaryFragments.end(), i);
        if(!found){
            indicesMissingPrimaryFragments.push_back(i);
        }
    }
    std::cout<<"indicesMissingPrimaryFragments:"<<StringHelper::vectorAsString(indicesMissingPrimaryFragments)<<"\n";
    std::cout<<"indicesAvailableSecondaryFragments:"<<StringHelper::vectorAsString(indicesAvailableSecondaryFragments)<<"\n";
    fec_decode2(fragmentSize,pf,sf,indicesMissingPrimaryFragments,indicesAvailablePrimaryFragments);
}


/*template<std::size_t S>
void fec_encode(unsigned int fragmentSize,
                std::vector<std::array<uint8_t,S>>& primaryFragments,
                std::vector<std::array<uint8_t,S>>& secondaryFragments){

}*/


//Note: By using "blockBuffer" as input the fecEncode / fecDecode function(s) don't need to allocate any new memory.
// The "blockBuffer" can be either at least as big as needed or bigger, implementation doesn't care

// returns an array of pointers to all primary fragments of this block
template<std::size_t S>
std::vector<uint8_t*> getPrimaryFragmentPointers(std::vector<std::array<uint8_t,S>>& blockBuffer, unsigned int nPrimaryFragments){
    std::vector<uint8_t*> primaryFragmentsP(nPrimaryFragments);
    for(unsigned int i=0;i<nPrimaryFragments;i++){
        primaryFragmentsP[i]=blockBuffer[i].data();
    }
    return primaryFragmentsP;
}

// returns an array of pointers to all secondary fragments of this block (doesn't matter if the secondary fragment was actually used or not)
template<std::size_t S>
std::vector<uint8_t*> getPossibleSecondaryFragmentPointers(std::vector<std::array<uint8_t,S>>& blockBuffer, unsigned int nPrimaryFragments){
    const int nSecondaryFragmentsPointers=blockBuffer.size()-nPrimaryFragments;
    std::vector<uint8_t*> secondaryFragmentsP(nSecondaryFragmentsPointers);
    for(unsigned int i=0;i<nSecondaryFragmentsPointers;i++){
        secondaryFragmentsP[i]=blockBuffer[nPrimaryFragments+i].data();
    }
    return secondaryFragmentsP;
}

template<std::size_t S>
std::vector<uint8_t*> getSecondaryFragmentPointers(std::vector<std::array<uint8_t,S>>& blockBuffer, unsigned int nPrimaryFragments,unsigned int nSecondaryFragments){
    //const int nSecondaryFragmentsPointers=blockBuffer.size()-nPrimaryFragments;
    std::vector<uint8_t*> secondaryFragmentsP(nSecondaryFragments);
    for(unsigned int i=0;i<secondaryFragmentsP.size();i++){
        secondaryFragmentsP[i]=blockBuffer[nPrimaryFragments+i].data();
    }
    return secondaryFragmentsP;
}


/**
 * @param packetSize size of each data packet (fragment) to use for the FEC encoding step. FEC only works on packets the same size
 * @param blockBuffer (big) data buffer. The nth element is to be treated as the nth fragment of the block, either as primary or secondary fragment.
 * During the FEC step, @param nPrimaryFragments fragments are used to calculate nSecondaryFragments FEC blocks.
 * After the FEC step,beginning at idx @param nPrimaryFragments ,@param nSecondaryFragments are stored at the following indices, each of size @param packetSize
 */
template<std::size_t S>
void fecEncode(unsigned int packetSize,std::vector<std::array<uint8_t,S>>& blockBuffer,unsigned int nPrimaryFragments,unsigned int nSecondaryFragments){
    assert(packetSize<=S);
    assert(nPrimaryFragments+nSecondaryFragments<=blockBuffer.size());
    auto primaryFragmentsP= getPrimaryFragmentPointers(blockBuffer, nPrimaryFragments);
    auto secondaryFragmentsP= getPossibleSecondaryFragmentPointers(blockBuffer, nPrimaryFragments);
    secondaryFragmentsP.resize(nSecondaryFragments);
    fec_encode(packetSize,primaryFragmentsP,secondaryFragmentsP);
    //fec_encode(packetSize, (const unsigned char**)primaryFragmentsP.data(), primaryFragmentsP.size(), (unsigned char**)secondaryFragmentsP.data(), nSecondaryFragments);
}

//template<std::size_t S>
//void fecDecode(unsigned int packetSize,std::vector<std::array<uint8_t,S>>& blockBuffer,unsigned int nPrimaryFragments,std::map)

/**
 * @param packetSize size of each data packet (fragment) to use for the FEC encoding step. FEC only works on packets the same size
 * @param blockBuffer (big) data buffer. The nth element is to be treated as the nth fragment of the block, either as primary or secondary fragment.
 * During the FEC step, all missing primary Fragments (indices from @param indicesMissingPrimaryFragments) are reconstructed from the FEC packets,
 * using indices from @param indicesAvailableSecondaryFragments
 * Note: both @param indicesMissingPrimaryFragments and @param indicesAvailableSecondaryFragments refer to a position in @param blockBuffer
 */
template<std::size_t S>
void fecDecode(unsigned int packetSize,std::vector<std::array<uint8_t,S>>& blockBuffer,unsigned int nPrimaryFragments,
               const std::vector<unsigned int>& indicesMissingPrimaryFragments,const std::vector<unsigned int>& indicesAvailableSecondaryFragments){
    // first validate input.
    assert(packetSize<=S);
    assert(indicesMissingPrimaryFragments.size()>=indicesAvailableSecondaryFragments.size());
    // I treat calling fecDecode() with more primary fragments than needed for the reconstruction step as an error here
    // (because it would create unneeded latency) though it would work just fine
    assert(indicesMissingPrimaryFragments.size()==indicesAvailableSecondaryFragments.size());
    // unfortunately the fec implementation needs an array of primary fragments
    // and a different array of secondary fragments where obviously the indices of all primary fragments are the same,
    // but the indices for secondary fragments start at 0 and not fec_k
    // ( in this regard, fec_encode() differs from fec_decode() )
    auto primaryFragmentsP=getPrimaryFragmentPointers(blockBuffer,nPrimaryFragments);
    auto secondaryFragmentsP=getPossibleSecondaryFragmentPointers(blockBuffer,nPrimaryFragments);

    std::vector<unsigned int> indicesAvailableSecondaryFragmentsAdjusted(indicesAvailableSecondaryFragments.size());
    for(int i=0;i<indicesAvailableSecondaryFragments.size();i++){
        indicesAvailableSecondaryFragmentsAdjusted[i]=indicesAvailableSecondaryFragments[i]-nPrimaryFragments;
    }
    std::cout<<"indicesMissingPrimaryFragments:"<<StringHelper::vectorAsString(indicesMissingPrimaryFragments)<<"\n";
    std::cout<<"indicesAvailableSecondaryFragmentsAdjusted:"<<StringHelper::vectorAsString(indicesAvailableSecondaryFragmentsAdjusted)<<"\n";

    //fec_decode(packetSize,primaryFragmentsP.data(),primaryFragmentsP.size(),secondaryFragmentsP.data(),indicesAvailableSecondaryFragmentsAdjusted.data(),indicesMissingPrimaryFragments.data(),indicesAvailableSecondaryFragmentsAdjusted.size());
    fec_decode(packetSize,primaryFragmentsP,secondaryFragmentsP,indicesMissingPrimaryFragments,indicesAvailableSecondaryFragmentsAdjusted);
}

template<std::size_t S>
void fecDecode2(unsigned int packetSize, std::vector<std::array<uint8_t,S>>& blockBuffer, unsigned int nPrimaryFragments,
                const std::vector<unsigned int>& indicesAvailablePrimaryFragments, const std::vector<unsigned int>& indicesAvailableSecondaryFragments){
    assert(indicesAvailablePrimaryFragments.size() + indicesAvailableSecondaryFragments.size() == nPrimaryFragments);
    // the fec impl. wants the indices of missing primary fragments, not those ones available
    std::vector<unsigned int> indicesMissingPrimaryFragments;
    for(unsigned int i=0;i<nPrimaryFragments;i++){
        auto found= indicesAvailablePrimaryFragments.end() != std::find(indicesAvailablePrimaryFragments.begin(), indicesAvailablePrimaryFragments.end(), i);
        if(!found){
            indicesMissingPrimaryFragments.push_back(i);
        }
    }
    assert(indicesMissingPrimaryFragments.size()== nPrimaryFragments - indicesAvailablePrimaryFragments.size());
    std::cout<<"indicesMissingPrimaryFragments:"<<StringHelper::vectorAsString(indicesMissingPrimaryFragments)<<"\n";

    //
    auto primaryFragmentP=getPrimaryFragmentPointers(blockBuffer, nPrimaryFragments);
    auto secondaryFragmentP=getPossibleSecondaryFragmentPointers(blockBuffer, nPrimaryFragments);

    std::vector<unsigned int> indicesAvailableSecondaryFragmentsAdjusted(indicesAvailableSecondaryFragments.size());
    for(int i=0; i < indicesAvailableSecondaryFragments.size(); i++){
        indicesAvailableSecondaryFragmentsAdjusted[i]= indicesAvailableSecondaryFragments[i] - nPrimaryFragments;
    }
    std::cout<<"indicesAvailableSecondaryFragmentsAdjusted:"<<StringHelper::vectorAsString(indicesAvailableSecondaryFragmentsAdjusted)<<"\n";

    fec_decode(packetSize, primaryFragmentP, secondaryFragmentP, indicesMissingPrimaryFragments, indicesAvailableSecondaryFragmentsAdjusted);

    //fec_decode(packetSize,primaryFragmentPointers.data(),nPrimaryFragments,secondaryFragmentPointers.data(),indicesAvailableSecondaryFragmentsAdjusted.data(),indicesMissingPrimaryFragments.data(),indicesAvailableSecondaryFragmentsAdjusted.size());

}

#endif //WIFIBROADCAST_FEC_H
