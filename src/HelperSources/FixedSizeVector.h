//
// Created by consti10 on 09.12.20.
//

#ifndef WIFIBROADCAST_FIXEDSIZEVECTOR_H
#define WIFIBROADCAST_FIXEDSIZEVECTOR_H

#include <vector>

template<typename T>
class FixedSizeVector : private std::vector<T>{
public:
    using std::vector<T>::end;
};
#endif //WIFIBROADCAST_FIXEDSIZEVECTOR_H
