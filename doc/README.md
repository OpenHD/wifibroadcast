# Rx flow
```mermaid
flowchart LR
    W1(WiFi adapter 1) --pcap frame--> Filt
    W2(WiFi adapter 2) --pcap frame--> Filt
    WN(WiFi adapter N) --pcap frame--> Filt
    
    Filt(Packets filter) -.- FiltDesc
    FiltDesc["We process 
    only valid
    WiFi data packets"]

    Filt --Session key--> Dec
    Filt --Encripted data--> Dec

    Dec(Decriptor with session key) -- Decriped data --> Fec
    Fec(FEC module) --RTP--> App
    Fec(FEC module) --Mavlink--> App

    App("Application (OpenHD)")
    
```
Adapters in monitoring mode receives all packets.  
Current implementation uses only "Data Frame"`s.  
Session keys transferred as data without FEC and encryption.  
Encryption is done by libsodium

# Tx flow

# Frame format
