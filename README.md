This code originated from https://github.com/svpcom/wifibroadcast \
It was re-written in c++ with the intention to reduce latency, improve syntax, improve documentation 
and modularize the FEC Enc/Dec and Encryption/Decryption part. (represented by FECEncoder/Decoder and Encryptor/Decryptor now).\
By doing so I was able to reduce latency quite a lot (even though the fix was one line of code in the end) and
write simple unit tests that don't require a wifi card.\
I also added some new features, like disabling FEC completely (use k==0 in this case) or disabling encryption to save
cpu resources.