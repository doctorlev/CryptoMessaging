# CryptoMessaging
Solutions: 
1. salt changed to pass
2. reserved salt for the future
3. cleaning

Bugs:
1. if pass is empty - no pass check on decrypt operation (even 'salt=555' works)

TBD:
1. how key, iv and salt are managed and retreived/derived.