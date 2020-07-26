# CryptoMessaging
Rel 2. Jul 8-Jul 24, 2020
Theory; https://golang.org/pkg/testing/
Renamed and moved files (E-n-D-CURL-w-Key->main).
main file split to 'handlers' and main
Adding uniTest: file handlers_test
Fixed: handling empty text or password.
Instructions to run the Unitest: 
> go test -v E-n-D-CURL-w-Key_test.go
Instructions to run functional (encrypt/decrypt) - see in Rel 1 below. 

Rel 1.
test:
> curl -X POST -H "Content-type: application/json" -d '{"text":"Lev changed to pass", "pass":"value5"}' http://127.0.0.1:8081/api/v1/encrypt

returns: D8jTIbHKSlwME8HkzhmnkLpuw+sg7RKfg5R44fvoLvM=

then send:
> curl -X POST -H "Content-type: application/json" -d '{"hash":"D8jTIbHKSlwME8HkzhmnkLpuw+sg7RKfg5R44fvoLvM=", "pass":"value5"}' http://127.0.0.1:8081/api/v1/decrypt

returns orig text: "Lev changed to pass"

