emcc -I ./depend/secp256k1 -I ./depend/secp256k1/src secp.cpp -o http/secp.html -s EXTRA_EXPORTED_RUNTIME_METHODS=["cwrap"] -std=c++11 --bind -s ALLOW_MEMORY_GROWTH=1 -s IMPORTED_MEMORY
