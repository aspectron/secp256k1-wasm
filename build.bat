REM emcc -I ./depend/secp256k1 -I ./depend/secp256k1/src secp256k1-bindings.cpp -o http/secp256k1.html -s EXTRA_EXPORTED_RUNTIME_METHODS=["cwrap"] -std=c++11 --bind -s ALLOW_MEMORY_GROWTH=1 -s IMPORTED_MEMORY
emcc -I ./depend/secp256k1 -I ./depend/secp256k1/src secp256k1-bindings.cpp -o http/secp256k1.html -s EXTRA_EXPORTED_RUNTIME_METHODS=["cwrap"] -std=c++11 --bind

