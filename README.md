secp256k1-wasm
==============

EMCC+LLVM WebAssembly bindings for [libsecp256k1 ](https://github.com/bitcoin-core/secp256k1)

This project provides Emscripten WASM bindings for libsecp256k1 and provides basic scaffolding to build the native libsecp256k1 C code to WASM using EMCC.

Building secp256k1-wasm
-----------------------

Repositories you will need to clone:

    $ git clone https://github.com/aspectron/secp256k1-wasm
    $ git clone https://github.com/WebAssembly/binaryen
    $ git clone https://github.com/llvm/llvm-project
    $ git clone https://github.com/emscripten-core/emscripten

Building Binaryen:

    $ cd binaryen
    $ cmake .
    $ cmake --build . --config Release -j NNN
    NNN = number of CPU cores/threads

Override emscripten src files:

    $ cp emscripten_override/src/* to emscripten/src/

The following process builds LLVM inside the `./emscripten/build` folder:

    $ cd emscripten
    $ mkdir build
    $ cd build/
    $ cmake ../../llvm-project/llvm -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_PROJECTS='lld;clang' -DLLVM_TARGETS_TO_BUILD="host;WebAssembly" -DLLVM_INCLUDE_EXAMPLES=OFF -DLLVM_INCLUDE_TESTS=OFF
    $ cmake --build . --config Release -j NNN
    NNN = number of CPU cores/threads
    $ cd ..     
    
We are now back in the Emscripten folder. Generate the default `.emscripten` file:

    $ ./emcc  -v

Edit the `.emscripten` file to contain correct paths to LLVM and Binaryen:

  * point `LLVM_ROOT` to `<path to emscripten>/build/bin` or `<path to emscripten>/build/Release/bin` if LLVM was built using Visual C++
  * point `BINARYEN_ROOT` to `<path to binaryen>`

Re-run `./emcc -v` to check that everything is ok.  You should now see the version of EMCC, clang and InstalledDir information.

Build secp256k1-wasm:

You can run `./build` or `build.bat` to build the WASM binaries or execute the following:

    $ emcc -I ./depend/secp256k1 -I ./depend/secp256k1/src secp256k1-bindings.cpp -o http/secp256k1.html -s EXTRA_EXPORTED_RUNTIME_METHODS=["cwrap"] -std=c++11 --bind -s ALLOW_MEMORY_GROWTH=1 -s IMPORTED_MEMORY

To test the build, you will require an installed version of NodeJs. From within the `secp256k1-wasm` folder please run the following:

using python SimpleHTTPServer:

    $ python -m SimpleHTTPServer 8000

using nodejs:

    $ npm install
    $ node test/node-server

You should now be able to access the emscripten environment with secp256k1 loaded at http://localhost:3000
