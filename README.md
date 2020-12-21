

### Repositories you need to clone

* git clone https://github.com/aspectron/secp256k1-wasm
* git clone https://github.com/WebAssembly/binaryen.git 
* git clone https://github.com/llvm/llvm-project.git
* git clone https://github.com/emscripten-core/emscripten.git


### Build emscripten
```
cd emscripten
mkdir build
cd build/
cmake ../../llvm-project/llvm -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_PROJECTS='lld;clang' -DLLVM_TARGETS_TO_BUILD="host;WebAssembly" -DLLVM_INCLUDE_EXAMPLES=OFF -DLLVM_INCLUDE_TESTS=OFF
cmake --build . -j NNN
NNN = no of CPU cores/threads  to faster the build process;
OR: cmake --build . --config Release -j NNN
cd ..     (emscripten dir)
./emcc  -v   cd ..
<this command "./emcc -v" will create .emscripten file>
 in .emscripten file ---> 
point "LLVM_ROOT" to <path to emscripten>/build/bin
point "BINARYEN_ROOT" to <path to binaryen>
restest "./emcc  -v" command now all should be ok to show version of emcc, clang and InstalledDir etc info
```

### Build binaryen
```
cd binaryen
cmake .
cmake --build . --config Release
cmake --build . --config Release -j NNN
```

### Build secp256k1-wasm
```
emcc -I ./depend/secp256k1-wasm -I ./depend/secp256k1-wasm/src secp.cpp -o http/secp.html -s EXTRA_EXPORTED_RUNTIME_METHODS=["cwrap"] -std=c++11 --bind -s ALLOW_MEMORY_GROWTH=1

npm install
node server
```

### msys2
```
pacman -S python base-devel
```