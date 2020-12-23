/*
 * Copyright 2011 The Emscripten Authors.  All rights reserved.
 * Emscripten is available under two separate licenses, the MIT license and the
 * University of Illinois/NCSA Open Source License.  Both these licenses can be
 * found in the LICENSE file.
 */

#include <stdio.h>
#include "emscripten.h"
#include "src/webp/encode.h"

int main() {
  printf("hello, world!\n");
  return 0;
}

EMSCRIPTEN_KEEPALIVE
int fib(int n) {
  if(n <= 0){
    return 0;
  }
  int i, t, a = 0, b = 1;
  for (i = 1; i < n; i++) {
    t = a + b;
    a = b;
    b = t;
  }
  return b;
}


EMSCRIPTEN_KEEPALIVE
int version() {
  return WebPGetEncoderVersion();
}