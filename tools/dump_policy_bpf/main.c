/*
   Kafel - dump BPF code for a policy
   -----------------------------------------

   Copyright 2016 Google Inc. All Rights Reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

*/

#include <stdio.h>
#include <stdlib.h>

#include <kafel.h>

#include "disasm.h"

int main(int argc, char** argv) {
  FILE* in = stdin;
  if (argc > 1) {
    in = fopen(argv[1], "r");
    if (in == NULL) {
      fprintf(stderr, "Error: could not open file `%s'\n", argv[1]);
      return -1;
    }
  }

  kafel_ctxt_t ctxt = kafel_ctxt_create();
  kafel_set_input_file(ctxt, in);

  struct sock_fprog prog;
  int rv = kafel_compile(ctxt, &prog);
  if (in != stdin) {
    fclose(in);
  }
  if (rv != 0) {
    fprintf(stderr, "Compile error\n");
    fprintf(stderr, "\t%s", kafel_error_msg(ctxt));
    kafel_ctxt_destroy(&ctxt);
    return -1;
  }
  kafel_ctxt_destroy(&ctxt);
  printf("BPF program with %d instructions\n", prog.len);
  disasm(prog);
  free(prog.filter);
  return 0;
}
