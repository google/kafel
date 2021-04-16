/*
   Kafel - dump BPF code for a policy
   -----------------------------------------

   Copyright 2016 Google LLC

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

#include <kafel.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "disasm.h"
#include "print.h"

int main(int argc, char** argv) {
  enum mode { HUMAN_READABLE, C_SOURCE_FILE } mode = HUMAN_READABLE;
  int opt;
  while ((opt = getopt(argc, argv, "hc")) != -1) {
    switch (opt) {
      case 'h':
        mode = HUMAN_READABLE;
        break;
      case 'c':
        mode = C_SOURCE_FILE;
        break;
      default: /* '?' */
        fprintf(stderr, "Usage: %s [-hc] INPUT\n", argv[0]);
        return -1;
    }
  }

  FILE* in = stdin;
  if (argc > optind) {
    in = fopen(argv[optind], "r");
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
  switch (mode) {
    case HUMAN_READABLE:
      printf("BPF program with %d instructions\n", prog.len);
      disasm(prog);
      break;
    case C_SOURCE_FILE:
      pretty_print(prog);
      break;
  }
  free(prog.filter);
  return 0;
}
