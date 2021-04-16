/*
   Kafel - parser types
   -----------------------------------------

   Copyright 2020 Google LLC

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

#ifndef KAFEL_PARSER_TYPES_H
#define KAFEL_PARSER_TYPES_H

#include <stdint.h>
#include <sys/queue.h>

struct kafel_constant {
  char *name;
  uint64_t value;
  TAILQ_ENTRY(kafel_constant) constants;
};

struct kafel_source_location {
  int first_line;
  int first_column;
  int last_line;
  int last_column;
  const char *filename;
};

struct kafel_identifier {
  char *id;
  struct kafel_source_location loc;
};

struct kafel_identifier *kafel_identifier_create(
    const char *id, const struct kafel_source_location *loc);
struct kafel_identifier *kafel_identifier_copy(
    const struct kafel_identifier *identifier);
void kafel_identifier_destroy(struct kafel_identifier **identifier);

#endif /* KAFEL_PARSER_TYPES_H */
