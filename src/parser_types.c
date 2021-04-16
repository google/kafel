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

#include "parser_types.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"

struct kafel_identifier *kafel_identifier_create(
    const char *id, const struct kafel_source_location *loc) {
  ASSERT(id != NULL);
  ASSERT(loc != NULL);

  struct kafel_identifier *rv = calloc(1, sizeof(*rv));
  rv->id = strdup(id);
  rv->loc = *loc;
  return rv;
}

struct kafel_identifier *kafel_identifier_copy(
    const struct kafel_identifier *identifier) {
  ASSERT(identifier != NULL);
  return kafel_identifier_create(identifier->id, &identifier->loc);
}

void kafel_identifier_destroy(struct kafel_identifier **identifier) {
  ASSERT(identifier != NULL);
  ASSERT((*identifier) != NULL);

  free((*identifier)->id);
  free(*identifier);
  *identifier = NULL;
}
