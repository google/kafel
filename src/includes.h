/*
   Kafel - includes
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

#ifndef KAFEL_INCLUDES_H
#define KAFEL_INCLUDES_H

#include <stdbool.h>
#include <stdio.h>
#include <sys/queue.h>

struct included_file {
  FILE* fp;
  const char* path;
  SLIST_ENTRY(included_file) files;
};

struct path_list {
  char* path;
  TAILQ_ENTRY(path_list) list;
};

struct includes_ctxt {
  int depth;
  TAILQ_HEAD(, path_list) search_paths;
  TAILQ_HEAD(, path_list) used_paths;
  SLIST_HEAD(, included_file) stack;
};

void includes_ctxt_init(struct includes_ctxt* ctxt);
void includes_ctxt_clean(struct includes_ctxt* ctxt);

void includes_add_search_path(struct includes_ctxt* ctxt, const char* path);
void includes_stack_push(struct includes_ctxt* ctxt,
                         struct included_file* file);
struct included_file* includes_stack_top(struct includes_ctxt* ctxt);
bool includes_stack_is_empty(struct includes_ctxt* ctxt);
void includes_stack_pop(struct includes_ctxt* ctxt);

int includes_depth(struct includes_ctxt* ctxt);
struct included_file* includes_resolve(struct includes_ctxt* ctxt,
                                       const char* filename);

#endif /* KAFEL_INCLUDES_H */
