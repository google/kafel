/*
   Kafel - includes
   -----------------------------------------

   Copyright 2018 Google LLC

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

#include "includes.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"

void includes_ctxt_init(struct includes_ctxt* ctxt) {
  ctxt->depth = 0;
  TAILQ_INIT(&ctxt->search_paths);
  TAILQ_INIT(&ctxt->used_paths);
  SLIST_INIT(&ctxt->stack);
}

void includes_ctxt_clean(struct includes_ctxt* ctxt) {
  ASSERT(ctxt != NULL);
  while (!TAILQ_EMPTY(&ctxt->search_paths)) {
    struct path_list* search_path = TAILQ_FIRST(&ctxt->search_paths);
    TAILQ_REMOVE(&ctxt->search_paths, search_path, list);
    free(search_path->path);
    free(search_path);
  }
  while (!SLIST_EMPTY(&ctxt->stack)) {
    struct included_file* file = SLIST_FIRST(&ctxt->stack);
    SLIST_REMOVE_HEAD(&ctxt->stack, files);
    fclose(file->fp);
    free(file);
  }
  while (!TAILQ_EMPTY(&ctxt->used_paths)) {
    struct path_list* used_path = TAILQ_FIRST(&ctxt->used_paths);
    TAILQ_REMOVE(&ctxt->used_paths, used_path, list);
    free(used_path->path);
    free(used_path);
  }
}

void includes_add_search_path(struct includes_ctxt* ctxt, const char* path) {
  ASSERT(ctxt != NULL);
  ASSERT(path != NULL);
  struct path_list* search_path = calloc(1, sizeof(*search_path));
  search_path->path = strdup(path);
  TAILQ_INSERT_TAIL(&ctxt->search_paths, search_path, list);
}

void includes_stack_push(struct includes_ctxt* ctxt,
                         struct included_file* file) {
  SLIST_INSERT_HEAD(&ctxt->stack, file, files);
  ++ctxt->depth;
}

struct included_file* includes_stack_top(struct includes_ctxt* ctxt) {
  return SLIST_FIRST(&ctxt->stack);
}

bool includes_stack_is_empty(struct includes_ctxt* ctxt) {
  return SLIST_EMPTY(&ctxt->stack);
}

void includes_stack_pop(struct includes_ctxt* ctxt) {
  ASSERT(!SLIST_EMPTY(&ctxt->stack));
  struct included_file* file = SLIST_FIRST(&ctxt->stack);
  fclose(file->fp);
  SLIST_REMOVE_HEAD(&ctxt->stack, files);
  free(file);
  --ctxt->depth;
}

static char* path_join(const char* first, const char* second) {
  size_t flen = strlen(first);
  size_t slen = strlen(second);
  ASSERT(flen <= SIZE_MAX - 2);         // overflow
  ASSERT(flen + 2 <= SIZE_MAX - slen);  // overflow
  size_t len = flen + slen + 1;
  char* rv = malloc(len + 1);
  ASSERT(rv != NULL);  // OOM
  memcpy(rv, first, flen);
  rv[flen] = '/';
  memcpy(rv + flen + 1, second, slen);
  rv[len] = '\0';
  return rv;
}

int includes_depth(struct includes_ctxt* ctxt) { return ctxt->depth; }

struct included_file* includes_resolve(struct includes_ctxt* ctxt,
                                       const char* filename) {
  ASSERT(ctxt != NULL);
  ASSERT(filename != NULL);
  struct path_list* search_path;
  TAILQ_FOREACH(search_path, &ctxt->search_paths, list) {
    char* path = path_join(search_path->path, filename);
    FILE* fp = fopen(path, "r");
    if (fp != NULL) {
      struct path_list* used_path = calloc(1, sizeof(*used_path));
      used_path->path = path;
      TAILQ_INSERT_TAIL(&ctxt->used_paths, used_path, list);
      struct included_file* file = calloc(1, sizeof(*file));
      file->fp = fp;
      file->path = used_path->path;
      return file;
    }
    free(path);
  }
  return NULL;
}
