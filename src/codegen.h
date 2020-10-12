/*
   Kafel - code generator
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

#ifndef KAFEL_CODEGEN_H
#define KAFEL_CODEGEN_H

#include <linux/filter.h>

#include "context.h"

int compile_policy(struct kafel_ctxt *kafel_ctxt, struct sock_fprog *prog);
void free_sock_program(struct sock_fprog* prog);
int knit_policy(struct kafel_ctxt* kafel_ctxt,
                struct sock_fprog* target_programs,
                struct sock_fprog* companion_programs,
                int default_action,
                struct sock_fprog* prog);

#endif /* KAFEL_CODEGEN_H */
