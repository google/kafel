/*
   Kafel - BPF pretty printer
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

#ifndef KAFEL_PRINT_H
#define KAFEL_PRINT_H

#include <linux/filter.h>

void pretty_print_inst(const struct sock_filter* inst);
void pretty_print(struct sock_fprog prog);

#endif /* KAFEL_PRINT_H */
