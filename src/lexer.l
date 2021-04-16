/*
   Kafel - lexer
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

%{
#define YY_USER_ACTION yylloc->first_line = yylloc->last_line = yylineno;     \
    yylloc->first_column = yycolumn; yylloc->last_column = yycolumn + yyleng; \
    yycolumn += yyleng;
#define YY_USER_INIT             \
    ctxt->lexical_error = false; \
    if (yycolumn == 0) yycolumn = 1;

#define set_error(loc, fmt, ...)                            \
    do {                                                    \
        append_error(ctxt, "%d:%d: "fmt, (loc)->first_line, \
                     (loc)->first_column, ##__VA_ARGS__);   \
        ctxt->lexical_error = true;                         \
    } while(0)

#define set_error_r(scanner, fmt, ...)                       \
    set_error(kafel_yyget_lloc(scanner), fmt, ##__VA_ARGS__)

#define emit_error(fmt, ...)                   \
    do {                                       \
        set_error(yylloc, fmt, ##__VA_ARGS__); \
        yyterminate();                         \
    } while(0)

#include <stdlib.h>
#include <string.h>

#include "common.h"

static bool push_include(yyscan_t yyscanner);
static bool pop_include(yyscan_t yyscanner);
%}

%top {
#include "parser.h"

#define MAX_INCLUDE_DEPTH 16

#define YYSTYPE KAFEL_YYSTYPE
#define YYLTYPE KAFEL_YYLTYPE

#define YY_DECL_IS_OURS 1
#define YY_DECL \
      int kafel_yylex(YYSTYPE* yylval_param, YYLTYPE* yylloc_param, \
                      struct kafel_ctxt* ctxt, yyscan_t yyscanner)
YY_DECL;
}

%option outfile="lexer.c" header-file="lexer.h"
%option noyywrap nounput noinput reentrant bison-bridge bison-locations yylineno
%option prefix="kafel_yy"

%s comment
%s include

IDENTIFIER [A-Za-z][A-Za-z0-9_]*

%%

%{
bool whitespace = false;
%}

<INITIAL>{

"//"[^\n]* {} /* line comments */

"/*" { /* C-style comments */
        BEGIN(comment);
    }


0x[0-9a-fA-F]+ {
        errno = 0;
        unsigned long long val = strtoull(yytext, NULL, 16);
        if (errno == ERANGE) {
          emit_error("number `%s' out of range", yytext);
        }
        yylval->number = val;
        return NUMBER;
    }

([0])|(-?[1-9][0-9]*) {
        errno = 0;
        unsigned long long val = strtoull(yytext, NULL, 10);
        if (errno == ERANGE) {
          emit_error("number `%s' out of range", yytext);
        }
        yylval->number = val;
        return NUMBER;
    }

[0][0-9]+ {
        errno = 0;
        unsigned long long val = strtoull(yytext, NULL, 8);
        if (errno == ERANGE) {
          emit_error("number `%s' out of range", yytext);
        }
        yylval->number = val;
        return NUMBER;
    }

[0][b][01]+ {
        errno = 0;
        unsigned long long val = strtoull(yytext+2, NULL, 2);
        if (errno == ERANGE) {
          emit_error("number `%s' out of range", yytext);
        }
        yylval->number = val;
        return NUMBER;
    }

"SYSCALL"       { return SYSCALL; }
"ALLOW"         { return ALLOW; }
"LOG"           { return LOG; }
"USER_NOTIF"    { return USER_NOTIF; }
"ERRNO"         { return ERRNO; }
"KILL_PROCESS"  { return KILL_PROCESS; }
"KILL_THREAD"   { return KILL; }
"KILL"          { return KILL; }
"DENY"          { return DENY; }
"TRAP"          { return TRAP; }
"TRACE"         { return TRACE; }
"USE"           { return USE; }
"POLICY"        { return POLICY; }
"DEFAULT"       { return DEFAULT; }
"define"        { return DEFINE; }

{IDENTIFIER} {
        yylval->id = strdup(yytext);
        return IDENTIFIER;
    }

"#include" { /* include statement */
        BEGIN(include);
    }

[ \t]+        {}
[\n]+         { yycolumn = 1; }

"=="            { return EQ; }
"!="            { return NEQ; }
"<="            { return LE; }
"<"             { return LT; }
">="            { return GE; }
">"             { return GT; }

"||"            { return LOGIC_OR; }
"&&"            { return LOGIC_AND; }
"|"             { return BIT_OR; }
"&"             { return BIT_AND; }
"["             { return '['; }
"]"             { return ']'; }
"("             { return '('; }
")"             { return ')'; }
"{"             { return '{'; }
"}"             { return '}'; }
","             { return ','; }
"!"             { return '!'; }
"#"             { return '#'; }

}

<comment>{
[^\n*]+   {}

"*"[^/]   {}

[\n]+     { yycolumn = 1; }

"*/"      { /* end of comment */
        BEGIN(INITIAL);
    }

<<EOF>>   {
        if (pop_include(yyscanner)) {
            BEGIN(include);
        } else {
            emit_error("unterminated comment");
        }
    }
}

<INITIAL>{
    <<EOF>> {
      if (pop_include(yyscanner)) {
          BEGIN(include);
      } else {
          yyterminate();
      }
    }
}

<include>{
[ \t]+        {
                whitespace = true;
    }
["][^"]+["]   {
        if (!whitespace) {
            emit_error("unexpected filename");
        }
        whitespace = false;
        if (push_include(yyscanner)) {
            BEGIN(INITIAL);
        } else {
            yyterminate();
        }
    }
[\n;]         { /* end of include */
        BEGIN(INITIAL);
    }
<<EOF>>       { /* unterminated include */
        emit_error("unterminated include statement");
    }
}

<*>. { emit_error("unexpected char `%c'", yytext[0]); }

%%

static bool push_include(yyscan_t yyscanner) {
  const char* filename_in_quotes = yyget_text(yyscanner);
  struct kafel_ctxt* ctxt = (struct kafel_ctxt*)yyget_extra(yyscanner);
  ASSERT(ctxt != NULL);
  struct includes_ctxt* ictxt = &ctxt->includes_ctxt;
  if (includes_depth(ictxt) >= MAX_INCLUDE_DEPTH) {
      set_error_r(yyscanner, "maximum include depth (%d) exceeded",
                  MAX_INCLUDE_DEPTH);
      return false;
  }
  size_t len = strlen(filename_in_quotes);
  ASSERT(len > 2);
  char* fname = malloc(len-1);
  ASSERT(fname != NULL);
  memcpy(fname, filename_in_quotes+1, len-2);
  fname[len-2] = '\0';
  struct included_file* file = includes_resolve(ictxt, fname);
  if (file == NULL) {
      set_error_r(yyscanner, "could not include file `%s'", fname);
      free(fname);
      fname = NULL;
      return false;
  }
  free(fname);
  fname = NULL;
  includes_stack_push(ictxt, file);
  YY_BUFFER_STATE buf_state = kafel_yy_create_buffer(file->fp, YY_BUF_SIZE,
                                                     yyscanner);
  kafel_yypush_buffer_state(buf_state, yyscanner);
  yyget_lloc(yyscanner)->filename = file->path;
  return true;
}

static bool pop_include(yyscan_t yyscanner) {
    struct kafel_ctxt* ctxt = (struct kafel_ctxt*)yyget_extra(yyscanner);
    ASSERT(ctxt != NULL);
    struct includes_ctxt* ictxt = &ctxt->includes_ctxt;
    if (!includes_stack_is_empty(ictxt)) {
        includes_stack_pop(ictxt);
        kafel_yypop_buffer_state(yyscanner);
        const char* fname = NULL;
        if (!includes_stack_is_empty(ictxt)) {
          fname = includes_stack_top(ictxt)->path;
        }
        yyget_lloc(yyscanner)->filename = fname;
        return true;
    }
    return false;
}
