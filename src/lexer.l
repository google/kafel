/*
   Kafel - lexer
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

%{
#define YY_USER_ACTION yylloc->first_line = yylloc->last_line = yylineno; \
    yylloc->first_column = yycolumn; yylloc->last_column = yycolumn + yyleng; \
    yycolumn += yyleng;
#define YY_USER_INIT                 \
    ctxt->lexical_error = false;     \
    if (yycolumn == 0) yycolumn = 1; \

#define emit_error(fmt, ...)                                  \
    do {                                                      \
        append_error(ctxt, "%d:%d: lexical error, "fmt,       \
                    yylloc->first_line, yylloc->first_column, \
                    ##__VA_ARGS__);                           \
        ctxt->lexical_error = true;                           \
        yyterminate();                                        \
    } while(0)                                                \

#include <stdlib.h>
#include <string.h>
%}

%top {
#include "parser.h"
}

%option outfile="lexer.c" header-file="lexer.h"
%option noyywrap nounput noinput reentrant bison-bridge bison-locations yylineno
%option prefix="kafel_yy"

%s comment

IDENTIFIER [A-Za-z][A-Za-z0-9_]*

%%

<comment>{
[^\n*]+   {}

"*"[^/]   {}

[\n]+  { yycolumn = 1; }

"*/" {
        BEGIN(INITIAL);
    }

<<EOF>> {
  emit_error("unterminated comment");
}

}

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
"ERRNO"         { return ERRNO; }
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
"("             { return '('; }
")"             { return ')'; }
"{"             { return '{'; }
"}"             { return '}'; }
","             { return ','; }
"!"             { return '!'; }
"#"             { return '#'; }
.               { return yytext[0]; }

}

%%
