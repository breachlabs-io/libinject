#ifndef _INJ_INJECT_H
#define _INJ_INJECT_H

#ifndef NDEBUG
#include <stdio.h>
#include <errno.h>
#include <string.h>
#define dprint(...) (printf(__VA_ARGS__))
#else
#define dprint(...)
#endif

#endif // _INJ_INJECT_H