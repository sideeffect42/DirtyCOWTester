#ifndef HAVE_PREFIX_H
#define HAVE_PREFIX_H

#ifndef __bool_true_false_are_defined
typedef signed char bool;
#define true  ((bool)(!0))
#define false ((bool)( 0))
#endif

#define NL "\n"
#define __DEBUG_PRINTF(...)														\
	do {																			\
		if (__DEBUG__) { fprintf(stderr, "DEBUG (" __FILE__ "): " __VA_ARGS__); }	\
	} while (false)

#ifndef __DEBUG__
#define __DEBUG__ 0
#endif

#endif
