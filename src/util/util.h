#ifndef UTIL_H
#define UTIL_H

#define ARRAY_LEN(first, ...) \
	(sizeof(((typeof(first) []){first, __VA_ARGS__}))/(sizeof(typeof(first))))

#define bool_equal(a,b) ({	\
	typeof(a) _a = (a);	\
	typeof(b) _b = (b);	\
	((_a) ? (_b) : (!(_b)));	\
})

#endif
