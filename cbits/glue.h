#ifndef __HS_NACL_GLUE_H__
#define __HS_NACL_GLUE_H__

#if defined(__GLASGOW_HASKELL__)

#define NACL_GLUE(f,ty)			\
  foreign import ccall unsafe #f	\
    f :: ty

#else
#error What are you doing?
#endif

#endif /* __HS_NACL_GLUE_H__ */
