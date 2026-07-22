#ifndef MLK_EXCHANGE_H
#define MLK_EXCHANGE_H

#include "common.h"

#define mlk_exchange MLK_NAMESPACE_K(exchange)
MLK_EXTERNAL_API
int mlk_exchange();

#define mlk_tempo_exchange MLK_TEMPO_NAMESPACE_K(exchange)
MLK_EXTERNAL_API
int mlk_tempo_exchange();

#endif
