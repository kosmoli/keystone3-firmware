/*
 * gui_ur_macros.h — UR 结果处理工具宏
 *
 * 纯工具宏，与链逻辑无关。从 gui_chain.h 中提取。
 */

#ifndef _GUI_UR_MACROS_H
#define _GUI_UR_MACROS_H

#include <stdio.h>

/* UREncodeResult 前向声明（定义在 rust.h） */
typedef struct UREncodeResult UREncodeResult;

#define CHECK_CHAIN_BREAK(result)                                       \
    if (result->error_code != 0) {                                      \
        printf("result->code = %d\n", result->error_code);              \
        printf("result->error message = %s\n", result->error_message);  \
        break;                                                          \
    }

#define CHECK_CHAIN_RETURN(result)                                      \
    if (result->error_code != 0) {                                      \
        printf("result->code = %d\n", result->error_code);              \
        printf("result->error message = %s\n", result->error_message);  \
        return NULL;                                                    \
    }

#define CHECK_FREE_UR_RESULT(result, multi)                             \
    if (result != NULL) {                                               \
        if (multi) {                                                    \
            free_ur_parse_multi_result((PtrT_URParseMultiResult)result);\
        } else {                                                        \
            free_ur_parse_result((PtrT_URParseResult)result);           \
        }                                                               \
        result = NULL;                                                  \
    }

#endif /* _GUI_UR_MACROS_H */
