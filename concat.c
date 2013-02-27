#include <stdio.h>
#include <stdlib.h>
#include <avahi-core/core.h>
#include <string.h>

#define OPEN_DELIMITER "\""
#define OPEN_DELIMITER_LEN 1
#define CLOSE_DELIMITER "\""
#define CLOSE_DELIMITER_LEN 1
#define FIELD_DELIMITER ","
#define FIELD_DELIMITER_LEN 1

#include "escape.h"

char *txt_list_to_string(AvahiStringList *txt) {
    char *list = NULL;
    char *open_delimiter = OPEN_DELIMITER;
    char *close_delimiter = CLOSE_DELIMITER;
    char *field_delimiter = FIELD_DELIMITER;
    int list_len = 0;
    for (; txt; txt = txt->next) {
        int escaped_len = 0;
        char *escaped = escape(txt->text, &escaped_len);

        list = (char*)realloc(list, list_len + 
                                    OPEN_DELIMITER_LEN +
                                    CLOSE_DELIMITER_LEN +
                                    escaped_len + 
                                    1);
        list[list_len] = '\0';

        strcat(list, open_delimiter);
        strcat(list, escaped);
        strcat(list, close_delimiter);

        list_len += escaped_len + OPEN_DELIMITER_LEN + CLOSE_DELIMITER_LEN;
        list[list_len] = '\0';

        if (txt->next) {
            list = (char*)realloc(list, list_len + FIELD_DELIMITER_LEN + 1);
            strcat(list, field_delimiter);
            list_len += FIELD_DELIMITER_LEN;
            list[list_len] = '\0';
        }

	free(escaped);
    }
    return list;
}