#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ESCAPE_QUOTE "&quot;"
#define ESCAPE_QUOTE_LEN 6
#define ESCAPE_LF "&#10;"
#define ESCAPE_LF_LEN 5
#define ESCAPE_CR "&#13;"
#define ESCAPE_CR_LEN 5

char *escape(char *to_escape, int *escaped_len) {
	char *escaped = NULL;
	char *escape_quote = ESCAPE_QUOTE;
	char *escape_lf = ESCAPE_LF;
	char *escape_cr = ESCAPE_CR;
	int i = 0;
	int to_escape_len = strlen(to_escape);

	*escaped_len = 0;
	while (i<to_escape_len) {

		/*
		 * Our alloc'd size is always one ahead 
		 * of the string length to accommodate 
		 * the NULL for the NULL-termination.
		 */
		switch (to_escape[i]) {
			case '\"':
				escaped = (char*)realloc(escaped, (*escaped_len) + ESCAPE_QUOTE_LEN + 1);
				memcpy(escaped + *escaped_len, escape_quote, ESCAPE_QUOTE_LEN);
				*escaped_len = *escaped_len + ESCAPE_QUOTE_LEN;
				break;
			case '\n':
				escaped = (char*)realloc(escaped, (*escaped_len) + ESCAPE_LF_LEN + 1);
				memcpy(escaped + *escaped_len, escape_lf, ESCAPE_LF_LEN);
				*escaped_len = *escaped_len + ESCAPE_LF_LEN;
				break;
			case '\r':
				escaped = (char*)realloc(escaped, (*escaped_len) + ESCAPE_CR_LEN + 1);
				memcpy(escaped + *escaped_len, escape_cr, ESCAPE_CR_LEN);
				*escaped_len = *escaped_len + ESCAPE_CR_LEN;
				break;
			default:
				escaped = (char*)realloc(escaped, (*escaped_len)+1+1);
				escaped[*escaped_len] = to_escape[i];
				*escaped_len = *escaped_len + 1;
		}
		escaped[*escaped_len] = '\0';
		i++;
	}
	return escaped;
}