#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char * ft_des(char *param_1)
{
	char *param_copy;
	uint param_len;
	char *param_copy_2;
	uint param_index;
	int num_index;
	int i;
	int j;
	char num_str[] = "0123456";
	char p_char;

	param_copy = strdup(param_1);
	num_index = 0;
	param_index = 0;

	param_copy_2 = param_copy;
	param_len = 0xffffffff;
	/* calculate the length of parameter : strlen(param_1) */
	do	{
		if (param_len == 0)
			break;
		param_len = param_len - 1;
		p_char = *param_copy_2;
		param_copy_2 = param_copy_2 + 1;
	} while(p_char);
	do {
		/* If param_index == len */
		if (~param_len - 1 <= param_index)
			return (param_copy);

		if (num_index == 6)
			num_index = 0;

		/* if param_index is a XX number then it's true */
		if ((param_index & 1) == 0)
		{
			if ((param_index & 1) == 0) 
			{
				i = 0;
				while (i < num_str[num_index])
				{
					param_copy[param_index] = param_copy[param_index] + -1;
					if (param_copy[param_index] == 0x1f)
						param_copy[param_index] = '~';
					i = i + 1;
				}
			}
		}
		else
		{
			j = 0;
			while (j < num_str[num_index])
			{
				param_copy[param_index] = param_copy[param_index] + 1;
				if (param_copy[param_index] == 0x7f) // 0x7f is the ascii code for Delete
					param_copy[param_index] = ' ';
				j = j + 1;
			}
		}
		param_index = param_index + 1;
		num_index = num_index + 1;
	} while( true );
}

int main(int argc, char const *argv[])
{
	printf("Flag : %s\n", ft_des("boe]!ai0FB@.:|L6l@A?>qJ}I"));
	return 0;
}
