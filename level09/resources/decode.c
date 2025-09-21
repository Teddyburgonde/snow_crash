#include <stdio.h>

int main(int argc, char **argv)
{
    int i;

    i = 0;

    if (argc != 2)
        return 1;
    while (argv[1][i])
    {
        printf("%c", argv[1][i] -i);
        i++;
    }
}
