#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

int main(int argc, char *argv[])
{
        int fh, i;
        char ch;
        ssize_t bytes;

        if (argc < 2)
        {
                printf("Usage: %s file [file ...]\n", argv[0]);
                return 1;
        }

        for (i = 1; i < argc; i++)
        {
                fh = open(argv[i], O_RDONLY);
                if (fh < 0)
                {
                        printf("Opening file '%s'...\n", argv[i]);
                        perror("Couldn't open");
                        continue;
                }

                bytes = read(fh, &ch, 1);
                while (bytes > 0)
                {
                        printf("%02x", (unsigned char)ch);
                        bytes = read(fh, &ch, 1);
                }

                printf("\n");

                close(fh);
        }

        return 0;
}
