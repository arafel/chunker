/**
 * Copyright 2012, Paul Walker.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/**** Includes */

/* System */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

/**** Main functions */

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
