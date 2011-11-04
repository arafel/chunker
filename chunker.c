#include <stdio.h>

#include "cryptlib.h"

int main(int argc, char *argv[])
{
        int rc = 0;

        if (argc < 2)
        {
                printf("Usage: %s <file> [output basename]\n", argv[0]);
                return 1;
        }

        rc = cryptInit();
        if (cryptStatusError(rc))
        {
                printf("Couldn't init cryptlib - rc %i\n", rc);
                return rc;
        }

cryptlib_setup_exit:
        rc = cryptEnd();
        if (cryptStatusError(rc))
        {
                printf("Couldn't end cryptlib - rc %i\n", rc);
                return rc;
        }

        return rc;
}
