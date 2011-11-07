/**** Includes */

/* System */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

/* Libraries */
#include "cryptlib.h"

/**** Constants and macros */

#define BUFSIZE         (5 * 1024)

/**** Typedefs */

/**** Statics */

/**** Prototypes */

static int filesize(const char *filename, unsigned long long int *filesize);
static CRYPT_CONTEXT *init_context(CRYPT_ALGO_TYPE algorithm);
static int free_context(CRYPT_CONTEXT *context);
static int reset_context(CRYPT_CONTEXT *context);

/**** Worker functions */

static int filesize(const char *filename, unsigned long long int *filesize)
{
        struct stat st;

        if (stat(filename, &st))
        {
                printf("Checking filesize of %s\n", filename);
                perror("Error");
                return -1;
        }
        else
                *filesize = st.st_size;

        return 0;
}

static CRYPT_CONTEXT *init_context(CRYPT_ALGO_TYPE algorithm)
{
        int rc;
        CRYPT_CONTEXT *context = NULL;

        context = malloc(sizeof(CRYPT_CONTEXT));
        if (!context)
        {
                printf("Couldn't allocate %i bytes for context.\n", sizeof(CRYPT_CONTEXT));
                return NULL;
        }

        rc = cryptCreateContext(context, CRYPT_UNUSED, algorithm);
        if (cryptStatusError(rc))
        {
                free(context);
                printf("Error %i creating context.\n", rc);
        }

        return context;
}

static int free_context(CRYPT_CONTEXT *context)
{
        int rc;

        if (!context)
        {
                printf("Bad context %p given\n", context);
                return -1;
        }

        rc = cryptDestroyContext(*context);
        if (cryptStatusError(rc))
        {
                printf("Error %i destroying context.\n", rc);
                rc = -1;
        }
        else
        {
                rc = 0;
                free(context);
        }

        return rc;
}

static int reset_context(CRYPT_CONTEXT *context)
{
        int rc = 0;

        printf("%s - write me.\n", __func__);
        return rc;
}

/**** Main functions */

int split_file(CRYPT_CONTEXT *md5, CRYPT_CONTEXT *sha1, const char *infilename, const char *outfilenamebase, unsigned long long int chunksize)
{
        unsigned long long int infilesize;
        int rc;

        rc = 0;
        if (!infilename)
        {
                printf("Invalid input filename %p\n", infilename);
                return -1;
        }
        if (!outfilenamebase)
        {
                printf("Invalid output filename %p\n", outfilenamebase);
                return -1;
        }

        reset_context(md5);
        reset_context(sha1);

        if (filesize(infilename, &infilesize))
        {
                printf("Couldn't get filesize of input file '%s'\n", infilename);
                return -1;
        }

        printf("Splitting '%s' into chunks with basename '%s'\n", infilename, outfilenamebase);
        printf("'%s' is %llu bytes in length; chunk length is %lld.\n", infilename, infilesize, chunksize);
        printf("Buffer size is %i\n", BUFSIZE);

        return 0;
}
 
int main(int argc, char *argv[])
{
        int rc = 0;
        CRYPT_CONTEXT *md5, *sha1;
        unsigned long int chunksize = (10 * 1024);

        if (argc < 3)
        {
                printf("Usage: %s <file> <output basename>\n", argv[0]);
                return 1;
        }

        rc = cryptInit();
        if (cryptStatusError(rc))
        {
                printf("Couldn't init cryptlib - rc %i\n", rc);
                return rc;
        }

        md5 = init_context(CRYPT_ALGO_MD5);
        if (!md5)
                printf("Couldn't create MD5 context\n");
        else
                printf("Got MD5 context %p\n", md5);
        sha1 = init_context(CRYPT_ALGO_SHA1);
        if (!sha1)
                printf("Couldn't create SHA1 context\n");
        else
                printf("Got SHA1 context %p\n", sha1);

        split_file(md5, sha1, argv[1], argv[2], chunksize);

        free_context(md5);
        free_context(sha1);

/* cryptlib_setup_exit: */
        rc = cryptEnd();
        if (cryptStatusError(rc))
        {
                printf("Couldn't end cryptlib - rc %i\n", rc);
                return rc;
        }

        return rc;
}
