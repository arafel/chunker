/**** Includes */

/* System */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

/* Libraries */
#include "cryptlib.h"

/**** Constants and macros */

/**** Typedefs */


typedef struct file_info_s
{
        int     fd;
        char    *start_buf;
        char    *temp_buf;
        unsigned int bufsize;
        unsigned long long size;
        unsigned long long offset;
} file_info;

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

static int open_file(const char *filename, file_info *file, bool reading, bool create, unsigned int bufsize)
{
        int flags;

        assert(file != NULL);
        assert(filename != NULL);

        /* Default */
        file->fd = -1;
        file->start_buf = MAP_FAILED;

        if (reading)
        {
                if (filesize(filename, &file->size))
                {
                        printf("Couldn't get filesize of input file '%s'\n", filename);
                        return -1;
                }
        }
        else
                file->size = -1;

        if (reading)
                flags = O_RDONLY;
        else
        {
                flags = O_RDWR;
                if (create)
                        flags |= O_CREAT | O_TRUNC;
        }

        printf("Opening %s for %s\n", filename, reading?"reading":"writing");
        file->fd = open(filename, flags, 0644);
        if (file->fd < 0)
        {
                perror("Couldn't open file");
        }

        /* Try mmap */
        if (reading)
                flags = PROT_READ;
        else
                flags = PROT_WRITE;
        file->start_buf = mmap(0, file->size, flags, MAP_SHARED, file->fd, 0);
        if (MAP_FAILED == file->start_buf)
        {
                printf("Couldn't mmap file, will access the slow way.\n");
                file->temp_buf = malloc(bufsize);
                if (NULL == file->temp_buf)
                {
                        printf("Couldn't allocate %i bytes for temporary memory.\n", bufsize);
                        close(file->fd);
                        file->fd = -1;
                }
                else
                {
                        printf("Allocated temporary buffer at %p\n", file->temp_buf);
                }
        }
        else
        {
                printf("Successfully mmapped input to %p\n", file->start_buf);
                file->temp_buf = NULL;
        }

        file->offset = 0;
        file->bufsize = bufsize;

        return 0;
}

static int close_file(file_info *file)
{
        assert(file != NULL);

        if (file->fd < 0)
        {
                printf("Bad parameter, file isn't opened");
                return -1;
        }

        if (MAP_FAILED != file->start_buf)
        {
                printf("Unmapping %lld bytes (buffer %p)\n", file->size, file->start_buf);
                munmap(file->start_buf, file->size);
        }

        if (file->temp_buf)
        {
                printf("Freeing temporary buffer %p\n", file->temp_buf);
                free(file->temp_buf);
        }

        close(file->fd);

        return 0;
}

static int file_next_buffer(file_info *file, char **buf, unsigned int *count)
{
        ssize_t bytesread;

        assert(file);
        assert(file->fd >= 0);
        assert(buf);

        printf("%s asked for next buffer on file %p\n", __func__, file);

        if (file->offset == file->size)
        {
                *buf = NULL;
                *count = 0;
                return 0;
        }

        /* TODO implement common offset/size checking to ensure getting next buffer makes sense */

        /* See if we can do it the easy way */
        if (file->start_buf)
        {
                printf("File is mapped, easy.\n");
                printf("start_buf %p bufsize %i\n", file->start_buf, file->bufsize);
                *buf = file->start_buf + file->offset;
                printf("Returning %p\n", *buf);
                if ((file->size - file->offset) > file->bufsize)
                        bytesread = file->bufsize;
                else
                        bytesread = (file->size - file->offset);
        }
        else
        {
                printf("File isn't mapped, less easy.\n");

                /* For speed, assume we're the only ones using this file pointer. */
                bytesread = read(file->fd, file->temp_buf, file->bufsize);
                if (0 == bytesread)
                {
                        printf("Got 0 for bytesread, EOF.\n");
                        if (file->offset < file->size)
                        {
                                printf("File offset is %lld, size is %lld - unexpected EOF.\n", file->offset, file->size);
                        }
                }
                else if (bytesread != file->bufsize)
                {
                        printf("Bytes read %i doesn't match bufsize %i\n", bytesread, file->bufsize);
                }

        }

        file->offset += bytesread;
        *count = bytesread;

        return 0;
}

/**** Main functions */

int split_file(CRYPT_CONTEXT *md5, CRYPT_CONTEXT *sha1, const char *infilename, const char *outfilenamebase, unsigned long long int chunksize)
{
        char *buf;
        file_info infile;
        file_info outfile;
        int rc;
        unsigned int count;

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

        printf("Splitting '%s' into chunks with basename '%s'\n", infilename, outfilenamebase);
        printf("'%s' is %llu bytes in length; chunk length is %lld.\n", infilename, infile.size, chunksize);

        if (open_file(infilename, &infile, true, false, 5000))
        {
                printf("Couldn't open input file for reading\n");
                return -1;
        }

        /* TODO build up chunk names */
        if (open_file("test.bin", &outfile, false, true, 7500))
        {
                printf("Couldn't open output file for writing\n");
                close_file(&infile);
                return -1;
        }

#if 0
        file_next_buffer(&infile, &buf, &count);
        printf("Got buffer %p, count %i\n", buf, count);
        file_next_buffer(&infile, &buf, &count);
        printf("Got buffer %p, count %i\n", buf, count);
#else
        do
        {
                file_next_buffer(&infile, &buf, &count);
                printf("Got buffer %p, count %i\n", buf, count);
                if (count && (write(outfile.fd, buf, count) != count))
                {
                        printf("Didn't write expected number of bytes.\n");
                }
        } while (count > 0);
#endif

        close_file(&infile);
        close_file(&outfile);

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
