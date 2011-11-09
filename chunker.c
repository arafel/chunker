/**** Includes */

/* System */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>
#include <fcntl.h>
#include <string.h>
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
        file->temp_buf = NULL;

        if (reading)
        {
                if (filesize(filename, &file->size))
                {
                        printf("Couldn't get filesize of input file '%s'\n", filename);
                        return -1;
                }
                flags = O_RDONLY;
        }
        else
        {
                file->size = -1;

                flags = O_RDWR;
                if (create)
                        flags |= O_CREAT | O_TRUNC;
        }

        printf("Opening %s for %s\n", filename, reading?"reading":"writing");
        file->fd = open(filename, flags, 0644);
        if (file->fd < 0)
        {
                perror("Couldn't open file");
                return -1;
        }

        if (reading)
        {
                /* Try mmap */
                flags = PROT_READ;
                file->start_buf = mmap(0, file->size, PROT_READ, MAP_SHARED, file->fd, 0);
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

static int file_read_next_buffer(file_info *file, char **buf, signed int toread, unsigned int *count)
{
        ssize_t bytesread, bytestoread;

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

        if (toread < 0)
                bytestoread = file->bufsize;
        else
                bytestoread = (ssize_t)toread;

        printf("Reading %i bytes.\n", bytestoread);

        /* TODO implement common offset/size checking to ensure getting next buffer makes sense */

        /* See if we can do it the easy way */
        if (file->start_buf)
        {
                printf("File is mapped, easy.\n");
                printf("start_buf %p bufsize %i\n", file->start_buf, bytestoread);
                *buf = file->start_buf + file->offset;
                printf("Returning %p\n", *buf);
                if ((file->size - file->offset) > bytestoread)
                        bytesread = bytestoread;
                else
                        bytesread = (file->size - file->offset);
        }
        else
        {
                printf("File isn't mapped, less easy.\n");

                /* For speed, assume we're the only ones using this file pointer. */
                bytesread = read(file->fd, file->temp_buf, bytestoread);
                if (0 == bytesread)
                {
                        printf("Got 0 for bytesread, EOF.\n");
                        if (file->offset < file->size)
                        {
                                printf("File offset is %lld, size is %lld - unexpected EOF.\n", file->offset, file->size);
                        }
                }
                else if (bytesread != bytestoread)
                {
                        printf("Bytes read %i doesn't match bufsize %i\n", bytesread, bytestoread);
                }

        }

        file->offset += bytesread;
        *count = bytesread;

        return 0;
}

static int file_write_next_buffer(file_info *file, const char *buf, unsigned int count)
{
        int retval = 0;
        ssize_t written;

        assert(file);
        assert(buf);

        if (file->fd < 0)
        {
                printf("Bad parameter, file not open\n");
                return -1;
        }

        written = write(file->fd, buf, count);
        if (0 == written)
        {
                printf("Wrote 0 bytes, expected to write %i. Disk full?\n", count);
                retval = -1;
        }
        else if (written != count)
        {
                printf("Warning - expected to write %d bytes, only wrote %d. Disk becoming full?\n", written, count);
                retval = -2;
        }

        return retval;
}

/**** Main functions */

static int write_context_hash(const char *basename, const char *extension, CRYPT_CONTEXT *context)
{
        int buflen, fd, hash_length, rc;
        char *name;
        char hash[CRYPT_MAX_HASHSIZE];

        assert(basename);
        assert(extension);
        assert(context);

        rc = cryptGetAttributeString(*context, CRYPT_CTXINFO_HASHVALUE, hash, &hash_length);
        if (cryptStatusError(rc))
        {
                printf("Couldn't get hash from context - rc %i\n", rc);
                return rc;
        }

        buflen = strlen(basename) + strlen(extension) + 2;
        name = malloc(buflen);
        if (NULL == name)
        {
                printf("Couldn't allocate %i byte name buffer.\n", buflen);
                return -1;
        }

        snprintf(name, buflen, "%s.%s", basename, extension);

        fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0622);
        if (fd < 0)
        {
                printf("Unable to open file '%s' for writing.\n", name);
        }
        else
        {
                rc = write(fd, hash, hash_length);
                if (rc != hash_length)
                {
                        printf("Expected to write %d bytes, only wrote %d.\n", hash_length, rc);
                        perror("Why");
                }
                else
                {
                        printf("Hash written okay.\n");
                }

                close(fd);
        }

        free(name);
        return 0;
}

int split_file(CRYPT_CONTEXT *md5, CRYPT_CONTEXT *sha1, const char *infilename, const char *outfilenamebase, unsigned long long int chunksize)
{
        char *buf;
        char *outfilename;
        file_info infile;
        file_info outfile;
        int rc, outfilenamelen;
        signed int to_read;
        unsigned int bytecount;
        unsigned long long int bytesleftinchunk;
        unsigned int chunkcount = 0;

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

        /* Filename, ., make wild assumption of no more than 100000 chunks. */
        outfilenamelen = strlen(infilename) + 1 + 6 + 1;
        outfilename = (char *)malloc(outfilenamelen);
        if (NULL == outfilename)
        {
                printf("Couldn't allocate memory for output filenames\n");
                close_file(&infile);
                return -1;
        }

        if (snprintf(outfilename, outfilenamelen, "%s%i", outfilenamebase, chunkcount) == outfilenamelen)
        {
                printf("Output filename too long (hit buffer size of %i bytes\n", outfilenamelen);
                printf("Stopping now to avoid data issues.\n");
                close_file(&infile);
                free(outfilename);
                return -1;
        }

        printf("Writing to file %s\n", outfilename);
        if (open_file(outfilename, &outfile, false, true, 7500))
        {
                printf("Couldn't open output file for writing\n");
                close_file(&infile);
                return -1;
        }

        rc = 0;
        bytesleftinchunk = chunksize;
        printf("Comparing %i to %lld\n", infile.bufsize, bytesleftinchunk);
        if (infile.bufsize > bytesleftinchunk)
                to_read = bytesleftinchunk;
        else
                to_read = -1;
        printf("Reading %i bytes.\n", to_read);
        
        file_read_next_buffer(&infile, &buf, to_read, &bytecount);
        while ((bytecount > 0) && (rc == 0))
        {
                printf("Got buffer %p, bytecount %i\n", buf, bytecount);
                rc = file_write_next_buffer(&outfile, buf, bytecount);
                if (rc != 0)
                {
                        printf("Problem writing: ");
                        switch (rc)
                        {
                                case -1: printf("disk may be full.\n");
                                         break;
                                default:
                                case -2: printf("unknown write error.\n");
                                         break;
                        }
                }

                rc = cryptEncrypt(*md5, buf, bytecount);
                if (cryptStatusError(rc))
                {
                        printf("Couldn't update MD5 hash context - rc %i\n", rc);
                        break;
                }
                rc = cryptEncrypt(*sha1, buf, bytecount);
                if (cryptStatusError(rc))
                {
                        printf("Couldn't update SHA-1 hash context - rc %i\n", rc);
                        break;
                }

                bytesleftinchunk -= bytecount;
                if (0 == bytesleftinchunk)
                {
                        printf("Finished chunk %i.\n", chunkcount);
                        close_file(&outfile);
                        cryptEncrypt(*md5, buf, 0);
                        cryptEncrypt(*sha1, buf, 0);
                        write_context_hash(outfilename, "md5", md5);
                        write_context_hash(outfilename, "sha1", sha1);

                        bytesleftinchunk = chunksize;
                        chunkcount++;

                        if (snprintf(outfilename, outfilenamelen, "%s%i", outfilenamebase, chunkcount) == outfilenamelen)
                        {
                                printf("Output filename too long (hit buffer size of %i bytes\n", outfilenamelen);
                                printf("Stopping now to avoid data issues.\n");
                                break;
                        }
                        printf("Writing to file %s\n", outfilename);
                        if (open_file(outfilename, &outfile, false, true, 7500))
                        {
                                printf("Couldn't open output file for writing\n");
                                break;
                        }
                }
                printf("Comparing %i to %lld\n", infile.bufsize, bytesleftinchunk);
                if (infile.bufsize > bytesleftinchunk)
                        to_read = bytesleftinchunk;
                else
                        to_read = -1;
                printf("Reading %i bytes.\n", to_read);

                file_read_next_buffer(&infile, &buf, to_read, &bytecount);
        } while ((bytecount > 0) && (rc == 0));

        free(outfilename);
        close_file(&infile);
        close_file(&outfile);
        write_context_hash(outfilename, "md5", md5);
        write_context_hash(outfilename, "sha1", sha1);

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

        rc = cryptEnd();
        if (cryptStatusError(rc))
        {
                printf("Couldn't end cryptlib - rc %i\n", rc);
                return rc;
        }

        return rc;
}
