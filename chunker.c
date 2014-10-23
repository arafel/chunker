/**
 * Copyright 2012, Paul Walker.
 *
 * This file is part of chunker.
 *
 * chunker is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * chunker is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * chunker.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/**** Includes */

/* System */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

/* Libraries */
#include "cryptlib.h"

/**** Constants and macros */

#define FILE_BUFFER_SIZE        (10000)
#define META_VERSION            (0);

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

typedef struct checkpoint_s
{
        char *filename;
        unsigned long long int chunksize;
        unsigned int last_chunk;
} checkpoint;

typedef struct split_metadata_s
{
        unsigned int version;
        unsigned long long int filesize;
        unsigned long long int chunksize;
        unsigned int chunkcount;
} split_metadata;

/**** Statics */

static int g_debug_max_chunk = 0;
static bool g_hit_debug_max_chunk = false;

static bool g_debug_hash = false;
static bool g_debug_chunk_size_check = false;
static bool g_debug_file_ops = false;
static bool g_debug_checkpoint = false;

static char g_tmpfile_template[300];
static bool g_tmpfile_template_created = false;

static bool g_verbose = false;
static bool g_verify_mode = false;

/**** Prototypes */

static int filesize(const char *filename, unsigned long long int *filesize);
static CRYPT_CONTEXT *init_context(CRYPT_ALGO_TYPE algorithm);
static int free_context(CRYPT_CONTEXT *context);
static int reset_context(CRYPT_CONTEXT *context);

static int create_checkpoint(checkpoint **cp, const char *filename, unsigned long long int chunksize);
static int delete_checkpoint(checkpoint *cp);
static int destroy_checkpoint(checkpoint *cp);
static int restore_checkpoint(const char *outfilenamebase, checkpoint **cp, bool *checkpoint_found, 
                                const char *filename, unsigned int *chunk, unsigned long long int chunksize);
static int update_checkpoint(checkpoint *cp, unsigned int chunk);

static int read_context_hash(const char *basename, const char *extension, char *hash, int *hash_length);

/**** Worker functions */

#if 1
static void dump_buf(const char *buf, unsigned int count)
{
        char s[8 + 2 + (16 * 3) + 1];
        int i, space, index;

        if (NULL == buf)
                return;

        s[0] = '\0';
        for (i = 0; i < count; i++)
        {
                if ((i % 16) == 0)
                {
                        if (strlen(s) > 0)
                                printf("%s\n", s);
                        memset(s, 0, sizeof(s));
                        snprintf(s, sizeof(s), "%08x  ", i);
                        index = (8 + 2);
                        space = sizeof(s) - index;
                }
                snprintf(&s[index], space, "%02x ", (unsigned char)buf[i]); 
                space -= 3;
                index += 3;
        }
        if (strlen(s) > 0)
                printf("%s\n", s);
}
#endif

static int filesize(const char *filename, unsigned long long int *filesize)
{
        struct stat st;

        assert(filename);
        assert(filesize);

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
                printf("Couldn't allocate %zu bytes for context.\n", sizeof(CRYPT_CONTEXT));
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

        assert(context);

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

        assert(context);

        rc = cryptDeleteAttribute(*context, CRYPT_CTXINFO_HASHVALUE);
        if (cryptStatusError(rc))
        {
                printf("Couldn't reset context - rc %i\n", rc);
        }

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

        if (g_verbose)
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
                munmap(file->start_buf, file->size);
        }

        if (file->temp_buf)
        {
                printf("Freeing temporary buffer %p\n", file->temp_buf);
                free(file->temp_buf);
        }

        fsync(file->fd);
        close(file->fd);

        return 0;
}

static int file_read_next_buffer(file_info *file, char **buf, signed int toread, unsigned int *count)
{
        ssize_t bytesread, bytestoread;

        assert(file);
        assert(file->fd >= 0);
        assert(buf);

        if (file->offset == file->size)
        {
                if (g_debug_file_ops)
                        printf("%s - file offset %llu matches file size %llu\n", __func__, file->offset, file->size);
                *buf = NULL;
                *count = 0;
                return 0;
        }

        if (toread < 0)
                bytestoread = file->bufsize;
        else
                bytestoread = (ssize_t)toread;

        if ((file->size - file->offset) > bytestoread)
                bytesread = bytestoread;
        else
                bytesread = (file->size - file->offset);

        /* See if we can do it the easy way */
        if (file->start_buf)
        {
                *buf = file->start_buf + file->offset;
                if (g_debug_file_ops)
                {
                        printf("\t%s - file %p - adjusted offset by %zu bytes (start %p buf now %p)\n", __func__,
                                        file, bytestoread, file->start_buf, *buf);
                }
        }
        else
        {
                printf("File isn't mapped, less easy.\n");
                printf("Reading %zu bytes.\n", bytestoread);

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
                        printf("Bytes read %zu doesn't match bufsize %zu\n", bytesread, bytestoread);
                }
                else if (g_debug_file_ops)
                {
                        printf("\t%s - file %p - read %zu bytes (target %zu)\n",  __func__, file, bytesread, bytestoread);
                }
        }

        file->offset += bytesread;
        if (g_debug_file_ops)
                printf("\t%s - file->offset now %lld\n", __func__, file->offset);
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

        if (g_debug_file_ops)
        {
                printf("\t%s - file %p - writing %i bytes from %p\n", __func__, file, count, buf);
        }

        written = write(file->fd, buf, count);
        if (0 == written)
        {
                printf("Wrote 0 bytes, expected to write %i. Disk full?\n", count);
                retval = -1;
        }
        else if (written != count)
        {
                printf("Warning - expected to write %zu bytes, only wrote %d. Disk becoming full?\n", written, count);
                retval = -2;
        }

        return retval;
}

/**** Main functions */

static int check_chunk(const char *outfilenamebase, int chunk, unsigned long long int chunksize, bool check_size)
{
        int outfilenamelen, rc;
        int problem = 0;
        unsigned long long int size;
        unsigned int bytecount;
        char *outfilename;
        char *buf;
        file_info file;
        char calc_sha1[CRYPT_MAX_HASHSIZE], calc_md5[CRYPT_MAX_HASHSIZE];
        char read_sha1[CRYPT_MAX_HASHSIZE], read_md5[CRYPT_MAX_HASHSIZE];
        int sha1_length, md5_length;
        int read_sha1_length, read_md5_length;

        if (g_verbose)
        {
                printf("Using output filename base '%s'\n", outfilenamebase);
        }

        outfilenamelen = strlen(outfilenamebase) + 1 + 6 + 1;
        outfilename = (char *)malloc(outfilenamelen);
        if (NULL == outfilename)
        {
                printf("Couldn't allocate memory for output filenames\n");
                problem = 1;
        }
        else if (snprintf(outfilename, outfilenamelen, "%s%i", outfilenamebase, chunk) == outfilenamelen)
        {
                printf("Output filename too long (hit buffer size of %i bytes)\n", outfilenamelen);
                problem = 1;
        }

        if ((0 == problem) && check_size)
        {
                if (filesize(outfilename, &size))
                {
                        printf("Couldn't get filesize of input file '%s'\n", outfilename);
                        problem = 1;
                }
                else
                {
                        if (size != chunksize)
                        {
                                printf("File size %lld doesn't match given chunksize %lld\n", size, chunksize);
                                problem = 1;
                        }
                        else if (g_verbose)
                        {
                                printf("File size %lld matches chunksize %lld\n", size, chunksize);
                        }
                }
        }

        if (problem)
                goto check_chunk_exit;

        if (g_verbose)
                printf("Opening %s for verifying\n", outfilename);
        if (open_file(outfilename, &file, true, false, FILE_BUFFER_SIZE))
        {
                printf("Couldn't open %s for reading\n", outfilename);
                problem = 1;
        }
        else
        {
                CRYPT_CONTEXT *md5, *sha1;

                md5 = init_context(CRYPT_ALGO_MD5);
                if (!md5)
                {
                        printf("Couldn't create MD5 context\n");
                        problem = 1;
                }
                sha1 = init_context(CRYPT_ALGO_SHA1);
                if (!sha1)
                {
                        free_context(md5);
                        printf("Couldn't create SHA1 context\n");
                        problem = 1;
                }

                if (problem)
                {
                        close_file(&file);
                        goto check_chunk_exit;
                }

                reset_context(md5);
                reset_context(sha1);

                file_read_next_buffer(&file, &buf, -1, &bytecount);
                while (bytecount && size)
                {
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

                        size -= bytecount;
                        if (size)
                                file_read_next_buffer(&file, &buf, -1, &bytecount);
                }
                close_file(&file);

                rc = cryptEncrypt(*md5, buf, 0);
                if (cryptStatusError(rc))
                {
                        printf("Error finalising MD5 - rc %i\n", rc);
                        free_context(md5);
                        problem = 1;
                }
                rc = cryptEncrypt(*sha1, buf, 0);
                if (cryptStatusError(rc))
                {
                        printf("Error finalising SHA1 - rc %i\n", rc);
                        free_context(sha1);
                        problem = 1;
                }

                if (problem)
                        goto check_chunk_exit;

                rc = cryptGetAttributeString(*sha1, CRYPT_CTXINFO_HASHVALUE, calc_sha1, &sha1_length);
                if (cryptStatusError(rc))
                {
                        printf("Couldn't get hash from SHA1 context - rc %i\n", rc);
                        problem = 1;
                }
                else if (g_debug_hash)
                {
                        printf("Calculated SHA1 hash, %i bytes\n", sha1_length);
                }

                rc = cryptGetAttributeString(*md5, CRYPT_CTXINFO_HASHVALUE, calc_md5, &md5_length);
                if (cryptStatusError(rc))
                {
                        printf("Couldn't get hash from MD5 context - rc %i\n", rc);
                        problem = 1;
                }
                else if (g_debug_hash)
                {
                        printf("Calculated MD5 hash, %i bytes\n", md5_length);
                }

                free_context(md5);
                free_context(sha1);

                if (problem)
                        goto check_chunk_exit;

                if (read_context_hash(outfilename, "sha1", read_sha1, &read_sha1_length))
                {
                        printf("Couldn't read SHA1 hash\n");
                        problem = 1;
                }
                else if (read_context_hash(outfilename, "md5", read_md5, &read_md5_length))
                {
                        printf("Couldn't read MD5 hash\n");
                        problem = 1;
                }
                else if (read_sha1_length != sha1_length)
                {
                        printf("Mismatch - read SHA1 length %i calculated %i\n", read_sha1_length, sha1_length);
                        problem = 1;
                }
                else if (read_md5_length != md5_length)
                {
                        printf("Mismatch - read MD5 length %i calculated %i\n", read_md5_length, md5_length);
                        problem = 1;
                }
                else
                {
                        if (g_debug_hash)
                        {
                                printf("SHA1:\n");
                                printf("Just calculated: ");
                                dump_buf(calc_sha1, sha1_length);
                                printf("    Stored hash: ");
                                dump_buf(read_sha1, read_sha1_length);
                                printf("MD5:\n");
                                printf("Just calculated: ");
                                dump_buf(calc_md5, md5_length);
                                printf("    Stored hash: ");
                                dump_buf(read_md5, read_md5_length);
                        }

                        if (memcmp(read_sha1, calc_sha1, sha1_length) || memcmp(read_md5, calc_md5, md5_length))
                        {
                                printf("Hash check failed.\n");
                                problem = 1;
                        }
                }

                if (problem)
                        goto check_chunk_exit;
        }

check_chunk_exit:
        return problem;
}

static int create_checkpoint(checkpoint **cp, const char *filename, unsigned long long int chunksize)
{
        checkpoint *tmp_cp;

        tmp_cp = malloc(sizeof(checkpoint));

        tmp_cp->filename = strdup(filename);
        tmp_cp->chunksize = chunksize;
        tmp_cp->last_chunk = 0;
        if (g_debug_checkpoint)
                printf("Created checkpoint - filename %s, chunksize %lld\n", filename, chunksize);

        *cp = tmp_cp;

        return 0;
}

static int destroy_checkpoint(checkpoint *cp)
{
        assert(cp);
        assert(cp->filename);

        free(cp->filename);
        cp->filename = NULL;

        free(cp);
        cp = NULL;

        return 0;
}

static int restore_checkpoint(const char *outfilenamebase, checkpoint **cp, bool *checkpoint_found, 
                                const char *filename, unsigned int *chunk, unsigned long long int chunksize)
{
        checkpoint tmp_cp;
        checkpoint *new_cp;
        int fd, ret = 0;

        assert(cp);
        assert(chunk);
        assert(checkpoint_found);

        *chunk = 0;
        *cp = NULL;
        *checkpoint_found = false;

        fd = open(filename, O_RDONLY, 0666);
        if (fd < 0)
        {
                /* Valid condition, don't error */
                ret = 0;
        }
        else 
        {
                if (read(fd, &tmp_cp, sizeof(checkpoint)) != sizeof(checkpoint))
                {
                        /* Couldn't read complete checkpoint, deleting */
                        unlink(filename);
                        ret = 0;
                }
                else
                {
                        close(fd);

                        if (tmp_cp.chunksize != chunksize)
                        {
                                printf("Chunksizes differ, invalid checkpoint\n");
                                unlink(filename);
                        }
                        else
                        {
                                *checkpoint_found = true;

                                if (check_chunk(outfilenamebase, tmp_cp.last_chunk, chunksize, true))
                                {
                                        printf("Last written chunk doesn't seem valid, discarding it.\n");
                                        if (tmp_cp.last_chunk > 0)
                                        {
                                                tmp_cp.last_chunk -= 1;
                                        }
                                        else
                                        {
                                                printf("Doesn't leave us with any valid chunks, ignoring checkpoint.\n");
                                                *checkpoint_found = false;
                                        }
                                }

                                if (*checkpoint_found)
                                {
                                        new_cp = malloc(sizeof(checkpoint));
                                        new_cp->filename = strdup(filename);
                                        new_cp->chunksize = tmp_cp.chunksize;
                                        new_cp->last_chunk = tmp_cp.last_chunk;
                                        printf("Found apparently-valid checkpoint, chunksize %lld, chunk %i\n", 
                                                        new_cp->chunksize, new_cp->last_chunk);

                                        *chunk = new_cp->last_chunk;
                                        *cp = new_cp;
                                }
                        }
                }
        }

        return ret;
}

static int delete_checkpoint(checkpoint *cp)
{
        int ret;

        assert(cp);
        assert(cp->filename);
        
        ret = 0;
        if (!g_hit_debug_max_chunk)
        {
                ret = unlink(cp->filename);
                if (ret != 0)
                {
                        printf("Deleting '%s'\n", cp->filename);
                        perror("Couldn't delete");
                }
        }

        return ret;
}

static int update_checkpoint(checkpoint *cp, unsigned int chunk)
{
        char *local_template;
        int fd, ret = 0;

        assert(cp);

        if (false == g_tmpfile_template_created)
        {
                char *tmpdir;
                
                /* printf("Setting up tmpfile template\n"); */
                memset(g_tmpfile_template, 0, sizeof(g_tmpfile_template));

                tmpdir = getenv("TMPDIR");
                if (NULL == tmpdir)
                {
                        snprintf(g_tmpfile_template, sizeof(g_tmpfile_template) - 1, "/tmp/chunker.XXXXXX");
                }
                else
                {
                        snprintf(g_tmpfile_template, sizeof(g_tmpfile_template) - 1, "%s/chunker.XXXXXX", tmpdir);
                }
                g_tmpfile_template_created = true;
        }

        local_template = strdup(g_tmpfile_template);
        if (NULL == local_template)
        {
                printf("Couldn't allocate memory for local tmpfile template\n");
                return -1;
        }

        fd = mkstemp(local_template);
        if (fd < 0)
        {
                printf("Using template %s\n", local_template);
                perror("update_checkpoint: couldn't open tempfile");
                ret = -1;
        }
        else 
        {
                if (g_debug_checkpoint)
                        printf("Updating checkpoint, tempfile %s\n", local_template);

                cp->last_chunk = chunk;

                if (write(fd, cp, sizeof(checkpoint)) != sizeof(checkpoint))
                {
                        perror("Couldn't write complete checkpoint\n");
                        ret = -1;
                }
                else if (g_verbose || g_debug_checkpoint)
                {
                        printf("Updated checkpoint with chunk %i\n", chunk);
                }

                if (fsync(fd))
                {
                        /* So what do we do about it? */
                        perror("fsync() returned error on checkpoint file");
                }

                close(fd);

                if (rename(local_template, cp->filename))
                {
                        printf("Renaming temporary file '%s' to '%s'\n", local_template, cp->filename);
                        perror("Couldn't rename temporary file");
                        ret = -1;
                }
                else if (g_debug_checkpoint)
                {
                        printf("Renamed %s to %s okay\n", local_template, cp->filename);
                }
        }

        free(local_template);

        return ret;
}

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

        if (g_debug_hash)
        {
                printf("Just calculated %s hash for %s:\n", extension, basename);
                dump_buf(hash, hash_length);
        }

        assert(strlen(basename) > 0);

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
                if (g_debug_hash)
                {
                        printf("Writing %i bytes of hash to %s\n", hash_length, name);
                }

                rc = write(fd, hash, hash_length);
                if (rc != hash_length)
                {
                        printf("Expected to write %d bytes, only wrote %d.\n", hash_length, rc);
                        perror("Why");
                }

                fsync(fd);
                close(fd);
        }

        free(name);
        return 0;
}

/* Incoming hash pointer must point to a buffer of length CRYPT_MAX_HASHSIZE */
static int read_context_hash(const char *basename, const char *extension, char *hash, int *hash_length)
{
        int buflen, fd, rc;
        char *name;

        assert(basename);
        assert(extension);
        assert(hash);

        assert(strlen(basename) > 0);

        buflen = strlen(basename) + strlen(extension) + 2;
        name = malloc(buflen);
        if (NULL == name)
        {
                printf("Couldn't allocate %i byte name buffer.\n", buflen);
                return -1;
        }

        snprintf(name, buflen, "%s.%s", basename, extension);

        if (g_debug_hash)
        {
                printf("Trying to read hash from %s\n", name);
        }

        fd = open(name, O_RDONLY, 0622);
        if (fd < 0)
        {
                printf("Unable to open file '%s' for reading.\n", name);
                *hash_length = 0;
                rc = -1;
        }
        else
        {
                rc = read(fd, hash, CRYPT_MAX_HASHSIZE);
                *hash_length = rc;
                if (g_debug_hash)
                {
                        printf("\tRead %i bytes for %s hash\n", *hash_length, extension);
                }
                rc = 0;

                close(fd);
        }

        free(name);
        return rc;
}

static int end_chunk(const char *outfilename, CRYPT_CONTEXT *md5, CRYPT_CONTEXT *sha1)
{                        
        int rc;
        char buf[1];

        rc = cryptEncrypt(*md5, buf, 0);
        if (cryptStatusError(rc))
        {
                printf("Error finalising MD5 - rc %i\n", rc);
                return rc;
        }
        rc = cryptEncrypt(*sha1, buf, 0);
        if (cryptStatusError(rc))
        {
                printf("Error finalising SHA1 - rc %i\n", rc);
                return rc;
        }

        rc = write_context_hash(outfilename, "md5", md5);
        if (rc)
                return rc;
        rc = write_context_hash(outfilename, "sha1", sha1);
        if (rc)
                return rc;
        rc = reset_context(md5);
        if (rc)
                return rc;
        rc = reset_context(sha1);
        if (rc)
                return rc;

        return 0;
}

static int read_meta(const char *outfilebasename, unsigned long long int *filesize, unsigned long long int *chunksize, unsigned int *chunkcount, split_metadata *meta)
{
        int fd, count, problem;
        split_metadata tmp_meta;
        char *name;

        problem = 0;

        name = malloc(strlen(outfilebasename) + strlen("meta") + 1);
        if (NULL == name)
        {
                printf("Couldn't allocate working memory\n");
                problem = 1;
        }
        else
        {
                snprintf(name, strlen(outfilebasename) + strlen("meta") + 1, "%smeta", outfilebasename);
                fd = open(name, O_RDONLY, 0622);
                if (fd < 0)
                {
                        printf("Unable to open '%s' for reading\n", name);
                        problem = 1;
                }
                else
                {
                        count = read(fd, &tmp_meta, sizeof(split_metadata));
                        if (count != sizeof(split_metadata))
                        {
                                printf("Error reading metadata - expected to read %zu, read %i\n", sizeof(split_metadata), count);
                                perror("Couldn't read");
                                problem = 1;
                        }
                        else if (g_verbose)
                        {
                                printf("Successfully read metadata\n");
                                printf("\tMetadata: filesize %lld; chunksize %lld; chunk count %i\n",
                                                tmp_meta.filesize, tmp_meta.chunksize, tmp_meta.chunkcount);
                        }

                        if (meta)
                                memcpy(meta, &tmp_meta, sizeof(split_metadata));
                        if (NULL != filesize)
                                *filesize = tmp_meta.filesize;
                        if (NULL != chunksize)
                                *chunksize = tmp_meta.chunksize;
                        if (NULL != chunkcount)
                                *chunkcount = tmp_meta.chunkcount;
                }

                free(name);
        }

        return problem;
}

static int write_meta(const char *outfilebasename, unsigned long long int filesize, unsigned long long int chunksize, unsigned int chunkcount, split_metadata *meta)
{
        int fd, count, problem;
        split_metadata our_meta;
        char *name;

        problem = 0;

        /* If they don't specify one, build it locally */
        if (NULL == meta)
        {
                if (g_verbose)
                {
                        printf("User didn't specify meta struct, building our own.\n");
                }
                meta = &our_meta;
                meta->version = META_VERSION;
                meta->filesize = filesize;
                meta->chunksize = chunksize;
                meta->chunkcount = chunkcount;
        }
        else if (g_verbose)
        {
                printf("Using user-supplied meta-data struct\n");
        }

        name = malloc(strlen(outfilebasename) + strlen("meta") + 1);
        if (NULL == name)
        {
                printf("Couldn't allocate working memory\n");
                problem = 1;
        }
        else
        {
                snprintf(name, strlen(outfilebasename) + strlen("meta") + 1, "%smeta", outfilebasename);
                fd = open(name, O_CREAT | O_WRONLY | O_TRUNC, 0622);
                if (fd < 0)
                {
                        printf("unable to open '%s' for writing\n", name);
                        problem = 1;
                }
                else
                {
                        count = write(fd, meta, sizeof(split_metadata));
                        if (count != sizeof(split_metadata))
                        {
                                printf("Error writing metadata - expected to write %zu, wrote %i\n", sizeof(split_metadata), count);
                                perror("Couldn't write");
                                problem = 1;
                        }
                        else if (g_verbose)
                        {
                                printf("Successfully wrote metadata\n");
                        }
                }

                free(name);
        }

        return problem;
}

int split_file(CRYPT_CONTEXT *md5, CRYPT_CONTEXT *sha1, const char *infilename, const char *outfilenamebase, unsigned long long int chunksize)
{
        char *buf;
        char *outfilename;
        char *checkpointname;
        file_info infile;
        file_info outfile;
        int rc, retval = 0;
        int outfilenamelen, checkpointnamelen;
        bool checkpoint_found;
        bool debug_end_chunk_now = false;
        signed int to_read;
        unsigned int bytecount;
        unsigned long long int bytesleftinchunk;
        unsigned int chunkcount = 0, starting_chunk = 0;
        checkpoint *cp;

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

        if (open_file(infilename, &infile, true, false, FILE_BUFFER_SIZE))
        {
                printf("Couldn't open input file for reading\n");
                return -1;
        }
        
        printf("'%s' is %llu bytes in length; chunk length is %lld.\n", infilename, infile.size, chunksize);

        bytesleftinchunk = chunksize;
        if (infile.bufsize > bytesleftinchunk)
                to_read = bytesleftinchunk;
        else
                to_read = -1;

        checkpointnamelen = strlen(outfilenamebase) + strlen("checkpoint") + 1;
        checkpointname = (char *)malloc(checkpointnamelen);
        if (NULL == checkpointname)
        {
                printf("Couldn't allocate memory for checkpoint filename\n");
                close_file(&infile);
                return -1;
        }
        snprintf(checkpointname, checkpointnamelen, "%scheckpoint", outfilenamebase);
        printf("Using checkpoint file %s\n", checkpointname);

        if (restore_checkpoint(outfilenamebase, &cp, &checkpoint_found, checkpointname, &starting_chunk, chunksize))
        {
                printf("Error trying to restore checkpoint\n");
                close_file(&infile);
                return -1;
        }

        if (!checkpoint_found)
        {
                printf("No outstanding checkpoint, starting from scratch.\n");

                if (create_checkpoint(&cp, checkpointname, chunksize))
                {
                        printf("Couldn't create checkpoint %s\n", checkpointname);
                        close_file(&infile);
                        return -1;
                }
        }
        else
        {
                unsigned long long int bytes_to_skip;

                printf("Checkpoint found: %s\n", checkpoint_found?"yes":"no");
                if (checkpoint_found)
                {
                        /* checkpoint records the last successful chunk, so we
                         * start on the next one */
                        printf("Checkpoint says last successful chunk was %i\n", starting_chunk);
                        chunkcount = starting_chunk + 1;
                        printf("\tRestarting at chunk %i\n", chunkcount);
                }

                /* Use the +1 variable; the chunk count is zero-based */
                bytes_to_skip = chunkcount * chunksize;
                rc = 0;
                while (bytes_to_skip > 0)
                {
                        if (infile.bufsize > bytes_to_skip)
                                to_read = bytes_to_skip;
                        else
                                to_read = infile.bufsize;

                        file_read_next_buffer(&infile, &buf, to_read, &bytecount);
                        rc++;
                        bytes_to_skip -= bytecount;
                }
        }

        /* Filename, ., make wild assumption of no more than 100000 chunks. */
        outfilenamelen = strlen(infilename) + 1 + 6 + 1;
        outfilename = (char *)malloc(outfilenamelen);
        if (NULL == outfilename)
        {
                printf("Couldn't allocate memory for output filenames\n");
                free(checkpointname);
                close_file(&infile);
                return -1;
        }

        if (snprintf(outfilename, outfilenamelen, "%s%i", outfilenamebase, chunkcount) == outfilenamelen)
        {
                printf("Output filename too long (hit buffer size of %i bytes)\n", outfilenamelen);
                printf("Stopping now to avoid data issues.\n");
                free(checkpointname);
                close_file(&infile);
                free(outfilename);
                return -1;
        }

        if (open_file(outfilename, &outfile, false, true, FILE_BUFFER_SIZE))
        {
                printf("Couldn't open output file for writing\n");
                free(checkpointname);
                close_file(&infile);
                return -1;
        }

        file_read_next_buffer(&infile, &buf, to_read, &bytecount);

        rc = 0;
        while ((bytecount > 0) && (rc == 0))
        {
                if (g_debug_chunk_size_check && (g_debug_max_chunk == (chunkcount + 1)))
                {
                        if (bytecount != outfile.bufsize)
                        {
                                printf("Seems to be the last buffer, changing bytecount from %i\n", bytecount);
                                bytecount /= 2;
                                printf("\tCount now %i\n", bytecount);
                                debug_end_chunk_now = true;
                        }
                        else
                        {
                                printf("Bytecount %i matches bufsize %i, assuming not last buffer\n", 
                                                bytecount, outfile.bufsize);
                        }
                }

                rc = file_write_next_buffer(&outfile, buf, bytecount);
                if (rc != 0)
                {
                        printf("Got buffer %p, bytecount %i\n", buf, bytecount);
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
                if ((0 == bytesleftinchunk) || (debug_end_chunk_now))
                {
                        if (g_verbose)
                                printf("Finished chunk %i.\n", chunkcount);
                        close_file(&outfile);

                        if (end_chunk(outfilename, md5, sha1))
                        {
                                printf("Error ending chunk\n");
                                break;
                        }

                        update_checkpoint(cp, chunkcount);

                        bytesleftinchunk = chunksize;
                        chunkcount++;
                        if ((g_debug_max_chunk > 0) && (chunkcount >= g_debug_max_chunk))
                        {
                                printf("Debug: stopping at chunk %i\n", chunkcount);
                                rc = -1;
                                g_hit_debug_max_chunk = true;
                                break;
                        }

                        if (snprintf(outfilename, outfilenamelen, "%s%i", outfilenamebase, chunkcount) == outfilenamelen)
                        {
                                printf("Output filename too long (hit buffer size of %i bytes)\n", outfilenamelen);
                                printf("Stopping now to avoid data issues.\n");
                                break;
                        }
                        if (open_file(outfilename, &outfile, false, true, 7500))
                        {
                                printf("Couldn't open output file for writing\n");
                                break;
                        }
                }
                if (infile.bufsize > bytesleftinchunk)
                        to_read = bytesleftinchunk;
                else
                        to_read = -1;

                file_read_next_buffer(&infile, &buf, to_read, &bytecount);
        } while ((bytecount > 0) && (rc == 0));

        if ((chunksize != bytesleftinchunk) && (!debug_end_chunk_now))
        {
                if (end_chunk(outfilename, md5, sha1))
                {
                        printf("Error ending chunk\n");
                        retval = -1;
                }
        }
        else if (g_verbose)
        {
                printf("Ended on chunk boundary (%s)\n", g_hit_debug_max_chunk?"by debug":"by chance");
        }

        delete_checkpoint(cp);
        destroy_checkpoint(cp);

        free(checkpointname);
        free(outfilename);

        write_meta(outfilenamebase, infile.size, chunksize, chunkcount, NULL);

        close_file(&infile);
        close_file(&outfile);

        return retval;
}

int verify_file(const char *filenamebase, unsigned long long int chunksize)
{
        char *filename;
        int problem = 0;
        int filenamelen;
        unsigned long long int total_size;
        unsigned int chunkcount;
        struct stat st;
        split_metadata meta;
        bool have_metadata = true;

        if (!filenamebase)
        {
                printf("Invalid output filename %p\n", filenamebase);
                return -1;
        }

        printf("Verifying split of '%s'\n", filenamebase);

        /* Filename, ., make wild assumption of no more than 100000 chunks. */
        filenamelen = strlen(filenamebase) + 1 + 6 + 1;
        filename = (char *)malloc(filenamelen);
        if (NULL == filename)
        {
                printf("Couldn't allocate memory for filenames\n");
                return -1;
        }

        if (read_meta(filenamebase, NULL, NULL, NULL, &meta))
        {
                printf("Couldn't read metadata; doesn't look good, trying anyway.\n");
                have_metadata = false;
        }

        total_size = 0;
        chunkcount = 0;
        do
        {
                if (snprintf(filename, filenamelen, "%s%i", filenamebase, chunkcount) == filenamelen)
                {
                        printf("Filename too long (hit buffer size of %i bytes)\n", filenamelen);
                        printf("Stopping now to avoid data issues.\n");
                        problem = 1;
                        break;
                }
                if (stat(filename, &st))
                {
                        if (have_metadata)
                        {
                                printf("File '%s' not found; should be %i chunks.\n", filename, meta.chunkcount);
                                problem = 1;
                        }
                        else
                                printf("File '%s' not found, assuming end of split.\n", filename);
                        break;
                }
                else if (have_metadata)
                {
                        /* We know how big the chunks should be, check it */
                        if (meta.chunksize != st.st_size)
                        {
                                if (chunkcount != meta.chunkcount)
                                {
                                        printf("Chunksize %lld doesn't match filesize %lld\n", meta.chunksize, (unsigned long long int)st.st_size);
                                        printf("Chunk count is %i (expecting %i), doesn't look right.\n", chunkcount, meta.chunkcount);
                                }
                                else if (g_verbose)
                                {
                                        printf("Chunksize %lld doesn't match filesize %lld\n", meta.chunksize, (unsigned long long int)st.st_size);
                                        printf("Chunk count is %i (expecting %i), accepting it.\n", chunkcount, meta.chunkcount);
                                }
                        }
                }

                if (check_chunk(filenamebase, chunkcount, 0, false))
                {
                        printf("Error checking chunk %i\n", chunkcount);
                        problem = 1;
                }
                else
                {
                        total_size += st.st_size;
                        if (g_verbose)
                                printf("Now checked %lld bytes\n", total_size);
                }

                chunkcount++;
                if (have_metadata)
                {
                        if (chunkcount > meta.chunkcount)
                        {
                                if (g_verbose)
                                {
                                        printf("Finished all chunks\n");
                                        printf("Total of all chunks: %lld bytes; expected %lld\n", total_size, meta.filesize);
                                }
                                if (total_size != meta.filesize)
                                {
                                        printf("Wrong.\n");
                                        problem = 1;
                                }
                                break;
                        }
                }
        } while (1);

        free(filename);

        if (problem)
        {
                printf("Verify failed\n");
        }
        else
        {
                printf("Verify passed.\n");
        }

        return problem;
}
 
int main(int argc, char *argv[])
{
        int rc = 0;
        int index, c;
        CRYPT_CONTEXT *md5, *sha1;
        unsigned long int chunksize = (10 * 1024);
        char *infile, *basename;
        bool bail = false;

        while (((c = getopt(argc, argv, "cs:m:v")) != -1) && (false == bail))
        {
                switch (c)
                {
                        case 'c':
                                g_verify_mode = true;
                                printf("Setting verify mode to true\n");
                                break;
                        case 's':
                                chunksize = atoi(optarg);
                                if (0 == chunksize)
                                {
                                        printf("Bad chunksize '%s'\n", optarg);
                                        bail = true;
                                }
                                break;
                        case 'm':
                                g_debug_max_chunk = atoi(optarg);
                                if ((0 == g_debug_max_chunk) && (!strcmp(optarg, "0")))
                                        printf("Warning - '%s' doesn't seem to be a number.\n", optarg);
                                else
                                        printf("Debug mode - stopping after %i chunks.\n", g_debug_max_chunk);
                                break;
                        case 'v':
                                g_verbose = true;
                                printf("Setting verbose to true.\n");
                                break;
                        case '?':
                                if (optopt == 's')
                                        fprintf(stderr, "option -%c requires an argument.\n", optopt);
                                else if (isprint(optopt))
                                        fprintf(stderr, "Unknown option '-%c'\n", optopt);
                                else
                                        fprintf(stderr, "Unknown option character '\\x%x'.\n", optopt);
                                return 1;
                                break;
                        default:
                                fprintf(stderr, "Shouldn't ever reach this point.\n");
                                abort();
                }
        }
        if (g_debug_chunk_size_check && (g_debug_max_chunk == 0))
        {
                printf("To debug chunk size checking you need debug_max_chunk as well.\n");
                printf("Disabling chunk size checking.\n");
                g_debug_chunk_size_check = false;
        }

        if (bail)
                return -1;

        infile = NULL;
        basename = NULL;
        for (index = optind; index < argc; index++)
        {
                if ((NULL == infile) && (!g_verify_mode))
                        infile = argv[index];
                else if (NULL == basename)
                        basename = argv[index];
                else
                {
                        fprintf(stderr, "Too many arguments! (%s)\n", argv[index]);
                        break;
                }
        }

        if (((NULL == infile) && !g_verify_mode) || (NULL == basename))
        {
                fprintf(stderr, "Not enough arguments - need to supply filename and basename for chunks.\n");
                fprintf(stderr, "infile %p, verify %i, basename %p\n", infile, g_verify_mode, basename);
                return -1;
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
        sha1 = init_context(CRYPT_ALGO_SHA1);
        if (!sha1)
                printf("Couldn't create SHA1 context\n");

        if (g_verify_mode)
                verify_file(basename, chunksize);
        else
                split_file(md5, sha1, infile, basename, chunksize);

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
