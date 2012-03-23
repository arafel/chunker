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

typedef struct checkpoint_s
{
        char *filename;
        unsigned long long int chunksize;
        unsigned int last_chunk;
} checkpoint;

/**** Statics */

static int g_debug_max_chunk = 0;
static bool g_hit_debug_max_chunk = false;

static char g_tmpfile_template[300];
static bool g_tmpfile_template_created = false;

/**** Prototypes */

static int filesize(const char *filename, unsigned long long int *filesize);
static CRYPT_CONTEXT *init_context(CRYPT_ALGO_TYPE algorithm);
static int free_context(CRYPT_CONTEXT *context);
static int reset_context(CRYPT_CONTEXT *context);

static int create_checkpoint(checkpoint **cp, const char *filename, unsigned long long int chunksize);
static int delete_checkpoint(checkpoint *cp);
static int destroy_checkpoint(checkpoint *cp);
static int restore_checkpoint(checkpoint **cp, bool *checkpoint_found, const char *filename, unsigned int *chunk, unsigned long long int chunksize);
static int update_checkpoint(checkpoint *cp, unsigned int chunk);

/**** Worker functions */

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
        }
        else
        {
                printf("File isn't mapped, less easy.\n");
                printf("Reading %i bytes.\n", bytestoread);

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

static int create_checkpoint(checkpoint **cp, const char *filename, unsigned long long int chunksize)
{
        checkpoint *tmp_cp;

        tmp_cp = malloc(sizeof(checkpoint));

        tmp_cp->filename = strdup(filename);
        tmp_cp->chunksize = chunksize;
        tmp_cp->last_chunk = 0;
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

static int restore_checkpoint(checkpoint **cp, bool *checkpoint_found, const char *filename, unsigned int *chunk, unsigned long long int chunksize)
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
                        /* TODO fix me */
#if 0
                        if (strcmp(tmp_cp.filename, filename) != 0)
                        {
                                printf("Filenames differ, invalid checkpoint\n");
                                unlink(filename);
                        }
                        else 
#endif
                                if (tmp_cp.chunksize != chunksize)
                        {
                                printf("Chunksizes differ, invalid checkpoint\n");
                                unlink(filename);
                        }
                        else
                        {
                                *checkpoint_found = true;

                                new_cp = malloc(sizeof(checkpoint));
                                new_cp->filename = strdup(filename);
                                new_cp->chunksize = tmp_cp.chunksize;
                                new_cp->last_chunk = tmp_cp.last_chunk;
                                *chunk = new_cp->last_chunk;
                                *cp = new_cp;
                                printf("Found apparently-valid checkpoint, chunksize %lld, chunk %i\n", new_cp->chunksize, new_cp->last_chunk);
                        }
                }
        }

        return 0;
}

static int delete_checkpoint(checkpoint *cp)
{
        int ret;

        assert(cp);
        assert(cp->filename);
        
        if (!g_hit_debug_max_chunk)
        {
                ret = unlink(cp->filename);
                ret = 0;
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
                
                printf("Setting up tmpfile template\n");
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
                cp->last_chunk = chunk;

                if (write(fd, cp, sizeof(checkpoint)) != sizeof(checkpoint))
                {
                        perror("Couldn't write complete checkpoint\n");
                        ret = -1;
                }
                else
                {
                        printf("Updated checkpoint with chunk %i\n", chunk);
                }

                if (fsync(fd))
                {
                        /* So what do we do about it? */
                        perror("fsync() returned error on checkpoint file");
                }

                close(fd);

                printf("Renaming temporary file '%s' to '%s'\n", local_template, cp->filename);
                if (rename(local_template, cp->filename))
                {
                        printf("Renaming temporary file '%s' to '%s'\n", local_template, cp->filename);
                        perror("Couldn't rename temporary file");
                        ret = -1;
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
                rc = write(fd, hash, hash_length);
                if (rc != hash_length)
                {
                        printf("Expected to write %d bytes, only wrote %d.\n", hash_length, rc);
                        perror("Why");
                }

                close(fd);
        }

        free(name);
        return 0;
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

        if (open_file(infilename, &infile, true, false, 5000))
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

        if (restore_checkpoint(&cp, &checkpoint_found, checkpointname, &starting_chunk, chunksize))
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
                printf("Checkpoint found: %s\n", checkpoint_found?"yes":"no");
                if (checkpoint_found)
                {
                        /* checkpoint records last successful chunk, so we start 
                         * on the next one */
                        starting_chunk++;
                        chunkcount = starting_chunk;
                        printf("\tRestarting at chunk %i\n", starting_chunk);
                }

                /* Temporary use of rc variable */
                rc = 0;
                while (starting_chunk > 0)
                {
                        printf("Skipping chunk %i\n", rc);
                        file_read_next_buffer(&infile, &buf, to_read, &bytecount);
                        rc++;
                        starting_chunk--;
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
                printf("Output filename too long (hit buffer size of %i bytes\n", outfilenamelen);
                printf("Stopping now to avoid data issues.\n");
                free(checkpointname);
                close_file(&infile);
                free(outfilename);
                return -1;
        }

        printf("Writing to file %s\n", outfilename);
        if (open_file(outfilename, &outfile, false, true, 7500))
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
                if (0 == bytesleftinchunk)
                {
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
                                printf("Debug: stopping after chunk %i\n", chunkcount);
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
                        printf("Writing to file %s\n", outfilename);
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

        close_file(&infile);
        close_file(&outfile);
        if (end_chunk(outfilename, md5, sha1))
        {
                printf("Error ending chunk\n");
                retval = -1;
        }

        delete_checkpoint(cp);
        destroy_checkpoint(cp);

        free(checkpointname);
        free(outfilename);

        return retval;
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
        sha1 = init_context(CRYPT_ALGO_SHA1);
        if (!sha1)
                printf("Couldn't create SHA1 context\n");

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
