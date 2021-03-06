/*BEGIN_LEGAL 
Intel Open Source License 

Copyright (c) 2002-2017 Intel Corporation. All rights reserved.
 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
#include "utils.h"
#if defined(PIN_CRT) && defined(TARGET_LINUX)
# include "pincrt_file_utils.h"
#endif

char* append3(const char* s1, const char* s2, const char* s3)
{
    int n = 1;
    char* p = 0;
    if (s1)
        n += strlen(s1);
    if (s2)
        n += strlen(s2);
    if (s3)
        n += strlen(s3);
    p = (char*) malloc(sizeof(char) * n);
    if (s1)
        strcpy(p, s1);
    if (s2)
        strcat(p, s2);
    if (s3)
        strcat(p, s3);
    return p;
}

void check_retval(int retval, const char* str)
{
    if (retval != 0)
    {
        perror(str);
        exit(1);
    }
}

/*!
 * @brief Checks if the file exist and readable.
 * @param fn The file path
 * @return True if exist, readable and executable
 */
unsigned int check_file_exists(const char* fn)
{
    unsigned int okay = 1;
    if (access(fn, R_OK ) == -1)
        okay = 0;
    return okay;
}

/*!
 * @brief Checks for file properties and prints an error message is requirements are not met.
 * @param fn The file path
 */
void check_file(const char* fn)
{
    unsigned int okay = check_file_exists(fn);
    if (!okay)
    {
        fprintf(stderr, "Error. File doesn't exist (%s)\n\n",fn );
        exit(1);
    }
}

/*!
 * Check if the file path is a directory
 * @param fn The file path
 * @return 1 if the file path is not a directory
 */
unsigned int check_not_directory(const char* fn)
{
#if defined(PIN_CRT) && defined(TARGET_LINUX)
    return is_directory_file(fn);
#else
    unsigned int okay = 1;
    struct stat st;
    if (stat(fn, &st) == -1 || !S_ISREG(st.st_mode))
        okay = 0;
    return okay;
#endif
}

/*!
 * Checks that a file exists in the directory and that it is not a directory.
 * @param fn The file path to be checked
 * @param dir The directory path to be checked in
 * @param buff A buffer to create the complete path
 * @return 1 if file exist and not a directory
 */
unsigned int check_file_in_dir(const char* fn, const char *dir, char *buff)
{
    buff = append3(dir, "/", fn);
    return check_file_exists(buff) && check_not_directory(buff);
}

/*!
 * Searches for the given executable in the directories list at the PATH environment variable,
 * and returns the directory it was found in.
 * @param exename The executable path
 * @return The directory it was found in, or null if not found.
 */
char *search_in_path(const char *exename)
{
    const char dirsepchar = ':';

    char *syspath = strdup(getenv("PATH"));
    char *buff = (char*) malloc(strlen(syspath) + strlen(exename) + 2);
    char *dir = syspath;
    char *dirsep = strchr(dir, dirsepchar);
    char *path = 0;
    while (dirsep)
    {
        *dirsep = 0;
        if (check_file_in_dir(exename, dir, buff))
        {
            path = strdup(dir);
            free(syspath);
            free(buff);
            return path;
        }
        dir = dirsep + 1;
        dirsep = strchr(dir, dirsepchar);
    }
    if (check_file_in_dir(exename, dir, buff))
    {
        path = strdup(dir);
    }
    free(syspath);
    free(buff);
    return path;
}

/*!
 * Finds the base path (containing directory) of the given executable.
 * @param filename The file path
 * @return The base path
 */
char* find_base_path(char* filename)
{
    char* x;
    char* path = strdup(filename);
    x = strrchr(path, '/');
    if (x)
    {
        *x = 0;
    }
    else
    {
        x = search_in_path(filename);
        if (x)
        {
            free(path);
            return x;
        }
    }
    return path;
}
