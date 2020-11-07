#include "zc_io.h"

// The zc_file struct is analogous to the FILE struct that you get from fopen.
struct zc_file {
  // Insert the fields you need here.
};

/**************
 * Exercise 1 *
 **************/

zc_file *zc_open(const char *path) {
  // To implement
  return NULL;
}

int zc_close(zc_file *file) {
  // To implement
  return -1;
}

const char *zc_read_start(zc_file *file, size_t *size) {
  // To implement
  return NULL;
}

void zc_read_end(zc_file *file) {
  // To implement
}

/**************
 * Exercise 2 *
 **************/

char *zc_write_start(zc_file *file, size_t size) {
  // To implement
  return NULL;
}

void zc_write_end(zc_file *file) {
  // To implement
}

/**************
 * Exercise 3 *
 **************/

off_t zc_lseek(zc_file *file, long offset, int whence) {
  // To implement
  return -1;
}

/**************
 * Exercise 5 *
 **************/

int zc_copyfile(const char *source, const char *dest) {
  // To implement
  return -1;
}
