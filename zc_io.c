#include "zc_io.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>

// The zc_file struct is analogous to the FILE struct that you get from fopen.
struct zc_file {
  bool is_debug;
  
  void *ptr;
  off_t file_len;
  off_t offset;
};

/**************
 * Exercise 1 *
 **************/
off_t _zc_get_file_size(int fd) {
	bool is_debug = true;

	struct stat s;
	if (fstat(fd, &s) == -1) {
		int save_errno = errno;
		if (is_debug) {
			printf("[_zc_get_file_size(%d)]: fstat(%d) returned with err no [%d].\n", getpid(), fd, save_errno);
		}
		return -1;
	}
	
  return s.st_size;
}

void *_zc_ptr_add_offset(void* ptr, off_t offset) {
	return (void*) (((void*) ptr) + offset);
}

zc_file *zc_open(const char *path) {
  bool is_debug = true;
  
  zc_file *zc_file_ptr = malloc(sizeof(zc_file));
  
  int fd = open(path, O_CREAT | O_RDWR, S_IRWXU | S_IRWXG | S_IRWXO);
  
  if (fd == -1) {
  	if (is_debug) {
  		int save_errno = errno;
  		printf("[zc_open(%d)]: open(%s, O_CREAT | O_RDWR, S_IRWXU | S_IRWXG | S_IRWXO) returned with err no [%d].\n", getpid(), path, save_errno);
  	}
  	return NULL;
  }
  
  off_t file_len = _zc_get_file_size(fd);
  
  if (is_debug) {
  	printf("[zc_open(%d)]: File length determined to be [%ld].\n", getpid(), file_len);
  }
  
  if (file_len == -1) {
  	return NULL;
  }
  
  void *ptr = mmap(NULL, file_len, PROT_EXEC | PROT_READ | PROT_WRITE,  MAP_SHARED, fd, 0);
  
  if (is_debug) {
  	printf("[zc_open(%d)]: Mapped file to [%p].\n", getpid(), ptr);
  }
  
  if (ptr == MAP_FAILED) {
  	if (is_debug) {
  		int save_errno = errno;
  		printf("[zc_open(%d)]: mmap(NULL, %ld, PROT_EXEC | PROT_READ | PROT_WRITE,  MAP_SHARED, %d, 0) returned with err no [%d].\n", getpid(), file_len, fd, save_errno);
  	}
  	
  	return NULL;
  }
  
  close(fd);
  
  zc_file_ptr -> is_debug = true;
  zc_file_ptr -> ptr = ptr;
  zc_file_ptr -> file_len = file_len;
  zc_file_ptr -> offset = 0;
  
  return zc_file_ptr;
}

int zc_close(zc_file *file) {
	// munmap() triggers flushing to the file.
  int res = munmap(file -> ptr, file -> file_len);
  
  if (res == -1) {
  	if (file -> is_debug) {
  		int save_errno = errno;
  		printf("[zc_close(%d)]: munmap(%p, %ld) returned with err no [%d].\n", getpid(), file -> ptr, file -> file_len, save_errno);
  	}
  	
  	free(file);
  	return -1;
  }
  
  free(file);
  return 0;
}

const char *zc_read_start(zc_file *file, size_t *size) { 
  // Two cases
  // 1) We have >= *size bytes remaining
  // 2) We have < *size bytes remaining
  
  if (file -> is_debug) {
  	printf("[zc_read_start(%d)]: *size = [%ld].\n", getpid(), *size);
  }
  
  bool sanity_check = ((file -> file_len) - (file -> offset)) >= 0;
  
  if (!sanity_check) {
  	if (file -> is_debug) {
  		printf("[zc_read_start(%d)]: SANITY CHECK FAILED - file_len - offset < 0.\n", getpid());
  	}
  }

  bool is_file_has_less_than_size_rem = ((size_t) ((file -> file_len) - (file -> offset))) < *size;
  
  const char *to_return = NULL;
  
  // 1)
  if (is_file_has_less_than_size_rem) {
  	if (file -> is_debug) {
  		printf("[zc_read_start(%d)]: File remaining size = [%ld] < [%ld] = *size.\n", getpid(), ((file -> file_len) - (file -> offset)), *size);
  	}
  	
  	to_return = (const char *) _zc_ptr_add_offset(file -> ptr, file -> offset);
  	*size = (file -> file_len) - (file -> offset);
  	file -> offset = file -> file_len;
  } else {
  	// 2)
  	if (file -> is_debug) {
  			printf("[zc_read_start(%d)]: File remaining size = [%ld] >= [%ld] = *size.\n", getpid(), ((file -> file_len) - (file -> offset)), *size);
  	}
 		
 		to_return = (const char *) _zc_ptr_add_offset(file -> ptr, file -> offset);
 		file -> offset = (file -> offset) + *size;
 	}
 	
 	return to_return;
}

void zc_read_end(zc_file *file) {
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
