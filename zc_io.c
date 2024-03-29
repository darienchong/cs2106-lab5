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
#include <semaphore.h>
#include <string.h>

#define SHARED_BY_PROCESSES 1

// The zc_file struct is analogous to the FILE struct that you get from fopen.
struct zc_file {
  bool is_debug;
  
  int fd;
  void *ptr;
  off_t len;
  off_t offset;
  
  int num_readers;

  sem_t num_readers_sem; // Controls access to the `num_readers` shared variable.
  sem_t write_lseek_sem; // If available, signals no one is writing/lseeking.
};

off_t _zc_get_file_size(int fd) {
	bool is_debug = false;

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

int _zc_mmap_prot() {
	return PROT_EXEC | PROT_READ | PROT_WRITE;
}

int _zc_mmap_flags() {
	return MAP_SHARED;
}

/**
 * Returns 0 if successful, -1 otherwise.
 */
int _zc_resize_file(zc_file *file, size_t new_size) {
	if (new_size == (size_t) file -> len) {
		return 0;
	}
	
	void *new_ptr = mremap(file -> ptr, file -> len, new_size, MREMAP_MAYMOVE);
	
	if (new_ptr == MAP_FAILED) {
		if (file -> is_debug) {
			int save_errno = errno;
			printf("[_zc_resize_file(%d)]: mremap(%p, %ld, %ld, 0) return with err no [%d].\n", getpid(), file -> ptr, file -> len, new_size, save_errno);
		}
		
		return -1;
	} else {
		if (file -> is_debug) {
			printf("[_zc_resize_file(%d)]: mremap(%p, %ld, %ld, 0) successful, new pointer is [%p].\n", getpid(), file -> ptr, file -> len, new_size, new_ptr);
		}
	}
	
	file -> len = new_size;
	int ftruncate_return_val = ftruncate(file -> fd, new_size);
	
	if (ftruncate_return_val == -1) {
		if (file -> is_debug) {
			int save_errno = errno;
			printf("[_zc_resize_file(%d)]: ftruncate(%d, %ld) returned with err no [%d].\n", getpid(), file -> fd, new_size, save_errno);
		}
		
		return -1;
	}
	
	file -> ptr = new_ptr;
	
	return 0;
}

void _zc_advance_offset(zc_file *file, off_t advance) {
	file -> offset = (file -> offset) + advance;
}

void _zc_set_offset(zc_file *file, off_t new_offset) {
	file -> offset = new_offset;
}

void _zc_acquire_num_readers_sem(zc_file *file) {
	sem_wait(&(file -> num_readers_sem));
}

void _zc_release_num_readers_sem(zc_file *file) {
	sem_post(&(file -> num_readers_sem));
}

void _zc_acquire_write_lseek_sem(zc_file *file) {
	sem_wait(&(file -> write_lseek_sem));
}

void _zc_release_write_lseek_sem(zc_file *file) {
	sem_post(&(file -> write_lseek_sem));
}

/**************
 * Exercise 1 *
 **************/

zc_file *zc_open(const char *path) {
  bool is_debug = false;
  
  zc_file *zc_file_ptr = malloc(sizeof(zc_file));
  
  int fd = open(path, O_CREAT | O_RDWR, S_IRWXU | S_IRWXG | S_IRWXO);
  
  if (fd == -1) {
  	if (is_debug) {
  		int save_errno = errno;
  		printf("[zc_open(%d)]: open(%s, O_CREAT | O_RDWR, S_IRWXU | S_IRWXG | S_IRWXO) returned with err no [%d].\n", getpid(), path, save_errno);
  	}
  	return NULL;
  }
  
  if (is_debug) {
  	printf("[zc_open(%d)]: File descriptor = [%d].\n", getpid(), fd);
  }
  
  off_t file_len = _zc_get_file_size(fd);
  
  if (is_debug) {
  	printf("[zc_open(%d)]: File length determined to be [%ld].\n", getpid(), file_len);
  }
  
  // If file_len == 0, then we know we've created a new file.
  // We need to extend it to be able to mmap() it.
  if (file_len == 0) {
  	file_len = 1;
  	ftruncate(fd, file_len);
  }
  
  if (file_len == -1) {
  	return NULL;
  }
  
  void *ptr = mmap(NULL, file_len, _zc_mmap_prot(),  _zc_mmap_flags(), fd, 0);
  
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
  
  sem_init(&(zc_file_ptr -> num_readers_sem), SHARED_BY_PROCESSES, 1);
  sem_init(&(zc_file_ptr -> write_lseek_sem), SHARED_BY_PROCESSES, 1);
  
  zc_file_ptr -> is_debug = false;
  zc_file_ptr -> fd = fd;
  zc_file_ptr -> ptr = ptr;
  zc_file_ptr -> len = file_len;
  zc_file_ptr -> offset = 0;
  
	zc_file_ptr -> num_readers = 0;
  
  return zc_file_ptr;
}

int zc_close(zc_file *file) {
	// munmap() triggers flushing to the file.
  int res = munmap(file -> ptr, file -> len);
  close(file -> fd);
  sem_destroy(&(file -> num_readers_sem));
  sem_destroy(&(file -> write_lseek_sem));
  
  if (res == -1) {
  	if (file -> is_debug) {
  		int save_errno = errno;
  		printf("[zc_close(%d)]: munmap(%p, %ld) returned with err no [%d].\n", getpid(), file -> ptr, file -> len, save_errno);
  	}
  	
  	free(file);
  	return -1;
  }
  
  free(file);
  return 0;
}

const char *zc_read_start(zc_file *file, size_t *size) { 
	_zc_acquire_num_readers_sem(file);
	file -> num_readers = (file -> num_readers) + 1;
	if (file -> num_readers == 1) {
		_zc_acquire_write_lseek_sem(file);
	}
	_zc_release_num_readers_sem(file);
	
	// Check if the offset goes beyond the end of the file.
	bool is_offset_beyond_eof = (file -> offset) > (file -> len);
	
	if (is_offset_beyond_eof) {
		// Invalid offset, set bytes read to 0 and return an invalid pointer.
		*size = 0;
		return NULL;
	}
	
  // Two cases
  // 1) We have >= *size bytes remaining
  // 2) We have < *size bytes remaining
  
  if (file -> is_debug) {
  	printf("[zc_read_start(%d)]: *size = [%ld].\n", getpid(), *size);
  	printf("[zc_read_start(%d)]: current offset = [%ld].\n", getpid(), file -> offset);
  }

  bool is_file_has_less_than_size_rem = ((size_t) ((file -> len) - (file -> offset))) < *size;
  
  const char *to_return = NULL;
  
  // 1)
  if (is_file_has_less_than_size_rem) {
  	if (file -> is_debug) {
  		printf("[zc_read_start(%d)]: File remaining size = [%ld] < [%ld] = *size.\n", getpid(), ((file -> len) - (file -> offset)), *size);
  	}
  	
  	to_return = (const char *) _zc_ptr_add_offset(file -> ptr, file -> offset);
  	*size = (file -> len) - (file -> offset);
  	_zc_set_offset(file, file -> len);
  // 2)
  } else {
  	if (file -> is_debug) {
  			printf("[zc_read_start(%d)]: File remaining size = [%ld] >= [%ld] = *size.\n", getpid(), ((file -> len) - (file -> offset)), *size);
  	}
 		
 		to_return = (const char *) _zc_ptr_add_offset(file -> ptr, file -> offset);
 		_zc_advance_offset(file, *size);
 	}
 	
 	return to_return;
}

void zc_read_end(zc_file *file) {
	_zc_acquire_num_readers_sem(file);
	file -> num_readers = (file -> num_readers) - 1;
	if (file -> num_readers == 0) {
		_zc_release_write_lseek_sem(file);
	}
	_zc_release_num_readers_sem(file);
}

/**************
 * Exercise 2 *
 **************/

char *zc_write_start(zc_file *file, size_t size) {
	_zc_acquire_write_lseek_sem(file);
	
  // Two cases
  // 1) Size requested extends beyond end of file.
  // 2) Size requested does not extend beyond end of file.
  
  size_t file_offset = file -> offset;
  size_t file_len = file -> len;
  bool is_go_past_eof = file_offset + size > file_len;
  
  if (is_go_past_eof) {
  	size_t new_file_len = file_offset + size;
  	_zc_resize_file(file, new_file_len);
  }
  
  char *to_return = _zc_ptr_add_offset(file -> ptr, file -> offset);
	_zc_advance_offset(file, size);
	
  return to_return;
}

void zc_write_end(zc_file *file) {
	// For now we just sync the entire mmap'd region
	// Look into just syncing the original region?
  msync(file -> ptr, file -> len, MS_SYNC);
  
  _zc_release_write_lseek_sem(file);
}

/**************
 * Exercise 3 *
 **************/

off_t zc_lseek(zc_file *file, long offset, int whence) {
	_zc_acquire_write_lseek_sem(file);
	
	off_t new_offset;
	
  switch (whence) {
  	case SEEK_SET:
  		new_offset = offset;
  		break;
  	case SEEK_CUR:
  		new_offset = (file -> offset) + offset;
  		break;
  	case SEEK_END:
  		new_offset = (file -> len) + offset;
  		break;
  	default:
  		new_offset = -1;
  		break;
  }
  
  // Check here if zc_lseek() would set
  // the offset to before the start of the file
  // (offset < 0). If so, do not modify the offset
  // and return (off_t) -1.
  bool is_offset_before_start_of_file = new_offset < 0;
  if (is_offset_before_start_of_file) {
  	return -1;
  }
  
  file -> offset = new_offset;
  
  _zc_release_write_lseek_sem(file);
  return new_offset;
}

/**************
 * Exercise 5 *
 **************/

int zc_copyfile(const char *source, const char *dest) {
	bool is_debug = false;
	
  zc_file *src_file = zc_open(source);
  zc_file *dest_file = zc_open(dest);
  
  if (src_file == NULL) {
  	if (is_debug) {
  		printf("[zc_copyfile(%d)]: Failed to create src_file from path [%s].\n", getpid(), source);
  	}
  	
  	return -1;
  }
  
  if (dest_file == NULL) {
  	if (is_debug) {
  		printf("[zc_copyfile(%d)]: Failed to create dest_file from path [%s].\n", getpid(), source);
  	}
  	
  	return -1;
  }
  
  int resz_file_result = _zc_resize_file(dest_file, src_file -> len);
  
  if (resz_file_result == -1) {
  	if (is_debug) {
  		printf("[zc_copyfile(%d)]: Failed to resize dest_file from [%ld] to [%ld].\n", getpid(), dest_file -> len, src_file -> len);
  	}
  	
  	return -1;
  }
  
  memcpy(dest_file -> ptr, src_file -> ptr, src_file -> len);
  
  zc_close(src_file);
  zc_close(dest_file);
  
  return 0;
}
