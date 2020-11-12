#!/bin/sh

LD_LIBRARY_PATH=. valgrind --leak-check=full --show-leak-kinds=all ./runner "$@"
