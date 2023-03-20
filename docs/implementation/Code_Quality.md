# Code Quality

## Linter

To run the linter, enable it by setting the `CMAKE_RUN_CLANG_TIDY` flag:
```
cmake ../ -D CMAKE_RUN_CLANG_TIDY=ON
```

Following `make` calls will be run with the linter.

## Format

For source code formatting, a clang-format configuration file is provided.
The following code snipped can be used to apply the format on all files.
```
find ./src -iname *.h -o -iname *.c | xargs clang-format-14 -i
```