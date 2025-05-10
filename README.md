# Setup

Build the Dockerfile with:

```sh
docker build -t riscv-ex .
```

To run on windows:

```sh
docker run --rm -it -p 8800:8800 -v "${PWD}\workspace:/workspace" -w /workspace riscv-ex
```

then open `localhost:8800`.