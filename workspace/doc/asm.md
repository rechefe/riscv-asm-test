# Insertion Sort on assembly
> [!NOTE] 
> You can run the program on your own, check out the instructions at: https://github.com/rechefe/riscv-asm-test

After implementing insertion sort in RISC-V 32 bit assembly, we have had to run this on some sort of emulation or simulation (or an actual RISC-V chip if you have one in hand) to test it.

I used an emulator called `unicorn` which gives you a nice python API to control the running code.

The test is inserting the following test vectors as inputs to the assembly function:

```json
{
  "test_arrays": [
    [],
    [0],
    [1],
    [-1],
    [1, 2],
    [2, 1],
    [0, 0],
    [-1, 1],
    [-2, -1],
    [-1, -2],
    [1, 2, 3, 4, 5],
    [5, 4, 3, 2, 1],
    [3, 1, 4, 1, 5, 9, 2, 6],
    [-3, -1, -4, -1, -5, -9, -2, -6],
    [-5, 0, 5, -10, 10, -15, 15],
    [2, 2, 2, 2, 2, 2],
    [0, 0, 0, 0, 0, 0],
    [1, 0, -1, 0, 1, -1],
    [100, -100, 50, -50, 25, -25],
    [7, 3, -2, 8, 1, -5, 0, 4, -1, 9, -8, 6, 2, -3, -4, 5, -6, -7, -9, 10],
    [2147483647, -2147483648, 0],
    [2147483647, 2147483646, 2147483645],
    [-2147483648, -2147483647, -2147483646],
    [72, -35, 88, -12, 94, -81, 63, 47, -29, 10, -56, 25, 83, -97, 39, 14, -68, 51, -4, 76, 0, -42, 67, -19, 92, 33, -73, 58, -87, 21, 45, -64, 8, 97, -26, 70, -53, 17, 84, -38, -1, 61, -90, 30, 79, -15, 52, -70, 23, 96, -45, 66, 11, -78, 34, 89, -22, 75, -59, 2, 48, -83, 19, 91, -31, 64, -7, 37, -94, 27, 54, -66, 5, 98, -40, 71, -17, 82, -24, 59, -99, 42, 16, -74, 31, 87, -49, 68, -9, 38, 93, -28, 60, -85, 20, 77, -33, 49, -62, 13]
  ]
}
```

Then I wrote a simple script that drives this into an emulation:

```python
import json
import pytest
from unicorn import *
from conftest import *
from unicorn.riscv_const import *

INT_SIZE = 4
INT_MOD = 2**32
INT_MSB = 2**31


def write_array_to_buffer(mu: Uc, array: tuple, buffer: int):
    for i, val in enumerate(array):
        mu.mem_write(
            buffer + i * INT_SIZE,
            (val % INT_MOD).to_bytes(INT_SIZE, byteorder="little"),
        )


def read_array_from_buffer(mu: Uc, len: int, buffer: int) -> list:
    res = []
    for i in range(len):
        val = int.from_bytes(
            mu.mem_read(buffer + i * INT_SIZE, INT_SIZE), byteorder="little"
        )
        if val & INT_MSB:
            val -= INT_MOD
        res.append(val)
    return res


def get_vectors_from_json():
    with open("../../../test_vectors/test_arrays.json", "r") as fd:
        return json.loads(fd.read())["test_arrays"]


@pytest.mark.parametrize("test_input", get_vectors_from_json())
def test_emulation(mu: Uc, run_addresses: tuple, test_input: tuple):
    buffer = run_addresses[1] + 0x1000  # Buffer for array
    write_array_to_buffer(mu, test_input, buffer)

    mu.reg_write(UC_RISCV_REG_A0, buffer)
    mu.reg_write(UC_RISCV_REG_A1, len(test_input))
    mu.emu_start(run_addresses[0], run_addresses[1])

    res = read_array_from_buffer(mu, len(test_input), buffer)
    assert res == sorted(test_input)
```

After running it on the compiled binary of our assembly code, all the tests passed:

```
======================================================= test session starts ========================================================
platform linux -- Python 3.11.2, pytest-8.3.5, pluggy-1.5.0
rootdir: /workspace/src/asm/test
collected 24 items                                                                                                                 

test_emul.py ........................                                                                                        [100%]

======================================================== 24 passed in 0.21s ========================================================
```
