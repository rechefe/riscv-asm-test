import os
import sys
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
