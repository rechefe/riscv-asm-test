import os
import sys
import pytest
from unicorn import *
from conftest import *
from unicorn.riscv_const import *

# memory address where emulation starts
CODE_ADDRESS = 0

# Memory address where emulations
RETURN_ADDRESS = 0x10000

@pytest.mark.parametrize("test_input", [(1, 2, 3), (5, 6, 11)])
def test_emulation(mu: Uc, test_input: tuple):
    mu.reg_write(UC_RISCV_REG_A0, test_input[0])
    mu.reg_write(UC_RISCV_REG_A1, test_input[1])
    mu.emu_start(CODE_ADDRESS, RETURN_ADDRESS)
    assert mu.reg_read(UC_RISCV_REG_A0) == test_input[2]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__] + sys.argv[1:]))
