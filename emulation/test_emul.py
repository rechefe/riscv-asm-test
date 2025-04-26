import pytest
from conftest import mu, CODE_ADDRESS, RETURN_ADDRESS
from unicorn import *
from unicorn.riscv_const import *


@pytest.mark.parametrize("test_input", [(1, 2, 3)])
def test_emulation(mu: Uc, test_input: tuple):
    mu.reg_write(UC_RISCV_REG_A0, test_input[0])
    mu.reg_write(UC_RISCV_REG_A1, test_input[1])

    mu.emu_start(CODE_ADDRESS, RETURN_ADDRESS)

    assert mu.reg_read(UC_RISCV_REG_A0) == test_input[2]
