import os
import pytest
from unicorn import *
from unicorn.riscv_const import *
from pathlib import Path


# memory address where emulation starts
CODE_ADDRESS = 0

RETURN_ADDRESS = 0xC



def pytest_addoption(parser):
    parser.addoption(
        "--binary", action="store", default=f"{os.getenv('WORKSPACE')}/src/asm/program.bin"
    )


@pytest.fixture
def mu(request):
    mu = Uc(UC_ARCH_RISCV, UC_MODE_32)
    mu.mem_map(CODE_ADDRESS, 2 * 1024 * 1024)
    mu.mem_write(CODE_ADDRESS, Path(request.config.option.binary).read_bytes())
    yield mu

