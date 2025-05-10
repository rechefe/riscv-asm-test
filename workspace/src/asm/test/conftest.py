import os
import pytest
from unicorn import *
from unicorn.riscv_const import *
from pathlib import Path


def pytest_addoption(parser):
    parser.addoption(
        "--binary",
        action="store",
        default=f"{os.getenv('WORKSPACE')}/src/asm/program.bin",
    )
    parser.addoption("--code-address", type=int, action="store", default=0x0)
    parser.addoption("--halt-address", type=int, action="store", default=0x10000)


@pytest.fixture()
def run_addresses(request):
    print(request.config.option.code_address, request.config.option.halt_address)
    yield request.config.option.code_address, request.config.option.halt_address


@pytest.fixture
def mu(request):
    mu = Uc(UC_ARCH_RISCV, UC_MODE_32)
    mu.mem_map(request.config.option.code_address, 2 * 1024 * 1024)
    mu.mem_write(
        request.config.option.code_address,
        Path(request.config.option.binary).read_bytes(),
    )
    yield mu
