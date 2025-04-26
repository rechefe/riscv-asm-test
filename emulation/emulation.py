from unicorn import *
from unicorn.riscv_const import *
from pathlib import Path


# memory address where emulation starts
ADDRESS = 0

RETURN_ADDRESS = 0x10_0000


if __name__ == "__main__":
    print("Emulate RISC-V code")
    
    binary = Path('add.bin')
    code = binary.read_bytes()
    
    try:
        # Initialize emulator in RISC-V mode
        mu = Uc(UC_ARCH_RISCV, UC_MODE_32)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, code)

        # initialize machine registers
        mu.reg_write(UC_RISCV_REG_SP, 0x1_0000)
        mu.reg_write(UC_RISCV_REG_A0, 13)
        mu.reg_write(UC_RISCV_REG_A1, 942)
        mu.reg_write(UC_RISCV_REG_RA, RETURN_ADDRESS)

        # emulate code in infinite time & unlimited instructions
        mu.emu_start(ADDRESS, RETURN_ADDRESS)
        
        print(f"Emulation done - output is {mu.reg_read(UC_RISCV_REG_A0)=}")

    except UcError as e:
        print("ERROR: %s" % e)
