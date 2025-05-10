CODE_ADDRESS = DEFINED(CODE_ADDRESS) ? CODE_ADDRESS : 0x0;
HALT_ADDRESS = DEFINED(HALT_ADDRESS) ? HALT_ADDRESS : 0x100000;

MEMORY {
  kernel_space (rwx) : ORIGIN = CODE_ADDRESS, LENGTH = 2 * 1024 * 1024
}

SECTIONS {
  .text : {
    *(.text._start)
    *(.text)
  } > kernel_space

  .text.interrupt : ALIGN(4) {} 

  .data : {
    *(.data)
  } > kernel_space

  .rodata : {
    *(.rodata)
  } > kernel_space

  .bss : {
    *(.bss)
  } > kernel_space

  . = ALIGN(8);
  . = . + 4096;
  _STACK_PTR = .;

  .text._halt HALT_ADDRESS : {
    *(.text._halt)
  }
}
