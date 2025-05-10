MEMORY {
  kernel_space (rwx) : ORIGIN = 0x0, LENGTH = 2 * 1024 * 1024
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

  .text._halt 0x10000 : {
    *(.text._halt)
  }
}
