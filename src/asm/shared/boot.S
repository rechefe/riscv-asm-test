        .section .text._start

_start: 
        la sp, _STACK_PTR
	call gcd
	j . // Halt - used in emulation to know we need to stop



