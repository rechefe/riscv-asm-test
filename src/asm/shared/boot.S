        .section .text._start
_start: 
        la sp, _STACK_PTR
	call gcd
	j _halt

        .section .text._halt
// Halt - used in emulation to know we need to stop
_halt:
        j .
