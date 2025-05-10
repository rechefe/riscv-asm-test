	.file	"sort.c"
	.option nopic
	.attribute arch, "rv32i2p1_m2p0_a2p1_c2p0"
	.attribute unaligned_access, 0
	.attribute stack_align, 16
	.text
	.align	1
	.globl	insertion_sort
	.type	insertion_sort, @function
insertion_sort:
	addi	a3,a0,4
	li	a4,1
.L2:
	blt	a4,a1,.L6
	ret
.L6:
	lw	a6,0(a3)
	mv	a2,a3
	mv	a5,a4
.L3:
	lw	a7,-4(a2)
	bgt	a7,a6,.L5
.L4:
	slli	a5,a5,2
	add	a5,a0,a5
	sw	a6,0(a5)
	addi	a4,a4,1
	addi	a3,a3,4
	j	.L2
.L5:
	sw	a7,0(a2)
	addi	a5,a5,-1
	addi	a2,a2,-4
	bne	a5,zero,.L3
	li	a5,0
	j	.L4
	.size	insertion_sort, .-insertion_sort
	.ident	"GCC: (xPack GNU RISC-V Embedded GCC x86_64) 14.2.0"
	.section	.note.GNU-stack,"",@progbits
