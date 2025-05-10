        .section .text
        .global insertion_sort

// Insertion Sort -----------
// does insertion sort on an array
// sorting is done on signed integers
// Inputs - 
// int * arr (a0)
// int len (a1)
// Inner variables -
// t0 stores i
// t1 stores j
// t2 stores tmp
// t3, etc. does not have a name in the C function  
insertion_sort:
        // int i = 1;
        li t0, 1

loop_1:
        // while (i < len) == !(i >= len)
        bge t0, a1, loop_1_exit

        // tmp = arr[i]
        slli t3, t0, 2 // t3 = t0 * 4 (i * sizeof(int) - without using mul)
        add t3, t3, a0
        lw t2, 0(t3)

        mv t1, t0 // j = i

loop_2:
        // while ((j > 0) && (arr[j-1] > tmp))
        // arr[j-1]
        addi t4, t1, -1
        slli t4, t4, 2
        add t4, t4, a0
        lw t5, 0(t4)

        // (arr[j-1] > tmp) == !(tmp >= arr[j-1])
        bge t2, t5, loop_2_exit

        // (j > 0) == !(0 >= j)
        bge x0, t1, loop_2_exit

        // arr[j] = arr[j-1]
        sw t5, 4(t4)

        // j--
        addi t1, t1, -1

        j loop_2

loop_2_exit:
        // arr[j] = tmp
        sw t2, 4(t4)

        // i++
        addi t0, t0, 1

        j loop_1

loop_1_exit:
        ret
