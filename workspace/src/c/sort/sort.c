#include "sort.h"

void insertion_sort(int * arr, int len) {
    int i = 1, j;
    int tmp;
    while (i < len) {
        tmp = arr[i];
        j = i;
        while ((j > 0) && (arr[j-1] > tmp)) {
            arr[j] = arr[j-1];
            j--;
        }
        arr[j] = tmp;
        i++;
    }
}
