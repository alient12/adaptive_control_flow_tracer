#include <stdio.h>
#include <unistd.h> // For sleep function

// sample struct for pointer argument test
typedef struct {
    int a;
    float b;
} SampleStruct;

// function for different argument test
void func_int(int x0, long x1, float x2, double x3, char x4, short x5, unsigned int x6) {
    return;
}

// function for pointer argument test
void func_ptr(void* p0, int* p1, int** p2, SampleStruct* p3) {
    return;
}


int main() {
    // Call the function to create some control flow
    func_int(-42, 100000L, 3.14f, 2.71828, 'A', 7, 123456U);
    
    // Call the pointer function
    SampleStruct ss = {10, 1.23f};
    int val = 99;
    int *pval = &val;
    void * vp = (void*)&ss;
    printf("Calling func_ptr with vp=%p, pval=%p, &pval=%p, &ss=%p\n", vp, pval, &pval, &ss);
    func_ptr(vp, pval, &pval, &ss);

    // test null pointer
    func_ptr(NULL, NULL, NULL, NULL);

    return 0;
}


// gcc -g -O0 -o example-program example-program.c
// objdump -d example-program
// ps aux | grep example-program
// sudo cat /proc/2463104/maps

// LD_PRELOAD=./cft-auto-data-test.so ./example-program