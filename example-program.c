#include <stdio.h>
#include <unistd.h> // For sleep function

// sample struct for pointer argument test
typedef struct {
    int a;
    float b;
} SampleStruct;

// function for different argument test
void func_int(int x0, long x1, float x2, double x3, char x4, short x5, unsigned int x6) {
    if (x0 < 0) {
        x0 = -x0;
    }
    if (x1 > 1000) {
        x1 = x1 / 2;
    } else {
        x1 = x1 * 2;
    }
    if (x2 < 0.0f) {
        x2 = 0.0f;
    } else if (x2 > 100.0f) {
        x2 = 100.0f;
    }
    x3 = x3 + 1.0;
    x4 = x4 + 1;
    x5 = x5 * 2;
    x6 = x6 - 1;
    return;
}

// function for pointer argument test
void func_ptr(void* p0, int* p1, int** p2, SampleStruct* p3) {
    if (p0) {
        // Do something with p0
        volatile char c = *((char*)p0); // volatile to prevent optimization
        (void)c;
    }
    if (p1) {
        *p1 = *p1 + 10;
    }
    if (p2 && *p2) {
        **p2 = **p2 + 20;
    }
    if (p3) {
        p3->a = p3->a * 2;
        p3->b = p3->b + 3.14f;
    }
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