#include <stdio.h>
#include <unistd.h>

int main() {

    while (1) {
        sleep(1); // Sleep for a second to avoid busy waiting
    }

    return 0;
}

