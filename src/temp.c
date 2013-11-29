#include <stdio.h>

int main1(){
    FILE *x = NULL;
    x = fopen("rules.txt","r");
    if(x==NULL)
        printf("Oops");
    else
        printf("Yay");

    return 0;
}
