#include <stdio.h>
#include "crypting_core.h"
#include <string.h>
#include <time.h>
#include <stdlib.h>

int main(){
    srand((int) time(NULL));
    size_t y;
    char s[]="TESTING MESSAGE FOR YOU AND THIS PROGRAM";
    load_dictionary("eng2.dict",&y);
    new_random_alphabet("new.balph",1,y,0);/*number of mutations is zero, but you can change it*/
    load_alphabet("new.balph");
    size_t t;
    unsigned char* msg=cipher(s,&t);
    load_alphabet("new.balph");/*reloading alphabet is avaible as reloading dictionary*/
    load_message_to_module(t,msg);
    /*add_edit(0,'A');*/ /*example of adding user edit (some edits can be critical for uncrypting)*/
    free(msg);/*you MUST free all memory allocated from "creating" functions: cipher() and uncipher().*/
    char *res=uncipher(1);

    printf("%s\n\n",res);
    free(res);/*(see previous comment about freeing memory)*/
    stop();/*call stop() when you want to 'kill' everything in module; it's REQUIRED for
    secure and no-error stopping program*/

    printf("Press ENTER to exit...\n");
    getchar();

    return 0;
}
