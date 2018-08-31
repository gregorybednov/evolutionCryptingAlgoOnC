#include <stdio.h>
#include "crypting_core.h"
#include <string.h>
#include <time.h>
#include <stdlib.h>

int main(){
    srand((int) time(0));
    char s[]="Testing message for you and this program";
    size_t y;
    load_dictionary("eng2.dict",&y);
    new_random_alphabet("new.balph",6,y,0);/*мутации выставлены в ноль, можно изменять.*/
    load_alphabet("new.balph");
    size_t t;
    unsigned char* msg=cipher(s,&t);
    load_alphabet("new.balph");/*перезагрузка алфавита допустима (как и словаря)*/
    load_message_to_module(t,msg);
    /*add_edit(0,'A');*/ /*пример добавления пользовательской правки (некоторые коррективы оказываются критичными для всей дальнейшей расшифровки)*/
    free(msg);/*обязательно удалить сообщение, созданное cipher(), как только оно перестанет быть нужным (например, будет отослано)*/
    char *res=uncipher(1);
    printf("%s\n",res);
    free(res);/*аналогично со строками, созданными uncipher(), которые перестают быть нужными*/
    end();/*обязательно отключить систему перед выходом из нее*/
    return 0;
}
