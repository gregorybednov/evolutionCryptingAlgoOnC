// This is an independent project of an individual developer. Dear PVS-Studio, please check it.

// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include <stdio.h>
#include "crypting_core.h"
#include <string.h>
#include <time.h>
#include <stdlib.h>

int main(){
	//srand((int)time(0));
	srand(15);
	printf("0. \n");
	char s[]="It is interesting to see reactions...";
	printf("1. created=%d\n",new_random_alphabet("new.balph",3,load_dict("eng2.dict")));
	int x=load_alphabet("new.balph");
	if (x!=-1){
		printf("2. alph_status=%d\n",x);
	} else {
		return -1;
	}
	size_t t=0;
	printf("3. \n");

	unsigned char* msg=Cipher(&t,&s);
	printf("4. %d\n",load_message_to_module(t,msg));
	printf("5. \n");
	free(msg);
	printf("6. \n");
	char *res=Uncipher(1);
	printf("7. \n");
	printf("%s",Uncipher(1));
	printf("8. \n");
	free(res);
	printf("9. \n");
	end();
	printf("10. \n");
	return 0;
	/*srand(time(NULL));
	for (int i=0;i<100;i++)
	printf("%d ",(unsigned char) (1<<(rand()%(sizeof(unsigned char)*8))));
	return 0;*/
}
