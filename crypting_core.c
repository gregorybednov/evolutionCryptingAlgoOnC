#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypting_core.h"
#define GROUPS_HASH 32

struct _2ll_node{
	struct _2ll_node *prev;
	struct _2ll_node *next;
	char val;
	size_t intval;
};

struct edit{
	struct edit *next;
	size_t pos;
	char read_as;
};

size_t LENGTH_OF_ALPHABET=0;
size_t LENGTH_OF_SYMBOL=0;

unsigned char *alphabet;
unsigned char *reserved_alphabet;
char *fileName;
int MUTATIONS;
char *revdict;

struct _2ll_node *dict[GROUPS_HASH];
struct edit *edits;

unsigned char *message;
size_t msg_length=0;

void randmutations(){
	for (int i=0;i<MUTATIONS;i++){
		size_t randQ=rand()%(LENGTH_OF_ALPHABET*LENGTH_OF_SYMBOL);
		unsigned char randX=rand()%(sizeof(unsigned char)*8);
		alphabet[randQ]^=(unsigned char) (1<<(randX));
	}
}

size_t theSamestLiter(unsigned char *symbol){
	unsigned int *whatsthebest=calloc(LENGTH_OF_ALPHABET,sizeof(unsigned int));
	if (whatsthebest==NULL){return -1;}
	for (size_t q=0;q<LENGTH_OF_ALPHABET;q++){
		for (size_t x=0;x<(LENGTH_OF_SYMBOL);x++){
			unsigned char m=1;
			for (unsigned char x0=0;x0<8*sizeof(unsigned char);x0++){
				if 	((symbol[x]&m)==((alphabet[q*LENGTH_OF_SYMBOL+x])&m)){
					whatsthebest[q]++;
				}
				m<<=1;
			}
		}
	}
	unsigned int* bestBeg=whatsthebest;
	unsigned int* biggest=bestBeg;
	unsigned int* bestEnd=whatsthebest+LENGTH_OF_ALPHABET;
	for (whatsthebest=bestBeg;whatsthebest<bestEnd;whatsthebest++){
		if ((*biggest)<(*whatsthebest)){
			biggest=whatsthebest;
		}
	}
	whatsthebest=bestBeg;
	size_t result=(biggest-bestBeg);
	free(whatsthebest);
	return result;
}

unsigned char *Cipher(size_t *length,char *str){
	if (str==NULL||length==NULL){
		printf("\tstr OR length IS NULL!\n");
		return NULL;
	}
	size_t strlenV=strlen(str);
	size_t lng=strlenV*(LENGTH_OF_SYMBOL)+(size_t)(rand()%(LENGTH_OF_SYMBOL));
	unsigned char *result=malloc(sizeof(unsigned char)*lng);
	if (result==NULL){
		printf("\tresult MALLOC NULL!\n");
		return NULL;
	}
	for (size_t q=0;q<strlenV;q++){
		for (size_t i=0;i<(LENGTH_OF_SYMBOL);i++){
			struct _2ll_node *s=dict[str[q]%GROUPS_HASH];
			struct _2ll_node *s0;
			if (s!=NULL){
				s0=s;
				while ((s!=NULL)&&(s0->val!=str[q])){
					s0=s;
					s=s->next;
				}
				if (s0->val!=str[q]){
					free(result);
					printf("\tDOESN'T EXIST, NULL\n");
					*length=0;
					return NULL;
				}
			} else {
				*length=0;
				printf("\tDOESN'T EXIST, NULL\n");
				free(result);
				return NULL;
			}
			memcpy(result+q*(LENGTH_OF_SYMBOL)+i,(alphabet+s0->intval+i),LENGTH_OF_SYMBOL*sizeof(unsigned char));
		}
		randmutations();
	}
	char* resBegin=result;
	char* resEnd=result+lng;
	for (result=result+strlenV*LENGTH_OF_ALPHABET;result<resEnd;result++){
		*result=(unsigned char) rand();
	}
	*length=sizeof(unsigned char)*lng;
	return resBegin;
}

int load_message_to_module(size_t length,unsigned char *byteMessage){
	free(message);
	msg_length=length/(LENGTH_OF_SYMBOL)*(LENGTH_OF_SYMBOL);
	printf("\tmessage malloc started\n",msg_length*sizeof(char));
	message=(unsigned char*)malloc(msg_length*sizeof(char));//<<----- STOPPING CAN BE HERE!!!!!!!!!!
	printf("\tmessage malloc completed...\n");
	if (message==NULL){
		printf("\tmessage MALLOC ERROR\n");
		return -1;
	}
	memcpy(message,byteMessage,msg_length*sizeof(char));
	return 0;
}

char *Uncipher(int cancel_previous_unciphering){
	printf("\tWas I here?\n");
	if (message==NULL){
		return NULL;
	}
	printf("\tWas I here? msg_length=%u\n",msg_length);

	char *result=malloc(sizeof(char)*msg_length);
	printf("\tWas I here? msg_length=%u\n",msg_length);
	if (result==NULL){
		return NULL;
	}
	printf("\tMemCpy started\n");
	if (cancel_previous_unciphering){
		memcpy(alphabet,reserved_alphabet,sizeof(unsigned char)*LENGTH_OF_ALPHABET*LENGTH_OF_SYMBOL);
	} else {
		memcpy(reserved_alphabet,alphabet,sizeof(unsigned char)*LENGTH_OF_ALPHABET*LENGTH_OF_SYMBOL);
	}
	printf("\tMemCpy completed\n");
	for (size_t i=0;i<msg_length;i++){
		struct edit currEdit=*edits;
		while ((currEdit.next!=NULL)&&(currEdit.pos!=i)){
			currEdit=*(currEdit.next);
		}
		size_t num;
		if (currEdit.pos!=i){
			struct _2ll_node currDict=*(dict[currEdit.read_as%GROUPS_HASH]);
			while ((currEdit.read_as!=currDict.val)){
					currDict=*(currDict.next);
			}
			result[i]=currDict.val;
			num=currDict.intval;
		} else {
			num=theSamestLiter(message+i*LENGTH_OF_SYMBOL);
			result[i]=revdict[num];
		}
		memcpy(alphabet+num*LENGTH_OF_SYMBOL,message+i*LENGTH_OF_SYMBOL,LENGTH_OF_SYMBOL);
	}
	result[msg_length+1]='\0';
	return result;
}

///0, если успешно
///-1, если файл не был открыт на запись
int save_alphabet(){
	FILE *fp;
	if ((fp = fopen(fileName, "wb")) == NULL){
		return -1;
	}
	int ints[2]={LENGTH_OF_ALPHABET,LENGTH_OF_SYMBOL};
	fwrite(ints, sizeof(int),2,fp);
  	fwrite(alphabet, sizeof(unsigned char), LENGTH_OF_SYMBOL*LENGTH_OF_ALPHABET*sizeof(unsigned char), fp); // записать в файл содержимое буфера
	fclose(fp);
	return 0;
}

///0, если успешно
///-1, если файл по каким-то причинам не был открыт
///-2, если в файле неверное значение длины алфавита (файл с ошибкой)
///-3, если в файле неверное значение длины символа (файл с ошибкой)
int load_alphabet(char *name){
	FILE *fp;
	if ((fp = fopen(name, "rb")) == NULL){
		return -1;
	}
	size_t ints[2];
	fread(&ints,sizeof(size_t),2,fp);
	if (ints[0]<=0){
			fclose(fp);
			return -1;
	}
	if ((ints[1]>0)){
		LENGTH_OF_ALPHABET=ints[0];
		free(alphabet);
		free(reserved_alphabet);
		LENGTH_OF_SYMBOL=ints[1];
		alphabet=malloc(LENGTH_OF_ALPHABET*LENGTH_OF_SYMBOL*sizeof(unsigned char));
		reserved_alphabet=malloc(LENGTH_OF_ALPHABET*LENGTH_OF_SYMBOL*sizeof(unsigned char));
		if (alphabet==NULL || reserved_alphabet==NULL){
			fclose(fp);
			return -1;
		}
		printf("res_alph=%p\n",reserved_alphabet);
		fread(alphabet,sizeof(unsigned char),LENGTH_OF_ALPHABET*LENGTH_OF_SYMBOL,fp);
		memcpy(reserved_alphabet,alphabet,LENGTH_OF_ALPHABET*LENGTH_OF_SYMBOL*sizeof(unsigned char));
		fclose(fp);
		return 0;
	} else {
		fclose(fp);
		return -1;
	}
}

int load_dict(char *name){
	FILE *fp;
	fp = fopen(name, "rb");
	if (fp != NULL){
		for (size_t i=0;i<GROUPS_HASH;i++){
			struct _2ll_node *s=dict[i];
			if (s!=NULL){
				while (s->next!=NULL){
					struct _2ll_node *m=s->next;
					free(s);
					s=m;
			}
			}
			dict[i]=NULL;
		}
		free(revdict);
		size_t ints[1];
		fread(&ints,sizeof(size_t),1,fp);
		revdict=malloc(sizeof(char)*ints[0]);
		char c;
		for (size_t i=0;i<ints[0];i++){
			c=getc(fp);
			revdict[i]=c;
			struct _2ll_node *s=dict[c%GROUPS_HASH];
			struct _2ll_node *s0;
			unsigned char flag=1;
			if (s==NULL){
				dict[c%GROUPS_HASH]=malloc(sizeof(struct _2ll_node));
				dict[c%GROUPS_HASH]->prev=NULL;
				dict[c%GROUPS_HASH]->next=NULL;
				dict[c%GROUPS_HASH]->val=c;
				dict[c%GROUPS_HASH]->intval=i;
			} else {
				while ((s!=NULL)&&(flag)){
					flag=((s->val)!=c);
					s0=s;
					s=s->next;
				}
				if (s==NULL){
					s=malloc(sizeof(struct _2ll_node));
					if (s==NULL){fclose(fp);return -1;}
					s->prev=s0;
					s0->next=s;
					s->next=NULL;
					s->val=c;
					s->intval=i;
				} else {
					return -1;
				}
			}
		}

		fclose(fp);
		/*for (int i=0;i<GROUPS_HASH;i++){
			printf("\n%d (%p): ",i,dict[i]);
			struct _2ll_node *s=dict[i];
			while (s!=NULL){
				printf(" (%d,%c)",s->intval,s->val);
				s=s->next;
			}
		}*/
		return (int)ints[0];
	} else {
		return -1;
	}
}


void clearEdits(){
	struct edit *s=edits;
	if (edits!=NULL){
		struct edit *v=s->next;
		while (v!=NULL){
			free(s);
			s=v;
			v=v->next;
		}
		free(s);
	}
}

void end(){
	printf("\talphabet is free? ");
	free(alphabet);
	printf("completed.\n\treserved alphabet is free? ");
	free(reserved_alphabet);//<<----- STOPPING CAN BE HERE!!!!!!!!!!!!!!!
	printf("completed.\n\t\trevdict is free? ");
	free(revdict);
	printf("completed.\n\t\tmessage is free? ");
	free(message);
	printf("\n\tcomplted.\n");
	for (size_t i=0;i<GROUPS_HASH;i++){
		struct _2ll_node *s=(dict[i]);
		printf("%u ",i);
		struct _2ll_node *s0=s;
		while (1){
			s0=s0->next;
			free(s);
			s=s0;
			if (s0!=NULL){
					s0=s0->next;
			} else {
				break;
			}
		}
		dict[i]=NULL;
	}
	free(fileName);
	clearEdits();
}

int new_random_alphabet(char *name,size_t bytelength_symbol,size_t alphabet_length){
	FILE *fp=fopen(name,"wb");
	if (fp != NULL){
		int ints[2]={alphabet_length,bytelength_symbol};
		fwrite(ints, sizeof(int),2,fp);
		unsigned char* random_alphabet=malloc(alphabet_length*bytelength_symbol*sizeof(unsigned char));
		if (random_alphabet==NULL){
			fclose(fp);
			return -1;
		}
		unsigned char* begRandAlph=random_alphabet;
		unsigned char* endRandAlph=begRandAlph+alphabet_length*bytelength_symbol;
		for (random_alphabet=begRandAlph;random_alphabet<endRandAlph;random_alphabet++){
			*random_alphabet=(unsigned char) rand();
		}
		random_alphabet=begRandAlph;
		fwrite(random_alphabet,sizeof(unsigned char),alphabet_length*bytelength_symbol,fp);
		free(random_alphabet);
		fclose(fp);
		return 0;
	} else {
		return -1;
	}
}

int addEdit(size_t pos, char should_read_as){
	struct _2ll_node s=*(dict[should_read_as%GROUPS_HASH]);
	while ((s.next!=NULL)&&(s.val!=should_read_as)){
		s=*(s.next);
	}
	if (s.val!=should_read_as){
		return -1;
	}
	struct edit *m=edits;
	if (m==NULL){
		edits=malloc(sizeof(struct edit));
		if (edits==NULL){return -1;}
		edits->next=NULL;
		edits->pos=pos;
		edits->read_as=should_read_as;
	} else {
		while ((m->next!=NULL)&&(m->pos!=pos)){
			m=m->next;
		}
		if (m->pos==pos){
			m->read_as=should_read_as;
			return 1;
		} else {
			struct edit *m0=malloc(sizeof(struct edit));
			if (m0==NULL){return -1;}
			m->next=m0;
			m0->pos=pos;
			m0->read_as=should_read_as;
		}
	}
	return 0;
}
