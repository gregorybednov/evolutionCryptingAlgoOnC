/*
Complete C90 standard (provided by GCC 6.3.0 20170516)

It compiles in C99 and C11 standards too (provided by GCC 6.3.0 20170516)


!!! You should rewrite code for other rand() for more security
(use crypting-complete versions of pseudorandom number generators).

*/
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "crypting_core.h" /*only good manners in programming*/

#define DIGITS_FOR_DESCRIPTION 4
/*how many digits will be at begin of dictionary file for describing all letters in dictionary file*/

/*INTERFACE PART - GLOBAL VARIABLES AND IN-MODULE TYPES*/
/*'alphabet' vars*/
size_t LENGTH_OF_ALPHABET=0;
size_t LENGTH_OF_SYMBOL=0;
unsigned char* alphabet=NULL;
unsigned char* reserved_alphabet=NULL;
size_t MUTATIONS;

/*'dict' types and vars*/
struct dictrecord {
    int charval;
    size_t intval;
};
struct dictrecord* dict=NULL;
int* revdict=NULL;
size_t dictsize=0;

/*'edit' type and global dynamic array*/
struct editrecord {/* 'edit' keeps right (provided by reciever) interpretation of signals*/
    char read_as;
    size_t pos;
};
struct editrecord* editlist=NULL;/*dynamic array of edits*/
size_t editcapacity=0;/*dyn-array capacity (see C++ vector type to understand)*/
size_t editsize=0;/*dyn-array size (see C++ vector type to understand)*/

/*loaded from the outside module encrypted message*/
unsigned char* msg=NULL;/*encrypted message pointer*/
size_t msgsize=0;/*message array size*/

/*does MUTATIONS number of random mutations (bit inversions) in all alphabet*/
void random_mutations(){
    size_t x=0;
    for (;x<MUTATIONS;x++){
        size_t randQ=((size_t) rand())%(LENGTH_OF_SYMBOL*LENGTH_OF_ALPHABET);
        size_t randX=((size_t) rand())%(CHAR_BIT);
        alphabet[randQ]^=(1<<randX);
        reserved_alphabet[randQ]^=(1<<randX);
    }
}

/*returns the most similiar (by bits) letter index*/
ptrdiff_t the_most_similiar_letter(unsigned char* msgPtr){
    /*results array*/
    size_t* whatstheworst=calloc(LENGTH_OF_ALPHABET,sizeof(size_t));/*the values are saved for module extesibility
    for "return_list_by_similiarity". If not, we need only 2 values: the best and now) */
    if (whatstheworst==NULL){
        return -1;
    }
    size_t q,x,m;
    for (q=0;q<LENGTH_OF_ALPHABET;q++){
        unsigned char results;
        for (x=0;x<LENGTH_OF_SYMBOL;x++){
            results=msgPtr[x]^(alphabet[q*LENGTH_OF_SYMBOL+x]);/*xor => 0 is indicator of similiarity */
            for (m=0;m<CHAR_BIT;m++){
                if (results%2){
                    whatstheworst[q]++;/*inc, if xor-result bit is not 0, it's bad*/
                }
                results/=2;/*2 is base-system*/
            }
        }
    }

    /*minimum search*/
    size_t* arrBegin=whatstheworst;
    size_t* arrEnd=whatstheworst+LENGTH_OF_ALPHABET;
    size_t* minimum=whatstheworst;
    for (;whatstheworst<arrEnd;whatstheworst++){
        if (*minimum>*whatstheworst){
            minimum=whatstheworst;
        }
    }
    ptrdiff_t result=minimum-arrBegin;
    free(arrBegin);
    return result;
}

/*for binary search of sorted dictionary 'vector'*/
struct dictrecord* dict_binary_search (int found_this_charval){
    size_t left=0;
    size_t right=dictsize;
    size_t mid=(right+left)/2;
    while ((left!=right) && ((dict+mid)->charval != found_this_charval)){
        if ((dict+mid)->charval<found_this_charval){
            left=mid+1;
        } else {
            right=mid;
        }
        mid=(right+left)/2;
    }
    if ((dict+mid)->charval != found_this_charval){
        return NULL;
    } else {
        return (dict+mid);
    }
}

/*comparator for qsort*/
int dict_comparator(const void* x1, const void* x2){
    return  (((struct dictrecord* )x1)->charval) - (((struct dictrecord* )x2)->charval);
}

/*returns total number of letters in str string, which can be matched with letters in dictionary.
CREATES dynamic array with every SUCCESS result for every letter (if the letter hasn't been found, it'll be ignored.
So, it's converting of all text-message to indexes of alphabet 'crypting letters' ('letters' of encrypted message)*/
size_t* new_dict_intval_results (char* str, size_t* size){
    size_t arrCapacity=0;
    size_t arrSize=0;
    size_t* dict_intval_results=malloc(1*sizeof(size_t));
    if (dict_intval_results==NULL){
            return NULL;
    }
    arrCapacity=1;
    char* strI=str;
    while ((*strI)!='\0'){
        struct dictrecord* whereIsDictC=dict_binary_search((int) *strI);
        strI++;
        if (whereIsDictC!=NULL){
            if (arrSize==arrCapacity){
                size_t* temporary=realloc(dict_intval_results,sizeof(size_t)*arrCapacity*2);
                if (temporary==NULL){
                    free(dict_intval_results);
                    return NULL;
                }
                dict_intval_results=temporary;
                arrCapacity*=2;
            }
            dict_intval_results[arrSize]=whereIsDictC->intval;
            arrSize++;
        }
    }
    size_t* temporary=realloc(dict_intval_results,sizeof(size_t)*arrSize);
    if (temporary!=NULL){
        dict_intval_results=temporary;
    }
    *size=arrSize;
    return dict_intval_results;
}

unsigned char* cipher (char* str, size_t* bytelength){
    if (bytelength==NULL||str==NULL){
        return NULL;
    }

    size_t res_size;
    size_t* dict_intvals=new_dict_intval_results(str,&res_size);
    if (dict_intvals==NULL){
        *bytelength=0;
        return NULL;
    }


    size_t sum_length=(res_size*LENGTH_OF_SYMBOL+rand()%LENGTH_OF_SYMBOL);
    unsigned char* result=malloc(sum_length);
    if (result==NULL){
        *bytelength=0;
        return NULL;
    }
    size_t q=0;
    for (;q<(res_size);q++){
        memcpy(result+q*LENGTH_OF_SYMBOL,alphabet+LENGTH_OF_SYMBOL*dict_intvals[q],LENGTH_OF_SYMBOL);
        random_mutations();
    }
    free(dict_intvals);

    for (q=res_size*LENGTH_OF_SYMBOL;q<sum_length;q++){
        result[q]=(unsigned char) rand();
    }

    *bytelength=sum_length;
    return result;
}

int load_message_to_module(size_t bytelength,unsigned char *message){
    free(msg);
    bytelength=bytelength/(LENGTH_OF_SYMBOL)*(LENGTH_OF_SYMBOL);
    msgsize=bytelength;
    msg=malloc(bytelength);
    if (msg==NULL){
        return -1;
    }
    memcpy(msg,message,bytelength);
    return 0;
}

int edits_comparator (const void* x1, const void* x2){
    if ((((struct editrecord*)x1)->pos)>((struct editrecord*)x2)->pos){
        return 1;
    }
    if ((((struct editrecord*)x1)->pos)==((struct editrecord*)x2)->pos){
        return 0;
    }
    return -1;
}

char* uncipher (int cancel_previous){
    char* result=malloc((msgsize/(LENGTH_OF_SYMBOL)+1));
    if ((result==NULL)||(msg==NULL)){
        free(result);
        return NULL;
    }
    if (cancel_previous){
        memcpy(reserved_alphabet,alphabet,LENGTH_OF_SYMBOL*LENGTH_OF_ALPHABET);
    } else {
        memcpy(alphabet,reserved_alphabet,LENGTH_OF_SYMBOL*LENGTH_OF_ALPHABET);
    }

    if (editlist==NULL){
        size_t q=0;
        for (;q<(msgsize/LENGTH_OF_SYMBOL);q++){
            size_t num;
            num=the_most_similiar_letter(msg+q*LENGTH_OF_SYMBOL);
            result[q]=revdict[num];
            memcpy(alphabet+num,msg+q*LENGTH_OF_SYMBOL,LENGTH_OF_SYMBOL);
        }
    } else {
        size_t editI=0;
        size_t num;
        int flag=1;
        qsort(editlist,editsize,sizeof(struct editrecord),edits_comparator);
        size_t q=0;
        for (;q<(msgsize/LENGTH_OF_SYMBOL);q++){
            if (flag){
                if (((editlist+editI)->pos)==q && flag){
                    struct dictrecord* whereIsIntval=dict_binary_search((editlist+editI)->read_as);
                    if (whereIsIntval==NULL){
                        free(result);
                        return NULL;
                    } else {
                        num=whereIsIntval->intval;
                    }
                    editI++;
                    if (editI>=editsize){
                        flag=0;
                    }
                } else {
                    num=the_most_similiar_letter(msg+q*LENGTH_OF_SYMBOL);
                }
            } else {
                num=the_most_similiar_letter(msg+q*LENGTH_OF_SYMBOL);
            }
            result[q]=revdict[num];
            memcpy(alphabet+num,msg+q*LENGTH_OF_SYMBOL,LENGTH_OF_SYMBOL);
        }
    }
    result[msgsize/LENGTH_OF_SYMBOL]='\0';
    return result;
}

/*0, if success
-1, if file haven't opened for writing*/
int save_alphabet(char* file_name) {
    FILE *fp;
    if ((fp = fopen(file_name, "wb")) == NULL){
        return -1;
    }
    int ints[3]={LENGTH_OF_ALPHABET,LENGTH_OF_SYMBOL,MUTATIONS};
    fwrite(ints, sizeof(int),3,fp);
      fwrite(alphabet, 1, LENGTH_OF_SYMBOL*LENGTH_OF_ALPHABET, fp); /*write buffer to file*/
    fclose(fp);
    return 0;
}

/*0, if success
-1, if file haven't opened
-2, if size of alphabet variable is incorrect (there's error in file)
-3, if bytelength of symbol variable is incorrect (there's error in file)*/
int load_alphabet(char *file_name){
    FILE *fp;
    if ((fp = fopen(file_name, "rb")) == NULL){
        return -1;
    }
    size_t ints[3];
    fread(&ints,sizeof(size_t),3,fp);
    if (ints[0]<=0){
            fclose(fp);
            return -1;
    }
    if ((ints[1]>0)){
        LENGTH_OF_ALPHABET=ints[0];
        free(alphabet);
        free(reserved_alphabet);
        LENGTH_OF_SYMBOL=ints[1];
        MUTATIONS=ints[2];
        alphabet=malloc(LENGTH_OF_ALPHABET*LENGTH_OF_SYMBOL);
        reserved_alphabet=malloc(LENGTH_OF_ALPHABET*LENGTH_OF_SYMBOL);
        if (alphabet==NULL || reserved_alphabet==NULL){
            free(alphabet);
            free(reserved_alphabet);
            fclose(fp);
            return -1;
        }
        fread(alphabet,1,LENGTH_OF_ALPHABET*LENGTH_OF_SYMBOL,fp);
        memcpy(reserved_alphabet,alphabet,LENGTH_OF_ALPHABET*LENGTH_OF_SYMBOL);
        fclose(fp);
        return 0;
    } else {
        fclose(fp);
        return -1;
    }
}

int load_dictionary(char* file_name, size_t* length){
    FILE* fp;
    fp=fopen(file_name,"r");
    if (fp==NULL){
        return -1;
    }
    int number[DIGITS_FOR_DESCRIPTION];
    size_t t=0;
    for (;t<DIGITS_FOR_DESCRIPTION;t++){
        number[t]=getc(fp);
    }
    size_t size_of_dict=0;
    for (t=0;t<DIGITS_FOR_DESCRIPTION;t++){
        switch(number[t]){/*for portability, for non-POSIX encoding tables*/
            case '0':
                break;
            case '1':
                size_of_dict+=1;
                break;
            case '2':
                size_of_dict+=2;
                break;
            case '3':
                size_of_dict+=3;
                break;
            case '4':
                size_of_dict+=4;
                break;
            case '5':
                size_of_dict+=5;
                break;
            case '6':
                size_of_dict+=6;
                break;
            case '7':
                size_of_dict+=7;
                break;
            case '8':
                size_of_dict+=8;
                break;
            case '9':
                size_of_dict+=9;
                break;
            default:
                fclose(fp);
                return -2;/*error: first 4 letters aren't digits*/
                break;
        }
        size_of_dict*=10;/*next digit...*/
    }
    size_of_dict/=10;/*last shift was needless*/
    free(dict);
    dictsize=0;
    dict=malloc(size_of_dict*sizeof(struct dictrecord));
    if (dict==NULL){
        fclose(fp);
        return -3;/*malloc error*/
    }
    free(revdict);
    revdict=malloc(size_of_dict*sizeof(int));
    if (revdict==NULL){
        fclose(fp);
        return -3;/*malloc error*/
    }
    for (t=0;t<size_of_dict;t++){
        (dict+t)->charval=fgetc(fp);
        (dict+t)->intval=t;
        *(revdict+t)=(dict+t)->charval;
    }
    dictsize=size_of_dict;
    qsort(dict,dictsize,sizeof(struct dictrecord),dict_comparator);
    fclose(fp);
    *length=size_of_dict;
    return 0;
}

void erase_all_editlist(){
    free(editlist);
    editcapacity=0;
    editsize=0;
}

void stop(){
    free(alphabet);
    free(reserved_alphabet);
    alphabet=NULL;
    reserved_alphabet=NULL;
    LENGTH_OF_ALPHABET=0;
    LENGTH_OF_SYMBOL=0;
    MUTATIONS=0;

    free(dict);
    free(revdict);
    dictsize=0;

    free(msg);
    msgsize=0;

    free(editlist);
    editcapacity=0;
    editsize=0;
}

int new_random_alphabet(char *file_name, size_t bytelength_symbol,size_t alphabet_length,size_t mutations_count){
    FILE *fp=fopen(file_name,"wb");
    if (fp != NULL){
        size_t ints[3]={alphabet_length,bytelength_symbol,mutations_count};
        fwrite(ints, sizeof(size_t),3,fp);
        unsigned char* random_alphabet=malloc(alphabet_length*bytelength_symbol);
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
        fwrite(random_alphabet,1,alphabet_length*bytelength_symbol,fp);
        free(random_alphabet);
        fclose(fp);
        return 0;
    } else {
        return -1;
    }
}

int add_edit(size_t pos, char should_read_as){
    if (editcapacity){
        if (editsize==editcapacity){
            struct editrecord* temporary=realloc(editlist,sizeof(struct editrecord)*editcapacity*2);
            if (temporary==NULL){
                free(editlist);
                return -1;
            }
            editlist=temporary;
            editcapacity*=2;
            (editlist+editsize)->pos=pos;
            (editlist+editsize)->read_as=should_read_as;
            editsize++;
        } else {
            (editlist+editsize)->pos=pos;
            (editlist+editsize)->read_as=should_read_as;
            editsize++;
        }
    } else {
        editlist=malloc(sizeof(struct editrecord));
        if (editlist==NULL){
            return -1;
        }
        editcapacity++;
        editlist->pos=pos;
        editlist->read_as=should_read_as;
        editsize++;
    }
    return 0;
}
