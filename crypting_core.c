#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypting_core.h"
#define IMPOSSIBLE_ENCODING_POSITION_FOR_DIGIT -2
//IMPOSSIBLE_ENCODING_POSITION_FOR_DIGIT должно не являться номером какого-либо символа-цифры в таблице кодировки.

#define DIGITS_FOR_DESCRIPTION 4
//Сколько десятичных цифр требуется на описание файла словаря

/*ОПИСАНИЯ ГЛОБАЛЬНЫХ ПЕРЕМЕННЫХ И ТИПОВ МОДУЛЯ*/
/*Описания, связанные с алфавитами*/
size_t LENGTH_OF_ALPHABET=0;
size_t LENGTH_OF_SYMBOL=0;
unsigned char* alphabet;
unsigned char* reserved_alphabet;
size_t MUTATIONS;

/*Описаний, связанные со словарями*/
struct dictrecord {
	int charval;
	size_t intval;
};
struct dictrecord* dict;
int* revdict;
size_t dictsize=0;

/*Раздел описаний, связанных с правками*/
struct editrecord {//тип "правка"
	char read_as;
	size_t pos;
};
struct editrecord* editlist;//указатель на дин. массив правок
size_t editcapacity=0;//общая ёмкость дин.массива
size_t editsize=0;//количество уже задействованных элементов

/*Описание переменных, связанных с шифрованным сообщением*/
unsigned char* msg;//указатель на дин. массив сообщения
size_t msgsize=0;//количество шифросимволов в сообщении

///делает MUTATIONS мутаций в алфавите
void random_mutations(){
	for (size_t x=0;x<MUTATIONS;x++){
		size_t randQ=((size_t) rand())%(LENGTH_OF_SYMBOL*LENGTH_OF_ALPHABET);
		size_t randX=((size_t) rand())%(sizeof(unsigned char)*8);
		alphabet[randQ]^=(1<<randX);
		reserved_alphabet[randQ]^=(1<<randX);
	}
}

///возвращает номер (начиная с 0) наиболее подходящей по битам буквы
size_t the_samest_letter(unsigned char* msgPtr){
	//Постройка массива
	size_t* whatstheworst=calloc(LENGTH_OF_ALPHABET,sizeof(size_t));//значения следует хранить для возможной расширяемости модуля
																	//функцией "вывести все возможные варианты"
																	//(без этой функции, в общем-то, можно было бы обойтись 2 значениями:
																	//лучшим найденным и нынешним)
	for (size_t q=0;q<LENGTH_OF_ALPHABET;q++){
		unsigned char results;

		for (size_t x=0;x<LENGTH_OF_SYMBOL;x++){
			results=msgPtr[x]^(alphabet[q*LENGTH_OF_SYMBOL+x]);		//делаем XOR по uns char'у из алфавита и из сообщения
			for (size_t m=0;m<sizeof(unsigned char)*8;m++){			//чем меньше битов в состоянии "1", тем больше шанс, что это та самая буква
				if (results%2){
					whatstheworst[q]++;								//щелкаем счетчиком, если видим, что бит результата xor ненулевой
				}
				results/=2;
			}
		}
	}

	//Поиск минимума
	size_t* arrBegin=whatstheworst;
	size_t* arrEnd=whatstheworst+LENGTH_OF_ALPHABET;
	size_t* minimum=whatstheworst;
	for (;whatstheworst<arrEnd;whatstheworst++){
		if (*minimum>*whatstheworst){
			minimum=whatstheworst;
		}
	}
	size_t result=minimum-arrBegin;
	free(arrBegin);
	return result;
}

///для бинарного поиска по отсортированному словарному "вектору"
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

///функция для qsort
int dict_comparator(const void* x1, const void* x2){
	return  (((struct dictrecord* )x1)->charval) - (((struct dictrecord* )x2)->charval);
}

///возвращает общее количество литер str, для которых есть соответствие в словаре.
///Кроме того, создает дин. массив ("векторного" исполнения), в который последовательно сохранён
///каждый УСПЕШНЫЙ результат по всякому символу (т.е. все обращения к словарю можно и достаточно провести тут,
///а не в самой функции шифрования), а потом обращаться к созданным заранее результатам по адресу dict_intval_results

size_t* new_dict_intval_results (char* str, size_t* size){
	size_t arrCapacity=0;
	size_t arrSize=0;
	size_t* dict_intval_results=malloc(1*sizeof(size_t));
	if (dict_intval_results==NULL){
			return NULL;//если место не выделено, то функции нет особого смысла дальше работать: программисту не будет
			//удобно рассматривать все возможные случаи, скорее всего он просто начнет обращаться с dict_intval_results
	}
	arrCapacity=1;
	char* strI=str;
	while ((*strI)!='\0'){
		struct dictrecord* whereIsDictC=dict_binary_search((int) *strI);
		strI++;
		if (whereIsDictC!=NULL){
			if (arrSize==arrCapacity){
				dict_intval_results=realloc(dict_intval_results,sizeof(size_t)*arrCapacity*2);
				arrCapacity*=2;
			}
			dict_intval_results[arrSize]=whereIsDictC->intval;
			arrSize++;
		}
	}
	dict_intval_results=realloc(dict_intval_results,sizeof(size_t)*arrSize);
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
	unsigned char* result=malloc(sum_length*sizeof(unsigned char));
	if (result==NULL){
		*bytelength=0;
		return NULL;
	}

	for (size_t q=0;q<(res_size);q++){
		memcpy(result+q*LENGTH_OF_SYMBOL,alphabet+LENGTH_OF_SYMBOL*dict_intvals[q],LENGTH_OF_SYMBOL*sizeof(char));
		random_mutations();
	}

	for (size_t q=res_size*LENGTH_OF_SYMBOL;q<sum_length;q++){
		result[q]=(unsigned char) rand();
	}

	*bytelength=sum_length*sizeof(char);
	return result;
}

int load_message_to_module(size_t bytelength,unsigned char *message){
	free(msg);
	bytelength=bytelength/(LENGTH_OF_SYMBOL)*(LENGTH_OF_SYMBOL);
	msgsize=bytelength/sizeof(char);
	msg=malloc(bytelength);
	if (msg==NULL){
		return -1;
	}
	memcpy(msg,message,bytelength);
	return 0;
}

int edits_comparator (const void* x1, const void* x2){
	return ((struct editrecord*)x1)->pos - ((struct editrecord*)x2)->pos;
}

char* uncipher (int cancel_previous){
	char* result=malloc((msgsize/(LENGTH_OF_SYMBOL*sizeof(char))+1)*sizeof(char));
	if (result==NULL||msg==NULL){
		return NULL;
	}
	if (cancel_previous){
		memcpy(reserved_alphabet,alphabet,sizeof(unsigned char)*LENGTH_OF_SYMBOL*LENGTH_OF_ALPHABET);
	} else {
		memcpy(alphabet,reserved_alphabet,sizeof(unsigned char)*LENGTH_OF_SYMBOL*LENGTH_OF_ALPHABET);
	}
	if (editlist==NULL){
		for (size_t q=0;q<(msgsize/LENGTH_OF_SYMBOL);q++){
			size_t num;
			num=the_samest_letter(msg+q*LENGTH_OF_SYMBOL);
			result[q]=revdict[num];
			memcpy(alphabet+num,msg+q*LENGTH_OF_SYMBOL,LENGTH_OF_SYMBOL);
		}
	} else {
		size_t editI=0;
		size_t num;
		qsort(editlist,editsize,sizeof(struct editrecord),edits_comparator);
		for (size_t q=0;q<(msgsize/LENGTH_OF_SYMBOL);q++){
			int flag=1;
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
					} else {
						num=the_samest_letter(msg+q*LENGTH_OF_SYMBOL);
					}
				} else {
					num=the_samest_letter(msg+q*LENGTH_OF_SYMBOL);
				}
			} else {
				num=the_samest_letter(msg+q*LENGTH_OF_SYMBOL);
			}
			result[q]=revdict[num];
			memcpy(alphabet+num,msg+q*LENGTH_OF_SYMBOL,LENGTH_OF_SYMBOL);
		}
	}
	result[msgsize/LENGTH_OF_SYMBOL]='\0';
	return result;
}

///0, если успешно
///-1, если файл не был открыт на запись
int save_alphabet(char* file_name){
	FILE *fp;
	if ((fp = fopen(file_name, "wb")) == NULL){
		return -1;
	}
	int ints[3]={LENGTH_OF_ALPHABET,LENGTH_OF_SYMBOL,MUTATIONS};
	fwrite(ints, sizeof(int),3,fp);
  	fwrite(alphabet, sizeof(unsigned char), LENGTH_OF_SYMBOL*LENGTH_OF_ALPHABET*sizeof(unsigned char), fp); // записать в файл содержимое буфера
	fclose(fp);
	return 0;
}

///0, если успешно
///-1, если файл по каким-то причинам не был открыт
///-2, если в файле неверное значение длины алфавита (файл с ошибкой)
///-3, если в файле неверное значение длины символа (файл с ошибкой)
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
		alphabet=malloc(LENGTH_OF_ALPHABET*LENGTH_OF_SYMBOL*sizeof(unsigned char));
		reserved_alphabet=malloc(LENGTH_OF_ALPHABET*LENGTH_OF_SYMBOL*sizeof(unsigned char));
		if (alphabet==NULL || reserved_alphabet==NULL){
			fclose(fp);
			return -1;
		}
		fread(alphabet,sizeof(unsigned char),LENGTH_OF_ALPHABET*LENGTH_OF_SYMBOL,fp);
		memcpy(reserved_alphabet,alphabet,LENGTH_OF_ALPHABET*LENGTH_OF_SYMBOL*sizeof(unsigned char));
		fclose(fp);
		return 0;
	} else {
		fclose(fp);
		return -1;
	}
}

int comparator(const void* x1, const void* x2){
	return  (((struct dictrecord* )x1)->charval) - (((struct dictrecord* )x2)->charval);
}

int load_dictionary(char* file_name, size_t* length){
	FILE* fp;
	fp=fopen(file_name,"r");
	int number[DIGITS_FOR_DESCRIPTION];
	for (size_t t=0;t<DIGITS_FOR_DESCRIPTION;t++){
		number[t]=getc(fp);
	}
	size_t size_of_dict=0;
	for (size_t t=0;t<DIGITS_FOR_DESCRIPTION;t++){
		switch(number[t]){//жертва во имя переносимости: таблицы кодировок никак не ограничены тем, что '0'+1 это обязательно '1'
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
				return -2;//ошибка: первые 4 символа не оказались цифрами
				break;
		}
		size_of_dict*=10;//если мы всё ещё здесь, значит, результат можно смело домножать на 10.
	}
	size_of_dict/=10;//последнее смещение было лишним
	free(dict);
	dictsize=0;
	dict=malloc(size_of_dict*sizeof(struct dictrecord));
	if (dict==NULL){
		fclose(fp);
		return -3;//ошибка выеделения памяти
	}
	free(revdict);
	revdict=malloc(size_of_dict*sizeof(int));
	if (revdict==NULL){
		fclose(fp);
		return -3;//ошибка выеделения памяти
	}
	for (size_t t=0;t<size_of_dict;t++){
		(dict+t)->charval=fgetc(fp);
		(dict+t)->intval=t;
		*(revdict+t)=(dict+t)->charval;
	}
	dictsize=size_of_dict;
	qsort(dict,dictsize,sizeof(struct dictrecord),comparator);
	fclose(fp);
	*length=size_of_dict;
	return 0;
}

void erase_all_editlist(){
	free(editlist);
	editcapacity=0;
	editsize=0;
}

void end(){
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
		int ints[3]={alphabet_length,bytelength_symbol,mutations_count};
		fwrite(ints, sizeof(int),3,fp);
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

int add_edit(size_t pos, char should_read_as){
	if (editcapacity){
		if (editsize==editcapacity){
			editlist=realloc(editlist,sizeof(struct editrecord)*editcapacity*2);
			if (editlist==NULL){
				return -1;
			}
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
