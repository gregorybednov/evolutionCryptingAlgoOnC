#ifndef CRYPTING_CORE_H_INCLUDED
#define CRYPTING_CORE_H_INCLUDED

/* Use to load message into module (to save encapsulation)*/
int load_message_to_module(size_t length,unsigned char *message);

/* It's main uncrypting function. If any fail exists, it returns NULL. If all is OK, it returns C-string with results.

cancel_previous=0 - save crypting alphabet in module. Recommended to use with erase_all_editlist() procedure.
cancel_previous=1 - cancel crpyting alphabet to last saved condition (or starting-the-program condition,
if there hasn't any saves.

Use cancel...=0 then message has been uncrypted and reciever has read all the message,
no more edits in interpretation of symbols.
Use cancel...=1 only until reciever won't have edits in interpretation the message.*/
char* uncipher (int cancel_previous);

/* It's main crypting function. It returns pointer on message; it's dynamical array of (unsigned char)-type
 (bytes of this machine).
On address in bytelength you will get size of message.
str is pointer on string the module need to crypt for you.*/
unsigned char* cipher (char* str, size_t* bytelength);

/* This function saves crypting alphabet.

It returns -1 with any error in opening the file called file_name.
It returns 0 if success.*/
int save_alphabet(char* file_name);

/*
It loads crypting alphabet called file_name.

It returns 0 with success.
It returns -1 if file is empty
It returns -2 if first 4 symbols is NOT a digit.*/
int load_alphabet(char* file_name);

/*It deletes all edits list. Recommended to use with uncypher(0).*/
void erase_all_editlist();

/*
It loads crypting alphabet called file_name.

It returns 0 with success,
it returns -1 with any error.*/
int load_dictionary(char* file_name, size_t* length);

/*
Use it then working with module must be stopped.
You MUST use this procedure in end of working with this module;
ignoring this procedure will create memory leaks in your program.*/
void stop();

/*
Creates new random crpyting alphabet with
- file_name is name of file where the alphabet will have been saved;
- bitlength_symbol is length in bytes of one crypting symbol
- alphabet_length is how many crypting symbols will be created

Function return 0 if success, and -1 with any errors.*/
int new_random_alphabet(char *file_name, size_t bytelength_symbol,size_t alphabet_length,size_t mutations_count);

/*Add edit (reciever's interpretation of letter (on position POS) in uncrypted message (loaded to module using
 load_message_to_module() and uncrypted using uncipher() function) ). Normally, user interpretation of symbol was created
 because of reading uncrypted text.
It returns -1, if user symbol cannot be in message (it isn't in 'dictionary')
It returns 1, if edit index has been modified before (letter updating)
It returns 0, if it's adding new edit in list (letter adding)*/
int add_edit(size_t pos, char should_read_as);

#endif /*CRYPTING_CORE_H_INCLUDED*/
