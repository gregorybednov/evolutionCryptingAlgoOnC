#ifndef CRYPTING_CORE_H_INCLUDED
#define CRYPTING_CORE_H_INCLUDED

// This is an independent project of an individual developer. Dear PVS-Studio, please check it.

// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#ifndef CRYPTCORE_C_H_INCLUDED
#define CRYPTCORE_C_H_INCLUDED

int load_message_to_module(size_t length,unsigned char *byteMessage);

/** Главная расшифровывающая функция. Возвращает указатель на строку Си с результатами.
Возвращает NULL при любой неудаче.

cancel_previous_uncyphering=0 - сохранить внутри программы имеющуюся новую
версию шифроалфавита. =1 - откатить шифроафлавит в последнее сохраненное состояние

Используйте cancel...=0 тогда, когда сообщение точно прочитано пользователем, а все его
собственные правки в расшифровку сделаны от начала сообщения и до конца.
Используйте cancel...=1 до тех пор, пока самая последняя правка расшифровки человеком не будет сделана.

 **/
char *Uncipher(int cancel_previous_unciphering);

/** Главная шифрующая функция. Возвращает указатель на создаваемый динамический массив unsigned char.
По адресу length будет записано кол-во элементов в массиве.
str - указатель на Си-строку, которую надо зашифровать.
**/
unsigned char *Cipher(size_t *length,char *str);

/** Сохраняет алфавит.

Возвращает -1, если по каким-то причинам не удалось открыть файл и сделать запись.
В случае успеха возвращает 0.
**/
int save_alphabet();

/**
Загружает алфавит с именем, описанным строкой по указателю name

Возвращает 0, если успешно
Возвращает -1, если ошибка
**/
int load_alphabet(char *name);

///Удаляет весь журнал правок
void clearEdits();

/**
Загружает алфавит с именем, описанным строкой по указателю name

Возвращает 0, если успешно
Возвращает -1, если ошибка
**/
int load_dict(char *name);

/** Необходимо использовать при закрытии работы с модулем
**/
void end();

/**
Создает новый шифроалфавит с именем по адресу name длины символа (в битах) bitlength_symbol и
количеством символов alphabet_length.

bitlength_symbol делится на 8 нацело. Иначе ошибка (ошибка актуальна для абсолютного большинства платформ, т.к.
у этого абсолютного большинства платформ нет адресуемых ячеек памяти меньше 8 бит).

Возвращает 0 в случае успеха
Возвращает -1 в случае любой ошибки
**/
int new_random_alphabet(char *name,size_t bytelength_symbol,size_t alphabet_length);

///Добавляет пользовательское прочтение символа
///Возвращает -1, если пользовательский символ вообще не входит в словарь
///Возвращает 1, если правка по этому номеру буквы в строке уже поступала (обновление буквы)
///Возвращает 0, если правок по этому номеру буквы в строке ещё не поступало (добавление буквы)
int addEdit(size_t pos, char should_read_as);

#endif // CRYPTCORE_C_H_INCLUDED

#endif // CRYPTING_CORE_H_INCLUDED
