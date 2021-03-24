# Fuzzer

Фаззер формата файла


Реализованная программа осуществляет следующие действия:

—	изменение оригинального файла (однобайтовая замена, замена нескольких байт, дозапись в файл);

—	замена байт на граничные значения (0x00, 0xFF, 0xFFFF, 0xFFFFFF, 0xFFFFFFFF, 0xFFFF/2, 0xFFFF/2+1, 0xFFFF/2-1 и т.д.);

—	автоматический режим работы, при котором производится последовательная замена байт в файле;

—	расширение значения полей в файле (дописывать в конец, увеличивать длину строк в файле);

—	поиск границы полей в файле на основании анализа нескольких конфигурационных файлов;

—	запуск исследуемой программы;

—	обнаружение возникновения ошибки в исследуемом приложении;

—	получение кода ошибки;

—	логирование в файл информации о произошедших ошибках и соответствующих им входных параметрах (произведенных заменах).

