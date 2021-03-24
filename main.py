import os
import random
import subprocess

fuz_bytes = [b'\x00', b'\x00\x00', b'\x00\x00\x00', b'\x00\x00\x00\x00',
           b'\xff', b'\xff\xff', b'\xff\xff\xff', b'\xff\xff\xff\xff',
           b'\x7f\xfe', #ffff/2-1
           b'\x80\x00', #ffff/2+1
           b'\x7f\xff', #ffff/2
           b'\x7f\xff\xff',
           b'\x7f\xff\xfe',
           b'\x80\x00\x00',
           b'\x7f\xff\xff\xff',
           b'\x7f\xff\xff\xfe',
           b'\x80\x00\x00\x00']



def ChangeByte(start_indx,value):
    config = open('config_2', "br")
    config_text= config.read()
    config.close()
   # print(config_text,'\n')
    end_indx= start_indx+len(value)+1
    config_text = config_text[:start_indx]+value+config_text[end_indx:]
    #print(config_text)
    config = open('config_2', "bw")
    config.write(config_text)
    config.close()

def InsertByte(start_indx,value):
    config = open('config_2', "br")
    config_text= config.read()
    config.close()
  #  print(config_text,'\n')
    config_text = config_text[:start_indx] + value + config_text[start_indx:]
 #   print(config_text)
    config = open('config_2', "bw")
    config.write(config_text)
    config.close()






def CopyConfig():
    if (os.path.exists('config_2_default') == False):
        config_file = open('config_2', "br") #создаем копию оригинального файла
        config_text = config_file.read()
        config_file.close()
        config_file_copy = open('config_2_default', "bw")
        config_file_copy.write(config_text)
        config_file_copy.close()
    else:
        config_file_copy = open('config_2_default', "br")#возвращаем конфиг в оригинальный вид
        config_text = config_file_copy.read()
        config_file_copy.close()
        config_file = open('config_2', "bw")
        config_file.write(config_text)
        config_file.close()

def RunTest():
    process = subprocess.Popen('vuln2', stdout=subprocess.PIPE)
    code = 0
    try:
        code = process.wait(2.0)
    except subprocess.TimeoutExpired:
        print('Error: Timeout')
        code = 0xdeadbeef
    return code

def SearchFields():
    symbol_FF=(0xff).to_bytes(1,byteorder='big')
    # b'\xff'

    my_config_file = open('config_2', "br")
    my_config = my_config_file.read()
    my_config_file.close()
    my_config_len = len(my_config)

    i = random.randint(3, 6)
    temp_config_file=open('configs\\config_'+str(i), "br")
    temp_config = temp_config_file.read()
    temp_config_file.close()
    temp_len = len(temp_config)
    text = b''
    if(my_config_len  > temp_len):
        end_indx = temp_len
        text_7 = my_config[:end_indx]
        text_x = temp_config
    else:
        end_indx = my_config_len
        text_x = temp_config[:end_indx]
        text_7 = my_config

    for j in range(0, end_indx):
        if (text_x[j] == text_7[j] or j==0):
            text += text_7[j].to_bytes(1,byteorder='big')
        else:
            text += symbol_FF

    fields = []
    i = 0

    while (i < len(text)):
        if(text[i]==0xff):
            field=[i+1]
            while (i<len(text) and text[i]==0xff):
                i+=1
            field.append(i)
            fields.append(field)
        i+=1

    for field in fields:#отладочная часть
      print(field)

    return fields

def AutoFuzzer():
    log = open('log1.txt', "w")

    fields = SearchFields()
    for field in fields[:-1]:
      for fuz_byte in fuz_bytes:
        CopyConfig()
        ChangeByte(field[0], fuz_byte)
        err_code = RunTest()
        error_string = "Change byte: start_pos = " +  str(field[0]) + ", byte = "  + str(fuz_byte) + "\n"
        if (err_code != 0):
            err = "ERROR: " + str(err_code) + " :: " + error_string
            log.write(err)
            print('error: %x' % err_code)

      for x in [2, 10000]:
        for fuz_byte in fuz_bytes:
          CopyConfig()
          InsertByte(field[1], fuz_byte*x)
          err_code = RunTest()
          error_string = "Insert byte: start_pos = " + str(field[1]) + ", byte = " + str(fuz_byte*x) + "\n"
          if (err_code != 0):
            err = "ERROR: " + str(err_code) + " :: " + error_string
            log.write(err)
            print('error: %x' % err_code)

    CopyConfig()
    log.close()

def ByteLen(str):
    len=0
    for x in str[2:]:
        len+=1
    return len//2


if __name__ == "__main__":
    while 1:
        inp = input(">> ")
        if inp == "search fields":
            SearchFields()
        if inp == "exit":
            exit()
        if inp == "run test":
            err_code = RunTest()
            if (err_code!=0):
                print('error: %x' % err_code)
        if inp == "copy config":
            CopyConfig()
        if inp == "auto fuzzer":
            print("start")
            AutoFuzzer()
        if inp == "insert":
            pos = int(input("Input start position: "))
            byte_str = input("Input byte: ")
            byte_len = ByteLen(byte_str)
            byte = int(byte_str, 16)
           # byte_hex = binascii.unhexlify(byte_str)
            InsertByte(pos,byte.to_bytes(byte_len, byteorder='big'))
        if inp == "change":
            pos = int(input("Input start position: "))
            byte_str = input("Input byte: ")
            byte_len = ByteLen(byte_str)
            byte = int(byte_str, 16)
            ChangeByte(pos, byte.to_bytes(byte_len, byteorder='big'))

