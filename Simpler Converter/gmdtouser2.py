import os
import json

with open('gmdtouser2ccAA5.json') as json_file:
    cc_dict_AA5 = json.load(json_file)

with open('gmdtouser2ccAA6.json') as json_file:
    cc_dict_AA6 = json.load(json_file)

ini_dict = {}
with open('config.txt','r',encoding='utf-8') as f:
    lines = f.readlines()
for line in lines:
    split_line = line.replace('"','').replace('\n','').split('=')
    ini_dict[split_line[0]] = split_line[1]


def readint32(f):
    return int.from_bytes(f.read(4),'little')

def readutf16(f):
    return f.read(2).decode('utf-16')

class User2Header:
    def __init__(self,first_header,unk1,topic_count,unk2,rsz_header_size,unk3,unk4,unk5):
        self.first_header = first_header
        self.magic = b'RSZ\x00'
        self.unk1 = unk1
        self.topic_count_1 = topic_count + 2
        self.unk2 = unk2
        self.rsz_header_size1 = rsz_header_size
        self.unk3 = unk3
        self.rsz_header_size2 = rsz_header_size
        self.unk4 = unk4
        self.topic_count_2 = topic_count + 1
        self.unk5 = unk5
        self.stuff = bytearray()
        for _ in range(topic_count):
            self.stuff += b'\x42\xf0\xf3\x83\x56\x31\x26\x0b'
        self.stuff += b'\xa7\x3a\x93\xee\xac\xa4\xa1\x1a'
        self.padding = rsz_header_size - 0x3c - 8*(topic_count+1)

    def write_to_file(self,f):
        f.write(self.first_header + self.magic + self.unk1 + self.topic_count_1.to_bytes(4,'little') + self.unk2 + self.rsz_header_size1.to_bytes(4,'little') + self.unk3 + self.rsz_header_size2.to_bytes(4,'little') + self.unk4 + self.topic_count_2.to_bytes(4,'little') + self.unk5 + self.stuff + self.padding * b'\x00')

class User2Topic:
    def __init__(self,topic_name_size,topic_name,topic_data_size,topic_data):
        self.name_size = topic_name_size
        self.name = topic_name
        self.data_size = topic_data_size
        self.data = topic_data

    def write_to_file(self,f):
        f.write(self.name_size.to_bytes(4,'little'))
        f.write(self.name.encode("utf-16")[2:] + 2 * b'\x00')
        if f.tell() % 4 != 0: # 4 bytes block padding
            f.write(2*b'\x00')
        f.write(self.data_size.to_bytes(4,'little'))
        f.write(self.data.encode("utf-16")[2:] + 2 * b'\x00')
        if f.tell() % 4 != 0: # 4 bytes block padding
            f.write(2*b'\x00')

class User2File:
    def __init__(self,filepath):
        with open(filepath,mode='rb') as f:
            first_header = f.read(0x30)
            magic = f.read(4)
            if magic != b'RSZ\x00':
                raise Exception("Error: invalid input file (bad magic)")
            unk1 = f.read(8)
            topic_count = readint32(f) - 2
            unk2 = f.read(16)
            rsz_header_size = readint32(f)
            unk3 = f.read(4)
            f.read(4)
            unk4 = f.read(4)
            f.read(4)
            unk5 = f.read(8)
            f.read(rsz_header_size -  60)
            self.header = User2Header(first_header,unk1,topic_count,unk2,rsz_header_size,unk3,unk4,unk5)
            self.topic_list = []
            for _ in range(topic_count):
                topic_name_size = readint32(f)
                topic_name = ''
                for _ in range(topic_name_size - 1):
                    topic_name += readutf16(f)
                f.read(2)
                if f.tell() % 4 != 0: # 4 bytes block padding
                    f.read(2)
                topic_data_size = readint32(f)
                topic_data = ''
                for _ in range(topic_data_size - 1):
                    topic_data += readutf16(f)
                f.read(2)
                if f.tell() % 4 != 0: # 4 bytes block padding
                    f.read(2)
                self.topic_list.append(User2Topic(topic_name_size,topic_name,topic_data_size,topic_data))
            filename_lenght = readint32(f) - 1
            self.filename = ''
            for _ in range(filename_lenght):
                self.filename += readutf16(f)


    def write_to_file(self,filename):
        with open(filename,mode="wb") as f:
            self.header.write_to_file(f)
            for topic in self.topic_list:
                topic.write_to_file(f)
            f.write((len(self.filename) + 1).to_bytes(4,'little'))
            f.write(self.filename.encode('utf-16')[2:] + 2 * b'\x00')
            if f.tell() % 4 != 0: # 4 bytes block padding
                f.write(2*b'\x00')
            f.write(len(self.topic_list).to_bytes(4,'little'))
            for i in range(len(self.topic_list)):
                f.write((i+1).to_bytes(4,'little'))


def xor(texte): #xor encryption/decryption
    KEY1 = "fjfajfahajra;tira9tgujagjjgajgoa"
    KEY2 = "mva;eignhpe/dfkfjgp295jtugkpejfu"
    enc = bytearray()
    for i in range(len(texte)):
        x1 = ord(KEY1[i%32])
        x2 = ord(KEY2[i%32])
        data = texte[i]
        x1 = str('{0:b}'.format(x1))
        x2 = str('{0:b}'.format(x2))
        databin = str('{0:b}'.format(data))
        newdata = int(x1,2) ^ int(x2,2) ^ int(databin,2)
        enc.append(newdata)
    return enc


class AA5GmdFile:
    def __init__(self,filepath):
        with open(filepath,mode='rb') as f:
            self.magic = f.read(4)
            if self.magic != b'GMD\x00':
                raise Exception("Error: invalid input file (bad magic)")
            self.version = f.read(4)
            if self.version != b'\x01\x02\x01\x00':
                raise Exception("Error: invalid input file (wrong version")
            f.read(12) #skipping language and flags
            topic_count = readint32(f)
            f.read(4)
            topic_names_size = readint32(f)
            file_size = readint32(f)
            filename_size = readint32(f)
            f.read(filename_size + 1)
            for _ in range(topic_count): #skipping offsets
                f.read(8)
            self.topic_name_list = f.read(topic_names_size).split(b'\x00')[:-1]
            dec_data = xor(f.read())
            self.topic_data_list = dec_data.split(b'\x00')[:-1]


    def to_user2(self,user2_filename,output_filename):
        user2 = User2File(user2_filename)
        user2.topic_list = []
        for idx, topic in enumerate(self.topic_name_list):
            str_topic = topic.decode()
            newdata = self.script_convert(self.topic_data_list[idx])
            user2.topic_list.append(User2Topic(len(str_topic)+1,str_topic,len(newdata)+1,newdata))
        user2.header = User2Header(user2.header.first_header,user2.header.unk1,len(user2.topic_list),user2.header.unk2,0x40 + 0x10 * (len(user2.topic_list)//2 + 1),user2.header.unk3,user2.header.unk4,user2.header.unk5)
        user2.write_to_file(output_filename)

    def script_convert(self,data):
        user2_data = ""
        new_cc = ""
        cc_flag = False
        decoded_data = data.decode('utf-8')
        for char in decoded_data:
            if char == '<':
                cc_flag = True
            elif char == '>':
                cc_flag = False
                if not new_cc.startswith('ICON'):
                    func_data = new_cc.split(' ')
                else:
                    func_data = [new_cc]
                func_data[0] = cc_dict_AA5[func_data[0]]
                if func_data[0] != '':
                    user2_data += "<"
                    for arg in func_data[:-1]:
                        user2_data += arg
                        user2_data += ","
                    user2_data += func_data[-1]
                    user2_data += ">"
                new_cc = ''
            elif cc_flag == True:
                new_cc += char
            else:
                user2_data += char

        return user2_data

class AA6GmdFile:
    def __init__(self,filepath):
        with open(filepath,mode='rb') as f:
            self.magic = f.read(4)
            if self.magic != b'GMD\x00':
                raise Exception("Error: invalid input file (bad magic)")
            self.version = f.read(4)
            if self.version != b'\x02\x03\x01\x00':
                raise Exception("Error: invalid input file (wrong version")
            f.read(12) #skipping language and flags
            topic_count = readint32(f)
            f.read(4)
            topic_names_size = readint32(f)
            file_size = readint32(f)
            filename_size = readint32(f)
            f.read(filename_size + 1)
            for _ in range(topic_count): #skipping hash and ids
                f.seek(20,1)
            f.seek(0x400,1) #skipping extdata
            self.topic_name_list = f.read(topic_names_size).split(b'\x00')[:-1]
            dec_data = f.read()
            self.topic_data_list = dec_data.split(b'\x00')[:-1]


    def to_user2(self,user2_filename,output_filename):
        user2 = User2File(user2_filename)
        user2.topic_list = []
        for idx, topic in enumerate(self.topic_name_list):
            str_topic = topic.decode()
            newdata = self.script_convert(self.topic_data_list[idx])
            user2.topic_list.append(User2Topic(len(str_topic)+1,str_topic,len(newdata)+1,newdata))
        user2.header = User2Header(user2.header.first_header,user2.header.unk1,len(user2.topic_list),user2.header.unk2,0x40 + 0x10 * (len(user2.topic_list)//2 + 1),user2.header.unk3,user2.header.unk4,user2.header.unk5)
        user2.write_to_file(output_filename)

    def script_convert(self,data):
        user2_data = ""
        new_cc = ""
        cc_flag = False
        decoded_data = data.decode('utf-8')
        for char in decoded_data:
            if char == '<':
                cc_flag = True
            elif char == '>':
                cc_flag = False
                if not new_cc.startswith('ICON'):
                    func_data = new_cc.split(' ')
                else:
                    func_data = [new_cc]
                func_data[0] = cc_dict_AA6[func_data[0]]
                if func_data[0] != '':
                    user2_data += "<"
                    for arg in func_data[:-1]:
                        user2_data += arg
                        user2_data += ","
                    user2_data += func_data[-1]
                    user2_data += ">"
                new_cc = ''
            elif cc_flag == True:
                new_cc += char
            else:
                user2_data += char

        return user2_data

def main():
    if os.path.isdir(ini_dict["aa5_gmd_dir_path"]):
        for file in os.listdir(ini_dict["aa5_gmd_dir_path"]):
            gmd_filepath = os.path.join(ini_dict["aa5_gmd_dir_path"],file)
            user2_filename = file[1:-8] + '.user.2' + ini_dict["user2_extension"]
            user2_filepath = os.path.join(ini_dict["aa5_user2_dir_path"],user2_filename)
            output_dir = ini_dict["aa5_output_dir_path"]
            output_file = os.path.join(output_dir,user2_filename)
            if not os.path.isfile(user2_filepath):
                print(f"Skipping {file}, no user2 counterpart")
                continue
            else:
                print(f"Processing {file}...")
                gmd = AA5GmdFile(gmd_filepath)
                gmd.to_user2(user2_filepath,output_file)

    if os.path.isdir(ini_dict["aa6_gmd_dir_path"]):
        for file in os.listdir(ini_dict["aa6_gmd_dir_path"]):
            gmd_filepath = os.path.join(ini_dict["aa6_gmd_dir_path"],file)
            user2_filename = file[1:-8] + '.user.2' + ini_dict["user2_extension"]
            user2_filepath = os.path.join(ini_dict["aa6_user2_dir_path"],user2_filename)
            output_dir = ini_dict["aa6_output_dir_path"]
            output_file = os.path.join(output_dir,user2_filename)
            if not os.path.isfile(user2_filepath):
                print(f"Skipping {file}, no user2 counterpart")
                continue
            else:
                print(f"Processing {file}...")
                gmd = AA6GmdFile(gmd_filepath)
                gmd.to_user2(user2_filepath,output_file)

if __name__ == "__main__":
    main()