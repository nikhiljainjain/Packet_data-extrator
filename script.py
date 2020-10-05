import math

class Data_print :

    charlist = {
        'a' : 10,
        'b' : 11,
        'c' : 12,
        'd' : 13,
        'e' : 14,
        'f' : 15,
    }

    def ip_convert(string,address):
        address = list(address.strip())
        for i in range(len(address)):
            if (i == 2 or i == 5  or i==8) :
                address[i] = ':'
            else :
                if address[i] in ['a','b','c','d','e','f'] :
                   address[i] = int(Data_print.charlist[address[i]])
                elif address[i] == ':' or address[i] == ' ' :
                    continue
                else :
                    address[i] = int(address[i])
        new_ip = ''
        for i in range(0,11,3) :
            new_ip = new_ip + str((16*address[i])+address[i+1])+str(':')
        new_ip = list(new_ip)
        del (new_ip[-1])
        new_ip = ''.join(new_ip)
        print(string+str(new_ip))

    def line_one(lines):
        macadd = list(lines[26:42])
        for i in range(len(macadd)):
            if macadd[i] == ' ':
                macadd[i] = ':'
        print('Source MAC Address       '+''.join(macadd))
        macadd = list(lines[7:24])
        for i in range(len(macadd)):
            if macadd[i] == ' ':
                macadd[i] = ':'
        print('Destination MAC Address: '+''.join(macadd))

    def line_two(lines):
        var1 = list(lines[7:12])
        del(var1[2])
        totallength = 0
        for i in range(3,-1,-1):
            if str(var1[i]) in ['a','b','c','d','e','f'] :
               totallength +=  (16**(3-i))*int(math.floor(Data_print.charlist[var1[i]]))
            elif var1[i] == ' ' :
                continue
            else :
                totallength += (16**(3-i))*int(var1[i])
        print('Total length: '+str(totallength))
        var1 = list(lines[13:18])
        del (var1[2])
        var1 = ''.join(var1)
        print('Identification: 0x'+var1)
        print('TCP: '+lines[28:30])
        var1 = list(lines[31:36])
        del(var1[2])
        var1 = ''.join(var1)
        print('Header checksum: 0x'+var1)


    def line_three(lines):
        var1 = list(lines[13:18])
        del(var1[2])
        total_length = 0
        for i in range(len(var1)-1, -1, -1):
            if var1[i] in ['a', 'b', 'c', 'd', 'e', 'f']:
                total_length += (16**(len(var1)-1-i))*int(Data_print.charlist[var1[i]])
            elif var1[i] == ' ' :
                continue
            else:
                total_length += (16**(len(var1)-1-i))*int(var1[i])
        print('Source Port: '+str(total_length))
        var1 = list(lines[19:24])
        del (var1[2])
        total_length = 0
        for i in range(len(var1)-1, -1, -1):
            if var1[i] in ['a', 'b', 'c', 'd', 'e', 'f']:
                total_length += (16**(len(var1)-1-i))*int(Data_print.charlist[var1[i]])
            elif var1[i] == ' ' :
                continue
            else:
                total_length += (16**(len(var1)-1-i))*int(var1[i])
        print('Destination Port: '+str(total_length))


file_url = open('sample.txt','r')
line1 = file_url.readline()
line2 = file_url.readline()
line3 = file_url.readline()

first_object = Data_print

first_object.line_one(line1)
first_object.line_two(line2)
first_object.ip_convert('Source IP: ',line2[30:41])
dest_ip = (str(line2[42:48]).strip()+' '+str(line3[0:5]).strip()).strip()
first_object.ip_convert('Destination IP: ', dest_ip)
first_object.line_three(line3)
file_url.close()
