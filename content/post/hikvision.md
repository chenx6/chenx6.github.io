+++
title = "海康威视 固件格式/历史漏洞 分析"
date = 2023-03-11
[taxonomies]
tags = ["re"]
+++

高中时候曾经当过一段时间的脚本小子，通过 CVE-2017-7921 拿下过一波摄像头，体验了一把游戏里看门狗的感觉。所以在今天，在掌握了一定的技术之后，我将尝试对海康威视的固件进行重新分析。

## 固件格式

海康威视的固件可能有几种格式。在对文件开头进行 xor 运算之后，得到的文件开头如果是 0x484b5753("HKWS") 的话，那么固件本身是没有被加密的，可以通过文件头，得到固件中包含的文件名字和文件偏移。有一种格式是文件开头为 0x484b3230(HK02)，再通过 xor 运算解密后面的文件内容时，才会出现 0x484b5753 字段，如下图所示。

```txt
Magic: 484b3230, Size: 152, Checksum: 29ca, Count: 0
 0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f  0123456789abcdef
30 32 4b 48 ca 29 00 00 98 00 00 00 00 00 00 00  02KHÊ           
82 1d 53 01 02 00 00 00 ff ff ff ff ff ff ff ff    S     ÿÿÿÿÿÿÿÿ
ff ff ff ff ff ff ff ff ff ff ff ff 31 31 34 30  ÿÿÿÿÿÿÿÿÿÿÿÿ1140
30 35 30 30 33 31 31 31 31 31 31 30 30 31 31 00  050031111110011 
31 31 34 30 30 35 30 30 33 31 31 31 31 31 31 30  1140050031111110
30 31 31 00 00 00 00 00 00 00 00 00 00 00 00 00  011             
98 00 00 00 ed 4c 84 00 d7 ad a4 3d 31 31 34 30      íL      1140
30 35 30 30 33 31 31 31 31 31 31 30 30 31 31 00  050031111110011 
00 00 00 00 00 00 00 00 00 00 00 00 85 4d 84 00               M  
fd cf ce 00 04 58 8b 66    
Magic: 484b5753, Size: 240, Checksum: 27e5, Count: 4
 0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f  0123456789abcdef
53 57 4b 48 e5 27 00 00 f0 00 00 00 04 00 00 00  SWKHå   ð       
01 00 00 00 02 00 00 00 01 00 00 00 ff ff ff ff              ÿÿÿÿ
ed 4c 84 00 48 99 02 00 29 00 04 05 31 31 34 30  íL  H       1140
30 35 30 30 33 31 31 31 31 31 31 30 30 31 31 00  050031111110011 
5f 63 66 67 55 70 67 53 65 63 50 6c 73 00 00 00   cfgUpgSecPls   
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00                  
f0 00 00 00 f4 01 00 00 31 e6 00 00 5f 63 66 67  ð   ô   1æ   cfg
```

当然我还碰到了第三种情况，文件的开头是 0x484b3230，而文件后的新文件头为 0x484b3330(HK03) 这种情况下新文件头和固件中的文件是使用 AES-256-ECB 进行加密的。这种情况得需要拆机提取密钥，才能对文件进行解密。

```txt
Magic: 484b3230, Size: 108, Checksum: 2902, Count: 0
 0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f  0123456789abcdef
30 32 4b 48 02 29 00 00 6c 00 00 00 00 00 00 00  02KH    l       
be e9 e9 01 01 00 00 00 ff ff ff ff ff ff ff ff  ¾éé     ÿÿÿÿÿÿÿÿ
ff ff ff ff ff ff ff ff ff ff ff ff 31 32 30 30  ÿÿÿÿÿÿÿÿÿÿÿÿ1200
30 35 30 30 33 31 31 31 31 31 31 30 30 31 31 00  050031111110011 
31 32 30 30 30 35 30 30 33 31 31 31 31 31 31 30  1200050031111110
30 31 31 00 fb e5 46 5f 06 cc 44 d1 01 aa 09 ff  011 ûåF  ÌDÑ ª ÿ
6c 00 00 00 52 e9 e9 01 b9 d8 09 f4
Magic: 484b3330, Size: 3776, Checksum: 7e09e7ea, Count: 55
 0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f  0123456789abcdef
30 33 4b 48 ea e7 09 7e c0 0e 00 00 37 00 00 00  03KHêç  À   7   
01 00 00 00 02 00 00 00 01 00 00 00 00 03 f1 07                ñ 
5e cf d7 7d 52 e9 e9 01 e5 9a 02 00 00 00 05 05   Ï  Réé å       
00 00 00 00 5c 2c 5a 25 fa 96 56 cd 00 00 00 00        Z ú VÍ    
79 61 6f 6a 75 6e 6a 69 65 00 fb e5 46 5f 06 cc  yaojunjie ûåF  Ì
44 d1 01 aa 09 ff cb 4c 07 3a 52 00 64 4b b1 1f  DÑ ª ÿËL  R dK  
25 00 2b cf 38 a7 00 7e e2 ed 00 5b 05 db 97 c9     Ï8   âí   Û É
ce 78 ad 04 1c df 3b 44 0a ba 06 0e b4 71 ed 54  Îx   ß D º   qíT
fb e5 46 5f 06 cc 44 d1 01 aa 09 ff cb 4c 07 3a  ûåF  ÌDÑ ª ÿËL  
52 00 64 4b b1 1f 25 00 2b cf 38 a7 00 7e e2 ed  R dK     Ï8   âí
00 5b 05 db 97 c9 ce 78 ad 04 1c df 3b 44 0a ba     Û ÉÎx   ß D º
06 0e b4 71 ed 54 c1 44 08 89 0d 55 ba 2a 35 13     qíTÁD   Uº 5 
08 a2 3b 00 52 f3 e0 19 90 20 bd 57 d7 0d bb 46      Róà   ½W   F
42 ca da 35 ad e8 79 75 d5 00 d7 56 26 77 6e 61  BÊÚ5 èyuÕ  V wna
31 32 30 30 30 35 30 30 33 31 31 31 31 31 31 30  1200050031111110
30 31 31 00 fb e5 46 5f 06 cc 44 d1 01 aa 09 ff  011 ûåF  ÌDÑ ª ÿ
5f 63 66 67 55 70 67 43 6c 61 73 73 00 74 fd e8   cfgUpgClass týè
40 86 67 2d 7c 07 37 57 57 3d c9 d3 37 70 bc 02    g   7WW ÉÓ7p¼ 
c0 0e 00 00 64 02 00 00 78 5e 63 cc 74 fd e8 40  À   d   x cÌtýè 
86 67 2d 7c 07 37 57 57 3d c9 d3 37 70 bc 02 5e   g   7WW ÉÓ7p¼  
68 49 6d 61 67 65 00 74 fd e8 40 86 67 2d 7c 07  hImage týè  g  
```

解密后的文件格式可以参考 [Refs](#refs) 中的 "(转载文章)Hik or hack? (NOT) IoT Security Using Hikvision IP Cameras"，解密固件可以参考 [Refs](#refs) 中的 "HaToan/Decrypt-Firmware-Hikvision" 和 "MatrixEditor/hiktools" 项目。

> 在 Refs 我还放了 hikpack 的下载链接，hikpack 可以解密 r0,r1,r6,g0 设备的固件。我本来想看下 hikpack 是怎么进行文件解密的，但是 hikpack 居然用了 OLLVM 混淆，有必要吗...

## CVE-2017-7921

从 packetstormsecurity 上的邮件可以看到绕过 HIKCGI 权限验证的方法，只要在链接上加上一串以 base64 编码后的 `"username:password"`，就可以绕过权限检查了。

```txt
Vulnerability details:
----------------------
Hikvision camera API includes support for proprietary HikCGI protocol, which exposes URI endpoints through the camera's web interface. The HikCGI protocol handler checks for the presence of a parameter named "auth" in the query string and if that parameter contains a base64-encoded "username:password" string, the HikCGI API call assumes the idntity of the specified user. The password is ignored.

Virtually all Hikvision products come with a superuser account named "admin", which can be easily impersonated.  For example:

Retrieve a list of all users and their roles:
    http://camera.ip/Security/users?auth=YWRtaW46MTEK

Obtain a camera snapshot without authentication:
    http://camera.ip/onvif-http/snapshot?auth=YWRtaW46MTEK
```

在物理机器上通过 "netstat" 发现处理 HTTP 请求的是 davinci 程序，通过 hikpack 提取并进行解密（！） "davinci.tar.gz" 后得到 davinci 程序。

> binwalk -Me 解压未加密的固件时，不一定能得到 "davinci.tar.gz" 这个文件，是因为这个文件被加密了，没有留下 gzip 文件的特征。

在 5.4.1 版本固件中的 davinci 程序中的相关代码如下。可以从代码中发现，程序从 url 中读取 "auth" 参数的值，并对值进行 base64 解码，将解码后的参数通过 ":" 分割，如果参数中有 password 的话就进入 `sub_34A03C` 进行校验，最后跳转到 LABEL_2 代表着认证完成。`sub_34A03C` 函数中未对密码进行校验（至少我看不出来），所以只要 username 填一个存在的用户名就可以绕过认证，例如 root。

在 5.4.5 版本的 `hikcgiHandler` 中海康删除了这段代码来修复这个漏洞。

```c
int __fastcall hikcgiHandler(int a1) {
  // ...
  if ( !sub_2AF560(*(_DWORD *)(*(_DWORD *)(v23 + 124) + 32), "auth", param) )
  {
    param_len = strlen(param);
    base64_decode((int)param, param_len, (int)dec_param);// => EVP_DecodeBlock
    pass = strchr(dec_param, ':');
    if ( pass )
    {
      *pass = 0;
      sub_34A03C(v22, dec_param, pass + 1);
      goto LABEL_2;
    }
  }
  // ...
}
```

## CVE-2018-6414

这个漏洞只有网上的一篇文章提到过，然后原文失效了，只能看到一篇翻译的很烂的译文。不过根据截图，我们还是可以通过 搜索汇编/查找 `sscanf` 的 xref ，在 5.5.0 版本的固件中，来定位到相应的代码。

```asm
.text:0024A24E                 MOV             R1, R4  ; c
.text:0024A250                 MOVS            R2, #0x10 ; n
.text:0024A252                 ADD             R0, SP, #0x3A8+s1 ; s
.text:0024A254                 BLX             memset
.text:0024A258                 MOV             R1, R4  ; c
.text:0024A25A                 MOVS            R2, #0x15 ; n
.text:0024A25C                 ADD             R0, SP, #0x3A8+var_350 ; s
.text:0024A25E                 BLX             memset
.text:0024A262                 ADD             R0, SP, #0x3A8+var_27C ; s
.text:0024A264                 MOV             R1, R4  ; c
.text:0024A266                 MOVS            R2, #0x41 ; 'A' ; n
.text:0024A268                 BLX             memset
.text:0024A26C                 LDR.W           R0, [R8,#0x10]
.text:0024A270                 CBZ             R0, loc_24A27A
.text:0024A272                 LDR             R1, =aTimestampS ; "timeStamp=%s"
.text:0024A274                 ADD             R2, SP, #0x3A8+s1
.text:0024A276                 BLX             __isoc99_sscanf
```

看反编译可以看到，程序中在 `sscanf` 函数中使用了 "%s" 参数将用户输入读入栈中，并且未对输入长度进行限制。

```c
int __fastcall isapi_session_login_basic(int a1, _DWORD *a2, int a3, int a4, int a5) {
  // ...
  char s1[16]; // [sp+30h] [bp-378h] BYREF
  // ...
  memset(s1, 0, sizeof(s1));
  memset(v61, 0, 0x15u);
  memset(v66, 0, 0x41u);
  v6 = a2[4];
  if ( v6 )
    _isoc99_sscanf(v6, "timeStamp=%s", s1);
  // ...
}
```

在 davinci 程序中处理 HTTP 请求的框架是 appweb。通过 appweb 源代码定位到 `maCreateHttp` 和 `initLimits` 函数，发现在 davinci 中，URL 的长度限制为 0x400。

```c
_DWORD *__fastcall maCreateHttp(int a1)
{
  // ...
    v2[12] = 0x400;
    v2[11] = 0xA00000;
  // ...
}
```

可以发现 s1 在 [bp-378h] 的位置，而 URL 的长度为 0x400，如果输入长度为 0x400 的 URL 就会导致栈溢出。理论上通过 ROP 即可达成利用。

## CVE-2021-36260

在 5.4.5 版本的固件中，出现漏洞的代码如下。可以看到程序使用了格式化字符串拼接命令，并且未对用户输入进行过滤，造成命令注入。具体的利用方法请参考 [Refs](#refs) 中的 "hikvision CVE-2021-36260 分析以及教训"

> 在 5.5 版本的固件中，海康加入了 `filter_quotation_and_punctuation_mark` 函数来过滤用户输入，但是还是可以通过 "$()" 进行绕过，直到漏洞爆出后加入了 `hwif_is_all_language_character_legal` 函数才完全修复。

```c
int __fastcall hwif_language_load(const char *a1)
{
  char s[32]; // [sp+10h] [bp-138h] BYREF
  char v4[280]; // [sp+30h] [bp-118h] BYREF

  memset(s, 0, sizeof(s));
  if ( a1 )
  {
    if ( strlen(a1) <= 5 )
    {
      snprintf(s, 0x1Fu, "%s%s", "/home/webLib/doc/i18n/", a1);
      if ( !sub_103538(s) )
      {
        dev_debug_v1(5, 38, "hardwareif/r6_s2lm/unihardwareif.c", 482, "hwif_language_load", "%s exist!\n", s);
        return 0;
      }
      memset(s, 0, sizeof(s));
      snprintf(s, 0x1Fu, "/dav/IElang.tar %s.tar.gz", a1);
      memset(v4, 0, 0x100u);
      snprintf(
        v4,
        0xFFu,
        "tar -xf %s -C %s; tar -zxf %s%s.tar.gz -C %s",
        s,
        "/home/webLib/doc/i18n/",
        "/home/webLib/doc/i18n/",
        a1,
        "/home/webLib/doc/i18n/");
      if ( system(v4) >= 0 )
      // ...
```

## 总结

从开发的角度来说，这三个漏洞都是完全可以避免的漏洞，第二个漏洞可以通过给格式化字符串加上长度限制，例如 "%16s"，来防止栈溢出。第三个漏洞可以通过加强对用户输入的校验，或者使用 "fork + execve" 进行执行程序，而不是使用 system 函数，来规避命令注入。

从漏洞挖掘的角度来说，可以去追踪 system, popen 等函数的输入用户是否可控，来发现命令注入漏洞。通过加强污点分析，或者人肉分析 "scanf", "gets" 等和内存直接交互的函数，判断用户输入是否会影响内存中的数据存取，从而发现栈溢出漏洞和命令注入漏洞。

## Refs

- [(转载文章)Hik or hack? (NOT) IoT Security Using Hikvision IP Cameras](https://sudonull.com/post/64821-Hik-or-hack-NOT-IoT-Security-Using-Hikvision-IP-Cameras-NeoBIT-Blog)
- <https://ipcamtalk.com/threads/mcr-hikvision-packer-unpacker-for-5-3-x-and-newer-firmware.15710/page-15#post-387358>
- <https://github.com/HaToan/Decrypt-Firmware-Hikvision>
- <https://github.com/MatrixEditor/hiktools/>
- [Hikvision IP Camera Access Bypass](https://packetstormsecurity.com/files/144097/Hikvision-IP-Camera-Access-Bypass.html)
- <https://blog.vdoo.com/2018/11/13/significant-vulnerability-in-hikvision-cameras/>
  - [虹科案例 | 安全性防护平台-海康威视摄像机中的重大漏洞](https://zhuanlan.zhihu.com/p/381909279)
- [hikvision CVE-2021-36260 分析以及教训](http://www.f0und.icu/article/31.html)
