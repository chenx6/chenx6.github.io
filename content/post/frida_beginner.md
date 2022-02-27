# Frida 在一次离谱比赛中的应用

在某次离谱比赛中，我使用了 Frida 解出了题目，下面是一些简单的笔记。

> 在 2021 年 10 月 24 日，我浪费了2小时的时间解出了一个某弹幕网站办的比赛的离谱安卓题，解出之后的内心就是：rnm，退时间！更加嘲讽的是，他还在一个月后转给了我 0.56 元作为奖励！
>
> 那天比较欣慰的是在某弹幕网站上看完了 A·ZU·NA 的 FMT（

## 第一关

首先找到程序入口点，可以直接看到程序的逻辑，就是将用户输入的帐号和密码用 `Encrypt.a` 和 `Encrypt.b` 进行加密，然后对比内容。那接下来就直接照抄一遍加密函数中的代码进行反向解密。

```java
public class MainActivity extends AppCompatActivity {
    // ...
    public void onClick(View view) {
        String obj = ((EditText) MainActivity.this.findViewById(R.id.TextAccount)).getText().toString();
        String obj2 = ((EditText) MainActivity.this.findViewById(R.id.TextPassword)).getText().toString();
        byte[] b = Encrypt.b(Encrypt.a(obj.getBytes(), 3));
        byte[] b2 = Encrypt.b(Encrypt.a(obj2.getBytes(), 3));
        byte[] bArr = {89, 87, 66, 108, 79, 109, 90, 110, 78, 106, 65, 117, 79, 109, 74, 109, 78, 122, 65, 120, 79, 50, 89, 61};
        if (!Arrays.equals(b, new byte[]{78, 106, 73, 49, 79, 122, 65, 51, 89, 71, 65, 117, 78, 106, 78, 109, 78, 122, 99, 55, 89, 109, 85, 61}) || !Arrays.equals(b2, bArr)) {
            Toast.makeText(MainActivity.this, "还差一点点~~~", 1).show();
        } else {
            Toast.makeText(MainActivity.this, "bilibili- ( ゜- ゜)つロ 乾杯~", 1).show();
        }
    }
    // ...
}
```

下面是解密脚本。

```python
from base64 import b64decode

enc_username = [
    78,
    106,
    73,
    49,
    79,
    122,
    65,
    51,
    89,
    71,
    65,
    117,
    78,
    106,
    78,
    109,
    78,
    122,
    99,
    55,
    89,
    109,
    85,
    61,
]
enc_password = [
    89,
    87,
    66,
    108,
    79,
    109,
    90,
    110,
    78,
    106,
    65,
    117,
    79,
    109,
    74,
    109,
    78,
    122,
    65,
    120,
    79,
    50,
    89,
    61,
]


def dec(enc: list[int]):
    dec1 = "".join(map(chr, enc))
    dec2 = b64decode(dec1)
    dec3 = "".join(map(lambda x: chr(x ^ 3), dec2))
    return dec3


print(dec(enc_username))
print(dec(enc_password))

```

## 第二关

没想到吧，还有第二关。只剩下 `libMylib.so` 没分析过了。根据 Java 层的代码，第二关应该在 `Mylib` 的 `i` 函数中。

```java
public native String i();

static {
    System.loadLibrary("Mylib");
}
```

函数的开头就是调用了 `__system_property_get` 函数进行对比结果。

```c
  __system_property_get("ro.product.cpu.abi", res1);
  __system_property_get("ro.build.version.release", res2);
  if ( *(_DWORD *)res1 == 0x363878 && *(unsigned __int16 *)res2 == 0x39 )
  {
      // ...
  }
```

在网上进行查询后，我使用 `Memory.readCString` 读取函数的参数，然后根据参数，使用 `Memory.writeByteArray` 写入不同的结果。

```javascript
// hook system_property_get
let funcAddr = Module.findExportByName("libc.so", "__system_property_get");
console.log("[*] spg addr is %x", funcAddr);
Interceptor.attach(funcAddr, {
    arg0: "",
    arg1: 0,
    onEnter: function (args) {
        let arg0 = Memory.readCString(args[0]);
        console.log("[*] arg0", arg0);
        if (arg0 === "ro.product.cpu.abi") {
            this.arg0 = arg0;
            this.arg1 = args[1];
        } else if (arg0 === "ro.build.version.release") {
            this.arg0 = arg0;
            this.arg1 = args[1];
        }
    },
    onLeave: function (retval) {
        if (this.arg0 === "ro.product.cpu.abi") {
            Memory.writeByteArray(this.arg1, [0x78, 0x38, 0x36, 0x0]);
        } else if (this.arg0 === "ro.build.version.release") {
            Memory.writeByteArray(this.arg1, [0x39, 0x0, 0x0, 0x0]);
        }
        console.log("[*] ret", retval);
    }
});
```

接下来的代码就非常的直接了，就是检查 `/data/2233` 文件是否存在，如果存在就解密内容，写入到文件中。

```c
v1 = fopen("/data/2233", "r");
if ( v1 )
{
    fclose(v1);
    strcpy((char *)encrypt, "bili_2233_3322");
    strcpy((char *)encrypt2, "bili_3322_2233");
    *(_OWORD *)context.count = xmmword_1F60;
    *(_QWORD *)&context.state[2] = 0x1032547698BADCFELL;
    v2 = __strlen_chk((const char *)encrypt, 0xFuLL);
    EU(&context, encrypt, v2);
    *(_DWORD *)res3 = context.count[0];
    v24 = context.count[1];
    v3 = (context.count[0] >> 3) & 0x3F;
    if ( v3 >= 0x38 )
    v4 = 120;
    else
    v4 = 56;
    EU(&context, PADDING, v4 - v3);
    EU(&context, res3, 8u);
    *(_DWORD *)decrypt = context.state[0];
    *(_OWORD *)v15.count = xmmword_1F60;
    *(_QWORD *)&decrypt[4] = *(_QWORD *)&context.state[1];
    *(_DWORD *)&decrypt[12] = context.state[3];
    *(_QWORD *)&v15.state[2] = 0x1032547698BADCFELL;
    v5 = __strlen_chk((const char *)encrypt2, 0xFuLL);
    EU(&v15, encrypt2, v5);
    v6 = (v15.count[0] >> 3) & 0x3F;
    *(_DWORD *)res3 = v15.count[0];
    v24 = v15.count[1];
    if ( v6 >= 0x38 )
    v7 = 120;
    else
    v7 = 56;
    EU(&v15, PADDING, v7 - v6);
    EU(&v15, res3, 8u);
    *(_DWORD *)decrypt2 = v15.state[0];
    *(_QWORD *)&decrypt2[4] = *(_QWORD *)&v15.state[1];
    *(_DWORD *)&decrypt2[12] = v15.state[3];
    v10 = fopen("/data/2233", "a+");
    if ( v10 )
    {
        for ( i = 0LL; i != 8; ++i )
        {
            ZL7sprintfPcU17pass_object_size1PKcz(res3, v8, v9, decrypt[i]);
            ZL7sprintfPcU17pass_object_size1PKcz(dest, v12, v13, decrypt2[i]);
            fputs((const char *)res3, v10);
            fputs((const char *)dest, v10);
        }
        fwrite("-----------\n", 0xCuLL, 1uLL, v10);
    }
    fclose(v10);
}
```

很显然，作为一个普通的程序是不能直接写入 `/data` 文件夹的，所以得通过 hook 让他写到别的地方去。代码非常简单粗暴，将 `fopen` 的第一个参数 "/data/2233" 换成 '/data/local/tmp/2233'，然后返回一个错误的 fd 给他，让代码继续执行。

```javascript
// hook fopen
funcAddr = Module.findExportByName("libc.so", "fopen");
console.log("[*] fopen addr", funcAddr)
Interceptor.attach(funcAddr, {
    arg0: "",
    onEnter: function (args) {
        let arg0 = Memory.readCString(args[0]);
        console.log("[*] arg0", arg0);
        if (arg0 === "/data/2233") {
            Memory.protect(args[0], 16, 'rwx');
            args[0].writeUtf8String('/data/local/tmp/2233');
            console.log("[+] replaced by", Memory.readCString(args[0]));
        } else if (arg0 === "/data/local/tmp/2233") {
            this.arg0 = arg0;
        }
    },
    onLeave: function (retval) {
        if (this.arg0 === "/data/local/tmp/2233") {
            retval.replace(123);
        }
        console.log("[*] ret", retval);
    }
});
```

在上面这么 hook 之后，后面的 `fputs` 必定会错误，所以我们直接使用 Frida 将 `fputs` 替换成自己实现的函数，直接输出 `fputs` 的内容。

```javascript
// replace fputs
funcAddr = Module.findExportByName("libc.so", "fputs");
const fopen = new NativeFunction(funcAddr, 'int', ['pointer', 'pointer']);
Interceptor.replace(funcAddr, new NativeCallback((strPtr, filePtr) => {
    let str = Memory.readCString(strPtr);
    console.log('[*] fputs', str);
    return str.length;
}, 'int', ['pointer', 'pointer']));
```

> 最直观的方法让上一步返回一个真实文件的 FD，但是没有找到相关的代码，所以只能折中采用这种方式进行 Hook。

由于程序中没有任何一个地方调用 `i` 函数，所以调用一下进行解密。

```javascript
Java.perform(() => {
    Java.choose("com.example.test.MainActivity", {
        onMatch: function (instance) {
            console.log("[+] onMatch");
            let ret = instance.i();
            console.log("[*] ret=", ret);
        },
        onComplete: function () {
            console.log("[+] onComplete");
        }
    });
});
```

## 最终代码

```javascript
/**b13981f45ae996d4bc04be5b34662a78*/

// hook system_property_get
let funcAddr = Module.findExportByName("libc.so", "__system_property_get");
console.log("[*] spg addr is %x", funcAddr);
Interceptor.attach(funcAddr, {
    arg0: "",
    arg1: 0,
    onEnter: function (args) {
        let arg0 = Memory.readCString(args[0]);
        console.log("[*] arg0", arg0);
        if (arg0 === "ro.product.cpu.abi") {
            this.arg0 = arg0;
            this.arg1 = args[1];
        } else if (arg0 === "ro.build.version.release") {
            this.arg0 = arg0;
            this.arg1 = args[1];
        }
    },
    onLeave: function (retval) {
        if (this.arg0 === "ro.product.cpu.abi") {
            Memory.writeByteArray(this.arg1, [0x78, 0x38, 0x36, 0x0]);
        } else if (this.arg0 === "ro.build.version.release") {
            Memory.writeByteArray(this.arg1, [0x39, 0x0, 0x0, 0x0]);
        }
        console.log("[*] ret", retval);
    }
});

// hook fopen
funcAddr = Module.findExportByName("libc.so", "fopen");
console.log("[*] fopen addr", funcAddr)
Interceptor.attach(funcAddr, {
    arg0: "",
    onEnter: function (args) {
        let arg0 = Memory.readCString(args[0]);
        console.log("[*] arg0", arg0);
        if (arg0 === "/data/2233") {
            Memory.protect(args[0], 16, 'rwx');
            args[0].writeUtf8String('/data/local/tmp/2233');
            console.log("[+] replaced by", Memory.readCString(args[0]));
        } else if (arg0 === "/data/local/tmp/2233") {
            this.arg0 = arg0;
        }
    },
    onLeave: function (retval) {
        if (this.arg0 === "/data/local/tmp/2233") {
            retval.replace(123);
        }
        console.log("[*] ret", retval);
    }
});

// replace fputs
funcAddr = Module.findExportByName("libc.so", "fputs");
const fopen = new NativeFunction(funcAddr, 'int', ['pointer', 'pointer']);
Interceptor.replace(funcAddr, new NativeCallback((strPtr, filePtr) => {
    let str = Memory.readCString(strPtr);
    console.log('[*] fputs', str);
    return str.length;
}, 'int', ['pointer', 'pointer']));

// Invoke i
Java.perform(() => {
    Java.choose("com.example.test.MainActivity", {
        onMatch: function (instance) {
            console.log("[+] onMatch");
            let ret = instance.i();
            console.log("[*] ret=", ret);
        },
        onComplete: function () {
            console.log("[+] onComplete");
        }
    });
});
```

## 后记

得到解密的结果后还得加上 '-' 作为分隔符，才能正确提交，然而题目中也没有提示...

## Refs

- [javascript-api](https://frida.re/docs/javascript-api/)
- [使用 Frida Hook 不同类型的函数（失效文章）](https://www.cnblogs.com/shlyd/p/14726850.html)
