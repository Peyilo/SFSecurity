### SO库逆向 -- 菠萝包轻小说中的SFSecurity

#### 逆向分析

通过抓包分析APP的请求可知，每次请求都要在请求中加入一个特殊的请求头。

该请求头格式如下：

```
SFSecurity: nonce=6E72CFB2-2DE1-4123-A4B1-8EF4D9414A62&timestamp=1712106953992
			&devicetoken=a&sign=51A02F1DC8EEDF6B4E10BD07981F634C
```

请求头的值可以分为四个部分，nonce、timestamp、devicetoken、sign

- none：随机生成UUID字符串
- timestamp：当前时间戳
- devicetoken：设备标识
- sign：签名，用来验证请求的有效性

其中，none、timestamp、devicetoken很容易就可以获得。而对于sign，由于sign是一个32位的字符串，初步推测是MD5加密后的结果。

解压APK文件，在lib文件夹下可以找到一个libsfdata.so的库文件。使用IDA打开so库文件，在库文件中发现存在MD5加密算法的函数。初步验证了sign采用了MD5加密算法的推测。

破解MD5加密算法关键就在于如何获取所加的盐值salt。

脱去APK文件的壳，可以找到一个Java本地方法，签名为：

```java
private native String getSFSecurity(Context context, String str);
```

同时，可以在libsfdata.so文件中发现相应的JNI函数签名：

```c
Java_com_sf_security_AuthConfig_getSFSecurity(JNIEnv *env, jobject obj, ...)
```

借助unidbg库，直接调用so库文件中getSFSecurity函数。输入为a时，输出为

```
nonce=6E72CFB2-2DE1-4123-A4B1-8EF4D9414A62&timestamp=1712106953992
&devicetoken=a&sign=51A02F1DC8EEDF6B4E10BD07981F634C
```

虽然生成了有效的sign，但是具体生成过程是黑盒的，只能再换一种方式



在MD5加密算法过程中，会有个transform的过程。在so库文件中该函数的位置打上一个断点，并在断点处读取内存中的数据，转化为字符串，屏幕输出出来。

```java
// 0xb4b4是MD5::Transform函数在so库文件中的地址
debugger.addBreakPoint(module, 0xb4b4 + 1, (emulator1, address) -> {
    System.out.println("Debugger:");
    // 读取从内存地址0xbffff3b9L开始的64byte字节
    byte[] bytes = backend.mem_read(0xbffff3b9L, 64);	
    String s = new String(bytes);
    System.out.println(s);
    System.out.println(Arrays.toString(bytes));
    return true;
});
```

<img src="./pic/1.png"/>

程序在断点处执行了两次，因此屏幕输出了两次，输出结果如下：

```
13080C7A-A2EE-44E5-8B9B-CAC3F4FF7DFD1712283793341aFN_Q29XHVmfV3m
```

```
YX�                                                           
```

存在部分乱码，但是可以看到非乱码的字符存在一个规律

```
13A3008B-A427-45A2-B54B-36082BC347B41712126046742aFN_Q29XHVmfV3m
```

这个字符串是由UUID=“13A3008B-A427-45A2-B54B-36082BC347B4”、timestamp="1712126046742"、devicetoken="a"和一段未知的字符串"FN_Q29XHVmfV3m"拼接而成。

显然，末尾的未知字符串就是MD5加密算法用到的盐值salt。

使用salt="FN_Q29XHVmfV3m"来验证sign，发现并不匹配。又注意到，屏幕输出了两次，第二次输出时有段字符“YX”。推测MD5的transform过程中，使用的定长为64的数组，由于字符串过长，分成了两次进行transform。将“FN_Q29XHVmfV3m”和"YX"拼接起来作为盐值salt="FN_Q29XHVmfV3mYX"再进行验证。

验证成功。菠萝包轻小说的MD5加密算法所添加的盐值salt就是“FN_Q29XHVmfV3mYX”

#### SFSecurity的生成方式

```java
protected String getSFSecurity() {
    String nonce = UUID.randomUUID().toString();
    String timestamp = System.currentTimeMillis() + "";
    String sign = SecurityUtils.getMD5Str(nonce, timestamp, deviceToken, salt);
    return "nonce=" + nonce + "&timestamp=" + timestamp + "&devicetoken=" + deviceToken
        + "&sign=" + sign.toUpperCase();
}
```

nonce为随机生成的UID字符串，timestamp是当前时间戳，devicetoken是设备唯一标识字符串。最后再对none、timestamp、devicetoken拼接起来得到的字符串使用MD5加密算法，所添加的盐值salt为“FN_Q29XHVmfV3mYX”，并将加密后的byte数组转化为字符串，并将该字符串全部转为大写，最后该字符串即sign的值。

#### 注意

菠萝包轻小说5.0版本后的盐值salt为"FN_Q29XHVmfV3mYX"

5.0版本之前的盐值salt为“FMLxgOdsfxmN!Dt4"（其实在更早的版本，还存在第三个盐值）

