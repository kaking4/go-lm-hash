# go-lm-hash

#### 使用go生成lmhash的值
#### LM Hash

LM Hash的全称为LAN Manager Hash，这是windows中最早用的加密算法

LM Hash的计算方式：

- 用户的密码被限制为最多14个字符。
- 用户的密码转换为大写。
- 密码转换为16进制字符串，不足14字节将会用0来再后面补全。
- 密码的16进制字符串被分成两个7byte部分。每部分转换成比特流，并且长度位56bit，长度不足使用0在左边补齐长度，再分7bit为一组末尾加0，组成新的编码（str_to_key()函数处理）
- 上步骤得到的8byte二组，分别作为DES key为"KGS!@#$%"进行加密。
- 将二组DES加密后的编码拼接，得到最终LM HASH值。

测试服务密码：`1234567`

- 用户的密码被限制为最多14个字符
- 用户的密码转换为大写，大写转换后仍为它本身
- 转换为16进制字符串后，结果为31323334353637，不足14字节采用0进行补全，补全结果为3132333435363700000000000000
- 固定长度的密码被分成两个7byte部分，也就是分为31323334353637和00000000000000，
  先把31323334353637转换为比特流，比特流为110001001100100011001100110100001101010011011000110111，长度不足56bit使用0在左边补齐长度，补齐后为00110001001100100011001100110100001101010011011000110111。
  再分7bit为一组末尾加0，组成新的编码，如下：

`0011000010011000100011000110011001000010101010001101100001101110`

对应的8字节16进制编码（str_to_key()函数处理）：`30988C6642A8D86E`，同理知`00000000000000`对应的8字节16进制编码： `0000000000000000`

得到的两组16进制字符串，分别作为DES加密key为魔术字符串`KGS!@#$%`进行加密
##### go实现lm hash计算代码

```go
package main

import (
    "bytes"
    "crypto/cipher"
    "crypto/des"
    "encoding/hex"
    "fmt"
    "strconv"
    "strings"
)


func DesEncrypt(str string, Des_Key []byte) string {
    block, err := des.NewCipher(Des_Key)
    if err != nil {
        panic(err)
    }

    // 如果明文不是8的倍数，需要进行填充
    padding := byte(8 - len(str)%8)
    padtext := bytes.Repeat([]byte{padding}, int(padding))
    plaintext := []byte(str)
    plaintext = append(plaintext, padtext...)

    ciphertext := make([]byte, len(plaintext))
    // ECB mode
    mode := cipher.NewCBCEncrypter(block, make([]byte, 8))
    mode.CryptBlocks(ciphertext, plaintext)

    return hex.EncodeToString(ciphertext)
}

func strtoHex(str string)(strkey []byte){
	//将str转换为hex
    byteArr, err := hex.DecodeString(str)
    if err != nil {
        panic(err)
    }
    return byteArr
}


func binaryToHex(binaryStr string) string {
    //二进制转hex
    var hexStr strings.Builder
    for i := 0; i < len(binaryStr); i += 4 {
        binary := binaryStr[i:min(i+4, len(binaryStr))]
        num, _ := strconv.ParseInt(binary, 2, 64)
        hex := fmt.Sprintf("%X", num)
        hexStr.WriteString(hex)
    }
    return hexStr.String()
}

func min(a, b int) int {
    //比较大小
    if a < b {
        return a
    }
    return b
}

func split(bit1 string) (alist string) {
    alist = ""
    for _, ch := range bit1 {
        digit := ch - '0'
        //fmt.Printf("%d ", digit)
        binary := strconv.FormatInt(int64(digit), 2)
        paddedBinary := fmt.Sprintf("%04s", binary)
        alist = alist+paddedBinary
        //fmt.Println(paddedBinary)
    }
    return alist
}

func main() {
    str := "123456"
    strBytes := []byte(str)
    hexString := hex.EncodeToString(strBytes)
    lenl := len(hexString)
    if lenl<=28 {
        for i:=0;i<=27-lenl;i++{
            hexString=hexString+"0"
        }
    }
    //转换为比特流，长度不足56bit使用0在左边补齐长度，补齐后，
    bit1 := hexString[:14]
    bit2 := hexString[14:]

    fmt.Println(bit1)
    alist := split(bit1)
    //再分7bit为一组末尾加0，组成新的编码
    binaryStr := alist[:7]+"0"+alist[7:14]+"0"+alist[14:21]+"0"+alist[21:28]+"0"+alist[28:35]+"0"+alist[35:42]+"0"+alist[42:49]+"0"+alist[49:56]+"0"
    blist  := split(bit2)
    binaryStr2 := blist[:7]+"0"+blist[7:14]+"0"+blist[14:21]+"0"+blist[21:28]+"0"+blist[28:35]+"0"+blist[35:42]+"0"+blist[42:49]+"0"+blist[49:56]+"0"
	//两组16进制字符串，分别作为DES加密key为魔术字符串KGS!@#$%进行加密
    hexStr := binaryToHex(binaryStr)
    hexStr2 := binaryToHex(binaryStr2)
    fmt.Println(hexStr)
    fmt.Println(len(alist))
    fmt.Println(len(hexString))
    a:= DesEncrypt("KGS!@#$%",strtoHex(hexStr))[:16]
    b:= DesEncrypt("KGS!@#$%",strtoHex(hexStr2))[:16]
    fmt.Println(a+b)
}
```
