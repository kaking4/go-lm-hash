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
