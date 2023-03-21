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
