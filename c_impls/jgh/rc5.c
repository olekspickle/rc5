//
//  main.c
//  RC5
//
//  Created by jgh on 15/11/2.
//  Copyright © 2015年 jgh. All rights reserved.
//

//#include <stdio.h>
//
//int main(int argc, const char * argv[]) {
//    // insert code here...
//    printf("Hello, World!\n");
//    return 0;
//}


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>


int w=16;//字长
int r=12;//12;//轮数12
int b=16;//密钥长度
int t=26;//2*r+2=12*2+2=26
int c=8; //b*8/w = 16*8/16

typedef unsigned long int FOURBYTEINT;//四字节
typedef unsigned short int TWOBYTEINT;//2字节
typedef unsigned char BYTE;
void InitialKey(unsigned char* KeyK,int b);
void generateChildKey(unsigned char* KeyK,TWOBYTEINT* ChildKeyS);
void Encipher(TWOBYTEINT* In,TWOBYTEINT* Out,TWOBYTEINT* S);
void Decipher(TWOBYTEINT* In,TWOBYTEINT* Out,TWOBYTEINT* S);
#define NoOfData  4
/**2、Cyclic shift function 
    Since the cycle shift is performed during the process of generating the subkey, 
    encryption, and decryption, it is necessary to define the loop as a function first. 
    Loop left and right shift functions 
    x : The number of cycles
    y : The number of bits that will be looped
 */
#define ROTL(x,y) (((x)<<(y&(w-1))) | ((x)>>(w-(y&(w-1)))))
#define ROTR(x,y) (((x)>>(y&(w-1))) | ((x)<<(w-(y&(w-1)))))

/**3、    初始密钥产生函数
 生成一个初始的长度为b字节的密钥。
 产生初始密钥的函数
 */
void InitialKey(unsigned char* KeyK,int b)
{
    int i,j;
    for( i=0;i<b;i++)//初始化
    {
        KeyK[i]=0;
    }
    int intiSeed=3;
    KeyK[0]=intiSeed;
    for(j=1;j<b;j++)//生成
    {
        KeyK[j] = (BYTE) ( ((int)(pow(3,j))%(255-j)));
        //KeyK[j] = (BYTE) ( ((int)(pow(double(3),j))%(255-j)));
    }
}

/**4、    密钥扩展函数
 由于需加密r轮，每轮需要两个子密钥，所以需要密钥扩展函数根据初始密钥来扩展出2r+2个子密钥。
 产生子密钥的函数
 */
void generateChildKey(unsigned char* KeyK,TWOBYTEINT* ChildKeyS)
{
    //const double e = 2.718281828459;
    //const double Phia = 1.618033988749;
    int PW = 47073;//0xb7e1;
    int QW = 40503;//0x9e37;//genggai
    int i;
    TWOBYTEINT L[c];
    //初始化数组S
    ChildKeyS[0]=PW;
    for (i=1;i<t;i++)
    {
        ChildKeyS[i]=(ChildKeyS[i-1]+ QW);
    }
    
    //将K数组转换为L数组
    for(i=0;i<c;i++)//初始化L数组c=8
    {
        L[i]=0;
    }
    int u = w/8;
    for (i=b-1;i!=-1; i--)//转换，数组L每一元素长为32bit，数组K每一元素长为8bit
    {
        L[i/u] = (L[i/u]<<8)+KeyK[i];
    }
    for (i=0;i<c;i++)//16进制输出gaidong
    {
        printf("%.4X ",L[i]);
    }
    printf("\n");
    //产生子密钥，存储在ChildKeyS中
    TWOBYTEINT A,B,X,Y;
    A=B=X=Y=0;
    for(i=0;i<3*t;i++)
    {
        X = ChildKeyS[A] = ROTL(ChildKeyS[A]+X+Y,3);
        A = (A+1) % t;
        Y = L[B] = ROTL(L[B]+X+Y,(X+Y));
        B = (B+1) % c;
    }
    for (i=0;i<t;i++)//16进制输出
    {
        printf("%.4X ",ChildKeyS[i]);
    }
    printf("\n");
}
/**5、    加密函数
 加密函数
 */
void Encipher(TWOBYTEINT * In,TWOBYTEINT * Out,TWOBYTEINT* S)
{
    TWOBYTEINT X,Y; //定义两个32位存储器
    int i,j;
    for(j=0;j<NoOfData;j+=2)
    {
        X = In[j]+S[0];
        Y = In[j+1]+S[1];
        for( i=1;i<=r;i++)
        {
            X=ROTL((X^Y),Y) + S[2*i]; //异或，循环移位，相加
            Y=ROTL((Y^X),X) + S[2*i+1];
        }
        Out[j]=X;
        Out[j+1]=Y; //密文
    }
}
/**6、    解密函数
 解密函数
 */
void Decipher(TWOBYTEINT* In,TWOBYTEINT* Out,TWOBYTEINT* S)
{
    int i=0,j;
    TWOBYTEINT X,Y;
    for(j=0;j<NoOfData;j+=2)
    {
        X = In[j];
        Y = In[j+1];
        for(i=r;i>0;i--)
        {
//            Y = ROTR(Y-S[2*i+1],X)^X; //相减，循环移位，异或
//            X = ROTR(X-S[2*i],Y)^Y;
            
//            Y = ROTR(Y-S[2*i+1],X)^X; //相减，循环移位，异或
//            X = ROTR(X-S[2*i],Y)^Y;
//            改为（对数据进行强制转换）：
            Y = ROTR((unsigned short int)(Y-S[2*i+1]),X)^X;
            X = ROTR((unsigned short int)(X-S[2*i]),Y)^Y;
        }
        Out[j]=X - S[0];
        Out[j+1]=Y - S[1]; //明文
    }
}


/**7、    主函数测试
 
 主函数
 */
int main(void)
{
    TWOBYTEINT ChildKeyS[2*r+2]; //64bit
    TWOBYTEINT ChildKey1[26]={0x9b9a};
    //{0xe25b,0x4338,0x36ab,0xd59f,0x9b9a,0xc0f1,0xdc4f,
    // 0xc0d2,0xf03a,0xff5a,0x771f,0x5952,0xb797,0x28ad,
    //0x5c9a,0xfd9a,0xbd4b,0x3b12,0xd198,0x17f8,0x7f19,
    //0x458e,0x1629,0xaa8a,0xb609,0x9b3c};//{123,434,1,123,1,34,123,56,123,8};
    BYTE KeyK[b];//8bit=byte
    InitialKey(KeyK,b); //生成初始密钥
    int k;
    generateChildKey(KeyK,ChildKeyS); //根据初始密钥生成子密钥
//    TWOBYTEINT Source[]={'1','2','1','1'};//测试明文
    char arr[] = "what can i do for you?";
    unsigned long ll = strlen(arr);
    int m;
    for (m=0; NoOfData * m < ll; m++) {
        TWOBYTEINT Source[4] = {arr[4 * m], arr[4 * m + 1], arr[4 * m + 2], arr[4 * m + 3]};
        printf("加密以前的明文:");
        for (k=0;k<NoOfData;k++)
        {
            
            printf("%.4X ",Source[k]); //16进制输出
            printf("%c ",Source[k]); //16进制输出
        }
        printf("\n");
        TWOBYTEINT Dest[NoOfData]; //用来存储密文
        for(k=0;k<26;k++)
        {
            ChildKey1[k]=ChildKeyS[k];//如果此处自定义简单的数值为加密密钥，则可以解密出密文
            printf("%.4X ",ChildKey1[k]);
            
        }
        Encipher(Source,Dest,ChildKey1); //加密
        printf("\n");
        printf("加密以后的密文:");
        for (k=0;k<NoOfData;k++)
        {
            printf("%.4X ",Dest[k]);
            printf("%c ",Dest[k]);
        }
        printf("\n");
        TWOBYTEINT Data[NoOfData]={0}; //用来存储解密后的密文
        Decipher(Dest,Data,ChildKey1); //解密
        printf("解密以后的明文:");
        for (k=0;k<NoOfData;k++)
        {
            printf("%.4X ",Data[k]);
            printf("%c ",Data[k]);
        }
        printf("\n\n\n\n");

    }
    
    //printf("sizeof unsigned short int: %d",sizeof(unsigned short int));
    system("pause\n");
}



