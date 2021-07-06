/**************************************************************************
Copyright (C)2017, Xi'an NovaStar Tech Co., Ltd
** FileName:cryptrc2.h
** Function:提供ECB、CFB、CBC加解密算法
** Version Record:
** Version      Author             Date                 Description
** v1.0.0       DangRenchang       2017-4-10 09:32:15    接口头文件
**************************************************************************/

#ifndef CRYPTRC2_H
#define CRYPTRC2_H

#include "rc2.h"
#include <memory.h>
#include <string>
#include <iostream>
#include <fstream>

#define USE_RC2

#define RC2_BLOCKSIZE			RC2_BLOCK
#define RC2_EXPANDED_KEYSIZE	sizeof( RC2_KEY )
#define CRYPT_OK                0
#define CRYPT_MAX_IVSIZE        32

#define bitsToBytes( bits )			( ( ( bits ) + 7 ) >> 3 )
#define bytesToBits( bytes )		( ( bytes ) << 3 )

#define effectiveKeysizeBits( keySize )		bytesToBits( keySize )
#define zeroise( memory, size )             memset( memory , 0, size )



//RC2 加密类型
enum CRYPTTYPE
{
    ECB = 0,
    CFB,
    CBC
};

//RC2 方式方式
enum CRYPTSTYLE
{
    ENCRYPT = 0,    // 加密
    DECRYPT         // 解密
};

class  CryptRc2
{

public:
    explicit CryptRc2();

    /***************************************************************************
    * Function: RC2_ECB_Encrypt:对源数据进行ECB加密
    * InPut :   buffer_in:源数据;
    * OutPut :  buffer_length:加密后数据;
    * Return :  None
    * Other :   None
    * Author :  dangrenchang 2017-4-10 10:25:49
    ***************************************************************************/
    void RC2_ECB_Encrypt( unsigned char *buffer_in , int &buffer_length );

    /***************************************************************************
    * Function: RC2_ECB_Decrypt:对源数据进行ECB解密
    * InPut :   buffer_in:源数据;
    * OutPut :  buffer_length:解密后数据;
    * Return :  None
    * Other :   None
    * Author :  dangrenchang 2017-4-10 10:26:22
    ***************************************************************************/
    void RC2_ECB_Decrypt( unsigned char *buffer_in , int &buffer_length );

    /***************************************************************************
    * Function: RC2_CFB_Encrypt:对源数据进行CFB加密
    * InPut :   buffer_in:源数据;
    * OutPut :  buffer_length:加密后数据;
    * Return :  None
    * Other :   None
    * Author :  dangrenchang 2017-4-10 10:26:51
    ***************************************************************************/
    void RC2_CFB_Encrypt( unsigned char *buffer_in , int &buffer_length );

    /***************************************************************************
    * Function: RC2_CFB_Decrypt:对源数据进行CFB解密
    * InPut :   buffer_in:源数据;
    * OutPut :  buffer_length:解密后数据;
    * Return :  None
    * Other :   None
    * Author :  dangrenchang 2017-4-10 10:28:40
    ***************************************************************************/
    void RC2_CFB_Decrypt( unsigned char *buffer_in , int &buffer_length );

    /***************************************************************************
    * Function: RC2_CBC_Encrypt:对源数据进行CBC加密
    * InPut :   buffer_in:源数据;
    * OutPut :  buffer_length:加密后数据;
    * Return :  None
    * Other :   None
    * Author :  dangrenchang 2017-4-10 10:29:11
    ***************************************************************************/
    void RC2_CBC_Encrypt( unsigned char *buffer_in , int &buffer_length );

    /***************************************************************************
    * Function: RC2_CBC_Decrypt:对源数据进行CBC解密
    * InPut :   buffer_in:源数据;
    * OutPut :  buffer_length:解密后数据;
    * Return :  None
    * Other :   None
    * Author :  dangrenchang 2017-4-10 10:29:41
    ***************************************************************************/
    void RC2_CBC_Decrypt( unsigned char *buffer_in , int &buffer_length  , int &flag );

    bool RC2_CBC_EncryptEx( unsigned char *buffer_in , int &buffer_length,std::string file_desk);
    bool RC2_CBC_DecryptEx( unsigned char *buffer_in , int &buffer_length);

    // 加解密文件
    //bool ReadFileToEncryptOrDecrypt( QString filename_in, QString filename_out ,CRYPTSTYLE crypt_style , CRYPTTYPE crypt_type );
    void swap_head( unsigned char *in , int n );

private:
    int initKey( RC2_KEY *rc2Key, const void *key,const int keyLength );
    int encryptECB( RC2_KEY *rc2Key, unsigned char *buffer,int noBytes );
    int decryptECB( RC2_KEY *rc2Key , unsigned char *buffer,int noBytes );
    int encryptCBC( RC2_KEY *rc2Key , unsigned char *currentIV ,  unsigned char *buffer,int noBytes );
    int decryptCBC( RC2_KEY *rc2Key , unsigned char *currentIV , unsigned char *buffer,int noBytes );
    int encryptCFB( RC2_KEY *rc2Key  ,int  ivCount, unsigned char *buffer, int noBytes );
    int decryptCFB( RC2_KEY *rc2Key  ,int  ivCount, unsigned char *buffer,int noBytes );

private:
    RC2_KEY rc2Key ;
};

bool General_RC2_CBC_DecryptEx( unsigned char *buffer_in , int &buffer_length);



#endif // CRYPTRC2_H
