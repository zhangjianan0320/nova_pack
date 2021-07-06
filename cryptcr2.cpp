/**************************************************************************
            Copyright (C)2017, Xi'an NovaStar Tech Co., Ltd
** FileName:cryptrc2.cpp
** Function:提供ECB、CFB、CBC加解密算法
** Version Record:
** Version      Author             Date                 Description
** v1.0.0       DangRenchang       2017-4-10 09:51:17    接口实现文件
**************************************************************************/

#include "cryptcr2.h"
#include <stdio.h>
#include <string>
#include <string.h>
#include <iostream>

using namespace std;

#define BCB_BLOCK 1024

CryptRc2::CryptRc2()
{

}

/***************************************************************************
* Function: RC2_ECB_Encrypt:对源数据进行ECB加密
* InPut :   buffer_in:源数据;
* OutPut :  buffer_length:加密后数据;
* Return :  None
* Other :   None
* Author :  dangrenchang 2017-4-10 10:25:49
***************************************************************************/
void CryptRc2::RC2_ECB_Encrypt(unsigned char *buffer_in, int &buffer_length)
{
    unsigned char byKey[16] = { 106, 51, 25, 141, 157, 142, 23, 111, 234, 159, 187, 154, 215, 34, 37, 205 };
    CryptRc2::initKey( &rc2Key , (void *)byKey, 16 );
    CryptRc2::encryptECB( &rc2Key, buffer_in , buffer_length );
}

/***************************************************************************
* Function: RC2_ECB_Decrypt:对源数据进行ECB解密
* InPut :   buffer_in:源数据;
* OutPut :  buffer_length:解密后数据;
* Return :  None
* Other :   None
* Author :  dangrenchang 2017-4-10 10:26:22
***************************************************************************/
void CryptRc2::RC2_ECB_Decrypt( unsigned char *buffer_in , int &buffer_length )
{
    unsigned char byKey[16] = { 106, 51, 25, 141, 157, 142, 23, 111, 234, 159, 187, 154, 215, 34, 37, 205 };
    CryptRc2::initKey( &rc2Key , (void *)byKey, 16 );
    CryptRc2::decryptECB( &rc2Key, buffer_in , buffer_length );
}

/***************************************************************************
* Function: RC2_CFB_Encrypt:对源数据进行CFB加密
* InPut :   buffer_in:源数据;
* OutPut :  buffer_length:加密后数据;
* Return :  None
* Other :   None
* Author :  dangrenchang 2017-4-10 10:26:51
***************************************************************************/
void CryptRc2::RC2_CFB_Encrypt( unsigned char *buffer_in , int &buffer_length )
{
    unsigned char byKey[16] = { 106, 51, 25, 141, 157, 142, 23, 111, 234, 159, 187, 154, 215, 34, 37, 205 };
    CryptRc2::initKey( &rc2Key , (void *)byKey, 16 );
    CryptRc2::encryptCFB( &rc2Key, 0,  buffer_in , buffer_length );
}

/***************************************************************************
* Function: RC2_CFB_Decrypt:对源数据进行CFB解密
* InPut :   buffer_in:源数据;
* OutPut :  buffer_length:解密后数据;
* Return :  None
* Other :   None
* Author :  dangrenchang 2017-4-10 10:28:40
***************************************************************************/
void CryptRc2::RC2_CFB_Decrypt( unsigned char *buffer_in , int &buffer_length )
{
    unsigned char byKey[16] = { 106, 51, 25, 141, 157, 142, 23, 111, 234, 159, 187, 154, 215, 34, 37, 205 };
    CryptRc2::initKey( &rc2Key , (void *)byKey, 16 );
    CryptRc2::decryptCFB( &rc2Key, 0,  buffer_in , buffer_length );
}

/***************************************************************************
* Function: RC2_CBC_Encrypt:对源数据进行CBC加密
* InPut :   buffer_in:源数据;
* OutPut :  buffer_length:加密后数据;
* Return :  None
* Other :   None
* Author :  dangrenchang 2017-4-10 10:29:11
***************************************************************************/
void CryptRc2::RC2_CBC_Encrypt( unsigned char *buffer_in , int &buffer_length )
{
    if( buffer_length == 0 )
        return ;
    unsigned char byKey[16] = { 106, 51, 25, 141, 157, 142, 23, 111, 234, 159, 187, 154, 215, 34, 37, 205 };
    CryptRc2::initKey( &rc2Key , (void *)byKey, 16 );
    unsigned char currentIV[ CRYPT_MAX_IVSIZE + 8 ] = { 135, 186, 133, 136, 184, 149, 153, 144 };

    int buffer_surplus_length  =  8 - (buffer_length % 8);
    for( int i = buffer_length; i <buffer_length+buffer_surplus_length  ; i++ )
        buffer_in[i] = buffer_surplus_length;

    CryptRc2::encryptCBC( &rc2Key, currentIV,  buffer_in , buffer_length+buffer_surplus_length );
    return ;
}

/***************************************************************************
* Function: RC2_CBC_Decrypt:对源数据进行CBC解密
* InPut :   buffer_in:源数据;
* OutPut :  buffer_length:解密后数据;
* Return :  None
* Other :   None
* Author :  dangrenchang 2017-4-10 10:29:41
***************************************************************************/
void CryptRc2::RC2_CBC_Decrypt( unsigned char *buffer_in , int &buffer_length  , int &flag )
{
    unsigned char byKey[16] = { 106, 51, 25, 141, 157, 142, 23, 111, 234, 159, 187, 154, 215, 34, 37, 205 };
    CryptRc2::initKey( &rc2Key , (void *)byKey, 16 );
    unsigned char currentIV[ CRYPT_MAX_IVSIZE + 8 ] = { 135, 186, 133, 136, 184, 149, 153, 144 };

    if( flag >= 0 )
    {
        int buffer_surplus_length  =  8 - (buffer_length % 8);
        CryptRc2::decryptCBC( &rc2Key, currentIV,  buffer_in , buffer_length-buffer_surplus_length );
    }
    else
    {

        CryptRc2::decryptCBC( &rc2Key, currentIV,  buffer_in , buffer_length );
        int buffer_surplus_length  =  buffer_in[buffer_length-1];
        buffer_length = buffer_length-buffer_surplus_length;

        flag = buffer_surplus_length;
    }
    return ;
}

/***************************************************************************
* Function: ReadFileToEncryptOrDecrypt:加解密文件
* InPut :   filename_in:源文件名称;filename_out:输出文件名称;
            crypt_style:操作方式;crypt_type:加解密类型
* OutPut :  true:加解密文件成功，并且成功输出文件;false:加解密失败，或者输出文件失败；
* Return :  None
* Other :   None
* Author :  dangrenchang 2017-4-10 10:34:31
***************************************************************************/
#if 0
bool CryptRc2::ReadFileToEncryptOrDecrypt( QString filename_in, QString filename_out ,CRYPTSTYLE crypt_style , CRYPTTYPE crypt_type )
{
//    FILE *file_in = fopen( filename_in.c_str() , "rb+");
//    if( file_in == NULL )
//        return false;

//    fseek ( file_in , 0, SEEK_END);
//    int buffer_length = ftell ( file_in );
//    int buffer_surplus_length = 0;
//    fseek( file_in, 0, SEEK_SET );

    QFile file_in( filename_in );
    if (!file_in.open(QIODevice::ReadOnly))
    {
        qDebug() << "CryptRc2::ReadFileToEncryptOrDecrypt open failed:" << filename_in;
        return false;
    }

    int buffer_length = file_in.bytesAvailable();
    qDebug() << "CryptRc2::ReadFileToEncryptOrDecrypt filename_in:" << filename_in <<"    size:"<< buffer_length;

    char* buffer_in = (char *)malloc( buffer_length+1 );
    if( buffer_in == NULL )
    {
        // fclose( file_in );
        file_in.close();
        return false;
    }

    file_in.read( buffer_in, file_in.bytesAvailable() );

//    if( fread( buffer_in, 1, buffer_length , file_in) <= 0 )
//    {
//        cout<< "Error" <<endl;
//        if(feof(file_in))
//        {
//            fclose(file_in);
//            return false;
//        }
//    }

    bool bret = false;
    if( crypt_style == CRYPTSTYLE::ENCRYPT )
    {
        if( crypt_type == CRYPTTYPE::ECB )
            RC2_ECB_Encrypt( (unsigned char*)buffer_in , buffer_length );
        else if( crypt_type == CRYPTTYPE::CFB )
            RC2_CFB_Encrypt( (unsigned char*)buffer_in , buffer_length );
        else if( crypt_type == CRYPTTYPE::CBC )
        {
            bret = RC2_CBC_EncryptEx( (unsigned char*)buffer_in  , buffer_length , filename_out );
        }
        else
        {
            // fclose( file_in );
            file_in.close();
            free( buffer_in );
            return false;
        }
    }
    else if( crypt_style == CRYPTSTYLE::DECRYPT )
    {
        if( crypt_type == CRYPTTYPE::ECB )
            RC2_ECB_Decrypt( (unsigned char*)buffer_in , buffer_length );
        else if( crypt_type == CRYPTTYPE::CFB )
            RC2_CFB_Decrypt( (unsigned char*)buffer_in , buffer_length );
        else if( crypt_type == CRYPTTYPE::CBC )
        {
            bret = RC2_CBC_DecryptEx( (unsigned char*)buffer_in , buffer_length , filename_out );
        }
            else
        {
            // fclose( file_in );
            file_in.close();
            free( buffer_in );
            return false;
        }
    }
    // fclose( file_in );
    file_in.close();
    free( buffer_in );

    return bret;
}
#endif
/***************************************************************************
* Function: RC2_CBC_EncryptEx:对源数据进行CBC加密(带输出文件)
* InPut :   buffer_in:源数据;filename_out:待输出文件名称;
* OutPut :  buffer_length:加密后数据;
* Return :  None
* Other :   None
* Author :  dangrenchang 2017-4-10 10:38:46
***************************************************************************/
bool CryptRc2::RC2_CBC_EncryptEx( unsigned char *buffer_in , int &buffer_length,std::string file_desk)
{
    int n = buffer_length / BCB_BLOCK;
    int alllength = buffer_length;
    int buffer_surplus_length  =  8 - (buffer_length % 8);
    int bu_temp_len = buffer_length + n*8+buffer_surplus_length +1;
    unsigned char *buffer_in_all_temp = (unsigned char *)malloc( buffer_length + n*8+buffer_surplus_length +1 );
    unsigned char *buffer_in_temp = NULL;
    buffer_in_temp = (unsigned char *)malloc( BCB_BLOCK+1+8 );
    for( int i = 0 ; i < n ;i++)
    {
        memset( buffer_in_temp , 0 , BCB_BLOCK+1+8);
        memcpy( buffer_in_temp, buffer_in + i*BCB_BLOCK , BCB_BLOCK );

        int length = BCB_BLOCK;
        RC2_CBC_Encrypt( buffer_in_temp , length );
        memcpy( buffer_in_all_temp + i*(BCB_BLOCK+8) , buffer_in_temp , BCB_BLOCK+8 );
        alllength -= BCB_BLOCK;
    }

    if( alllength > 0 )
    {
        memcpy( buffer_in_temp, buffer_in + n*BCB_BLOCK , alllength );
        RC2_CBC_Encrypt( buffer_in_temp , alllength );
        memcpy( buffer_in_all_temp + n*(BCB_BLOCK+8) , buffer_in_temp , alllength+8 );
    }
    free( buffer_in_temp ); 
    buffer_in_temp = NULL;

    buffer_length = buffer_length + n*8+buffer_surplus_length;
    //新的长度比原来长，
    // cout<<"buffer_length len is "<<bu_temp_len<<" buffer_length "<<buffer_length<<endl;
    // memcpy(buffer_in, buffer_in_all_temp, buffer_length);
    cout<<"memcpy ok"<<endl;
    //将数据写入文件中
    ofstream desk;
    desk.open(file_desk,ios::binary|ios::app);
    if(!desk.is_open())
    {
        cout<<"desk open error"<<endl;
    }
    desk.write((const char *)buffer_in_all_temp,buffer_length);
    desk.close();

    free(buffer_in_all_temp);
    buffer_in_all_temp = NULL;

    return true;
}


/***************************************************************************
* Function: RC2_CBC_DecryptEx:对源数据进行CBC解密(带输出文件)
* InPut :   buffer_in:源数据;filename_out:待输出文件名称;
* OutPut :  buffer_length:解密后数据;
* Return :  None
* Other :   None
* Author :  dangrenchang 2017-4-10 10:39:53
***************************************************************************/
bool CryptRc2::RC2_CBC_DecryptEx( unsigned char *buffer_in , int &buffer_length)
{
    int n = buffer_length / (BCB_BLOCK+8);
    int alllength = buffer_length;

    unsigned char *buffer_in_all_temp = (unsigned char *)malloc( buffer_length - n*8 +1 );
    unsigned char *buffer_in_temp = NULL;
    buffer_in_temp = (unsigned char *)malloc( BCB_BLOCK+1+8 );
    for( int i = 0 ; i < n ;i++)
    {
        memcpy( buffer_in_temp, buffer_in + i*(BCB_BLOCK+8) , (BCB_BLOCK+8) );
        int length = BCB_BLOCK+8;
        RC2_CBC_Decrypt( buffer_in_temp , length , i );
        memcpy( buffer_in_all_temp + i*(BCB_BLOCK) , buffer_in_temp , BCB_BLOCK );
        if( alllength > (BCB_BLOCK+8) )
            alllength -= (BCB_BLOCK+8);
    }
    int buffer_surplus_length = -1;
    if( alllength > 0 )
    {
        memcpy( buffer_in_temp, buffer_in + n*(BCB_BLOCK+8) , alllength );
        RC2_CBC_Decrypt( buffer_in_temp , alllength , buffer_surplus_length );
        memcpy( buffer_in_all_temp + n*(BCB_BLOCK) , buffer_in_temp , alllength );
    }

    free( buffer_in_temp ); 
	buffer_in_temp = NULL;
    buffer_length = buffer_length - n*8;

    if( buffer_surplus_length != -1 )
        buffer_length = buffer_length - buffer_surplus_length;

	memcpy(buffer_in, buffer_in_all_temp, buffer_length);

    free( buffer_in_all_temp ); 
	buffer_in_all_temp = NULL;
    return true;
}



int CryptRc2::encryptECB( RC2_KEY *rc2Key, unsigned char *buffer,int noBytes )
{
    int blockCount = noBytes / RC2_BLOCKSIZE;

    while( blockCount-- > 0 )
    {
        /* Encrypt a block of data */
        RC2_ecb_encrypt( buffer, buffer, rc2Key, RC2_ENCRYPT );

        /* Move on to next block of data */
        buffer += RC2_BLOCKSIZE;
    }

    return( CRYPT_OK );
}

int CryptRc2::decryptECB( RC2_KEY *rc2Key , unsigned char *buffer,int noBytes )
{
    int blockCount = noBytes / RC2_BLOCKSIZE;

    while( blockCount-- > 0 )
    {
        /* Decrypt a block of data */
        RC2_ecb_encrypt( buffer, buffer, rc2Key, RC2_DECRYPT );

        /* Move on to next block of data */
        buffer += RC2_BLOCKSIZE;
    }

    return( CRYPT_OK );
}

/* Encrypt/decrypt data in CBC mode */

int CryptRc2::encryptCBC( RC2_KEY *rc2Key , unsigned char *currentIV ,  unsigned char *buffer, int noBytes )
{
    /* Encrypt the buffer of data */
    RC2_cbc_encrypt( buffer, buffer, noBytes, ( RC2_KEY * ) rc2Key, currentIV, RC2_ENCRYPT );

    return( CRYPT_OK );
}

int CryptRc2::decryptCBC( RC2_KEY *rc2Key , unsigned char *currentIV , unsigned char *buffer, int noBytes )
{
    /* Decrypt the buffer of data */
    RC2_cbc_encrypt( buffer, buffer, noBytes, ( RC2_KEY * )rc2Key, currentIV, RC2_DECRYPT );

    return( CRYPT_OK );
}

/* Encrypt/decrypt data in CFB mode */

int CryptRc2::encryptCFB( RC2_KEY *rc2Key  ,int  ivCount, unsigned char *buffer, int noBytes )
{
    int i;
    unsigned char currentIV[ CRYPT_MAX_IVSIZE + 8 ] = { 135, 186, 133, 136, 184, 149, 153, 144 };

    /* If there's any encrypted material left in the IV, use it now */
    if( ivCount > 0 )
    {
        int bytesToUse;

        /* Find out how much material left in the encrypted IV we can use */
        bytesToUse = RC2_BLOCKSIZE - ivCount;
        if( noBytes < bytesToUse )
            bytesToUse = noBytes;

        /* Encrypt the data */
        for( i = 0; i < bytesToUse; i++ )
            buffer[ i ] ^= currentIV[ i + ivCount ];
        memcpy( currentIV + ivCount, buffer, bytesToUse );

        /* Adjust the byte count and buffer position */
        noBytes -= bytesToUse;
        buffer += bytesToUse;
        ivCount += bytesToUse;
    }

    while( noBytes > 0 )
    {
        ivCount = ( noBytes > RC2_BLOCKSIZE ) ? RC2_BLOCKSIZE : noBytes;

        /* Encrypt the IV */
        RC2_ecb_encrypt( currentIV, currentIV, rc2Key,
                         RC2_ENCRYPT );

        /* XOR the buffer contents with the encrypted IV */
        for( i = 0; i < ivCount; i++ )
            buffer[ i ] ^= currentIV[ i ];

        /* Shift the ciphertext into the IV */
        memcpy( currentIV, buffer, ivCount );

        /* Move on to next block of data */
        noBytes -= ivCount;
        buffer += ivCount;
    }

    /* Remember how much of the IV is still available for use */
    ivCount = ( ivCount % RC2_BLOCKSIZE );

    return( CRYPT_OK );
}

int CryptRc2::decryptCFB( RC2_KEY *rc2Key  ,int  ivCount, unsigned char *buffer,int noBytes )
{
    unsigned char temp[ RC2_BLOCKSIZE + 8 ];
    int i;
    unsigned char currentIV[ CRYPT_MAX_IVSIZE + 8 ] = { 135, 186, 133, 136, 184, 149, 153, 144 };
    /* If there's any encrypted material left in the IV, use it now */
    if( ivCount > 0 )
    {
        int bytesToUse;

        /* Find out how much material left in the encrypted IV we can use */
        bytesToUse = RC2_BLOCKSIZE - ivCount;
        if( noBytes < bytesToUse )
            bytesToUse = noBytes;

        /* Decrypt the data */
        memcpy( temp, buffer, bytesToUse );
        for( i = 0; i < bytesToUse; i++ )
            buffer[ i ] ^= currentIV[ i + ivCount ];
        memcpy( currentIV + ivCount, temp, bytesToUse );

        /* Adjust the byte count and buffer position */
        noBytes -= bytesToUse;
        buffer += bytesToUse;
        ivCount += bytesToUse;
    }

    while( noBytes > 0 )
    {
        ivCount = ( noBytes > RC2_BLOCKSIZE ) ? RC2_BLOCKSIZE : noBytes;

        /* Encrypt the IV */
        RC2_ecb_encrypt( currentIV, currentIV, rc2Key,
                         RC2_ENCRYPT );

        /* Save the ciphertext */
        memcpy( temp, buffer, ivCount );

        /* XOR the buffer contents with the encrypted IV */
        for( i = 0; i < ivCount; i++ )
            buffer[ i ] ^= currentIV[ i ];

        /* Shift the ciphertext into the IV */
        memcpy( currentIV, temp, ivCount );

        /* Move on to next block of data */
        noBytes -= ivCount;
        buffer += ivCount;
    }

    /* Remember how much of the IV is still available for use */
    ivCount = ( ivCount % RC2_BLOCKSIZE );

    /* Clear the temporary buffer */
    zeroise( temp, RC2_BLOCKSIZE );

    return( CRYPT_OK );
}

int CryptRc2::initKey( RC2_KEY *rc2Key, const void *key , const int keyLength )
{
    /* Copy the key to internal storage */
    RC2_set_key( rc2Key, keyLength, (unsigned char *)key, effectiveKeysizeBits( keyLength ) );
    return( CRYPT_OK );
}


unsigned char buffer_base[][8] = {
    { 0xB1 , 0x30 , 0x4D , 0xBF , 0x7E , 0x32 , 0x30 , 0x29 } ,
   // { 0xD2 , 0x9C , 0x9B , 0x35 , 0xF0 , 0xEA , 0xCC , 0x39 } ,
    { 0x3D , 0x25 , 0xD2 , 0x10 , 0x68 , 0xD2 , 0x78 , 0xBF } ,
    { 0x28 , 0xA4 , 0x39 , 0xFA , 0x24 , 0x7B , 0xE8 , 0x5D } ,
    { 0xC1 , 0xB9 , 0x89 , 0x5B , 0xA3 , 0x14 , 0xB3 , 0x26 } ,
    { 0x9D , 0x7F , 0xB5 , 0x14 , 0xCE , 0x4E , 0x6E , 0x57 } ,
    { 0x73 , 0x27 , 0xE6 , 0xAE , 0xE1 , 0xB7 , 0x81 , 0x80 } ,
    { 0x20 , 0x60 , 0x78 , 0x00 , 0x8F , 0xF5 , 0xE0 , 0x24 } ,
    { 0x25 , 0xF2 , 0x27 , 0xBB , 0x6D , 0x01 , 0xB9 , 0x54 } ,
    { 0xC3 , 0x89 , 0x23 , 0xF9 , 0x3D , 0x7C , 0x20 , 0xEB } ,
    { 0x6E , 0x9E , 0x61 , 0x77 , 0x9C , 0x40 , 0x39 , 0x93 } ,
    { 0x4B , 0x24 , 0x98 , 0x35 , 0x47 , 0x43 , 0x49 , 0x1E } ,
    { 0x9B , 0xDA , 0xDA , 0xC9 , 0x35 , 0xD9 , 0x03 , 0x7A } ,
    { 0x99 , 0xB8 , 0x02 , 0xC1 , 0x49 , 0x73 , 0x7B , 0x67 } ,
    { 0x3F , 0xF4 , 0x44 , 0x21 , 0x0B , 0x7E , 0xA6 , 0x84 } ,
    { 0x4F , 0x34 , 0xFD , 0x76 , 0xF1 , 0xA5 , 0x83 , 0xB7 } ,
    { 0xF4 , 0x32 , 0x69 , 0xD0 , 0xA8 , 0xB4 , 0x61 , 0x97 }
} ;

void CryptRc2::swap_head( unsigned char *in , int n)
{
    n = n%16;
    for( int i = 0 ; i < 8 ; i++)
    {
        unsigned char lo4_base,hi4_base;
        hi4_base = (buffer_base[n][i] & 0xf0) >> 4;
        lo4_base = buffer_base[n][i] & 0x0f;

        unsigned char lo4,hi4;
        hi4 = (in[i] & 0xf0) >> 4;
        lo4 = in[i] & 0x0f;

        unsigned char lo4_result,hi4_result;
        hi4_result = hi4_base^hi4;
        lo4_result = lo4_base^lo4;

        in[i] = (hi4_result<<4) | lo4_result;
    }
}

/***************************************************************************
* @@@@@@@: 
* @@@@@@@: 
* @@@@@@@: 
* @@@@@@@: 以下为线程安全的方式，不使用用全局变量
* @@@@@@@: 
* @@@@@@@: 
* @@@@@@@: 
***************************************************************************/
int General_initKey( RC2_KEY *rc2Key, const void *key , const int keyLength )
{
    /* Copy the key to internal storage */
    RC2_set_key( rc2Key, keyLength, (unsigned char *)key, effectiveKeysizeBits( keyLength ) );
    return( CRYPT_OK );
}
int General_decryptCFB( RC2_KEY *rc2Key  ,int  ivCount, unsigned char *buffer,int noBytes )
{
    unsigned char temp[ RC2_BLOCKSIZE + 8 ];
    int i;
    unsigned char currentIV[ CRYPT_MAX_IVSIZE + 8 ] = { 135, 186, 133, 136, 184, 149, 153, 144 };
    /* If there's any encrypted material left in the IV, use it now */
    if( ivCount > 0 )
    {
        int bytesToUse;

        /* Find out how much material left in the encrypted IV we can use */
        bytesToUse = RC2_BLOCKSIZE - ivCount;
        if( noBytes < bytesToUse )
            bytesToUse = noBytes;

        /* Decrypt the data */
        memcpy( temp, buffer, bytesToUse );
        for( i = 0; i < bytesToUse; i++ )
            buffer[ i ] ^= currentIV[ i + ivCount ];
        memcpy( currentIV + ivCount, temp, bytesToUse );

        /* Adjust the byte count and buffer position */
        noBytes -= bytesToUse;
        buffer += bytesToUse;
        ivCount += bytesToUse;
    }

    while( noBytes > 0 )
    {
        ivCount = ( noBytes > RC2_BLOCKSIZE ) ? RC2_BLOCKSIZE : noBytes;

        /* Encrypt the IV */
        RC2_ecb_encrypt( currentIV, currentIV, rc2Key,RC2_ENCRYPT );

        /* Save the ciphertext */
        memcpy( temp, buffer, ivCount );

        /* XOR the buffer contents with the encrypted IV */
        for( i = 0; i < ivCount; i++ )
            buffer[ i ] ^= currentIV[ i ];

        /* Shift the ciphertext into the IV */
        memcpy( currentIV, temp, ivCount );

        /* Move on to next block of data */
        noBytes -= ivCount;
        buffer += ivCount;
    }

    /* Remember how much of the IV is still available for use */
    ivCount = ( ivCount % RC2_BLOCKSIZE );

    /* Clear the temporary buffer */
    zeroise( temp, RC2_BLOCKSIZE );

    return( CRYPT_OK );
}
/***************************************************************************
* Function: RC2_CFB_Decrypt:对源数据进行CFB解密
* InPut :   buffer_in:源数据;
* OutPut :  buffer_length:解密后数据;
* Return :  None
* Other :   None
* Author :  dangrenchang 2017-4-10 10:28:40
***************************************************************************/
void General_RC2_CFB_Decrypt( unsigned char *buffer_in , int &buffer_length )
{
	RC2_KEY rc2Key = {0};
    unsigned char byKey[16] = { 106, 51, 25, 141, 157, 142, 23, 111, 234, 159, 187, 154, 215, 34, 37, 205 };
    General_initKey( &rc2Key , (void *)byKey, 16 );
    General_decryptCFB( &rc2Key, 0,  buffer_in , buffer_length );
}

int General_decryptCBC( RC2_KEY *rc2Key , unsigned char *currentIV , unsigned char *buffer, int noBytes )
{
    /* Decrypt the buffer of data */
    RC2_cbc_encrypt( buffer, buffer, noBytes, ( RC2_KEY * )rc2Key, currentIV, RC2_DECRYPT );

    return( CRYPT_OK );
}

/***************************************************************************
* Function: RC2_CBC_Decrypt:对源数据进行CBC解密
* InPut :   buffer_in:源数据;
* OutPut :  buffer_length:解密后数据;
* Return :  None
* Other :   None
* Author :  dangrenchang 2017-4-10 10:29:41
***************************************************************************/
void General_RC2_CBC_Decrypt( unsigned char *buffer_in , int &buffer_length  , int &flag )
{
	RC2_KEY rc2Key = {0};
    unsigned char byKey[16] = { 106, 51, 25, 141, 157, 142, 23, 111, 234, 159, 187, 154, 215, 34, 37, 205 };
    General_initKey( &rc2Key , (void *)byKey, 16 );
    unsigned char currentIV[ CRYPT_MAX_IVSIZE + 8 ] = { 135, 186, 133, 136, 184, 149, 153, 144 };

    if( flag >= 0 )
    {
        int buffer_surplus_length  =  8 - (buffer_length % 8);
        General_decryptCBC( &rc2Key, currentIV,  buffer_in , buffer_length-buffer_surplus_length );
    }
    else
    {

        General_decryptCBC( &rc2Key, currentIV,  buffer_in , buffer_length );
        int buffer_surplus_length  =  buffer_in[buffer_length-1];
        buffer_length = buffer_length-buffer_surplus_length;

        flag = buffer_surplus_length;
    }
    return ;
}

/***************************************************************************
* Function: RC2_CBC_DecryptEx:对源数据进行CBC解密(带输出文件)
* InPut :   buffer_in:源数据;filename_out:待输出文件名称;
* OutPut :  buffer_length:解密后数据;
* Return :  None
* Other :   None
* Author :  dangrenchang 2017-4-10 10:39:53
***************************************************************************/
bool General_RC2_CBC_DecryptEx( unsigned char *buffer_in , int &buffer_length,string file_desk)
{
    int n = buffer_length / (BCB_BLOCK+8);
    int alllength = buffer_length;

    unsigned char *buffer_in_all_temp = (unsigned char *)malloc( buffer_length - n*8 +1 );
    unsigned char *buffer_in_temp = NULL;
    buffer_in_temp = (unsigned char *)malloc( BCB_BLOCK+1+8 );
    for( int i = 0 ; i < n ;i++)
    {
        memcpy( buffer_in_temp, buffer_in + i*(BCB_BLOCK+8) , (BCB_BLOCK+8) );
        int length = BCB_BLOCK+8;
        General_RC2_CBC_Decrypt( buffer_in_temp , length , i );
        memcpy( buffer_in_all_temp + i*(BCB_BLOCK) , buffer_in_temp , BCB_BLOCK );
        if( alllength > (BCB_BLOCK+8) )
            alllength -= (BCB_BLOCK+8);
    }
    int buffer_surplus_length = -1;
    if( alllength > 0 )
    {
        memcpy( buffer_in_temp, buffer_in + n*(BCB_BLOCK+8) , alllength );
        General_RC2_CBC_Decrypt( buffer_in_temp , alllength , buffer_surplus_length );
        memcpy( buffer_in_all_temp + n*(BCB_BLOCK) , buffer_in_temp , alllength );
    }

    free( buffer_in_temp ); 
	buffer_in_temp = NULL;
    buffer_length = buffer_length - n*8;

    if( buffer_surplus_length != -1 )
    buffer_length = buffer_length - buffer_surplus_length;

	memcpy(buffer_in, buffer_in_all_temp, buffer_length);

    free( buffer_in_all_temp ); 
	buffer_in_all_temp = NULL;
    return true;
}





void test(string st)
{

    cout<<st<<endl;
}

