#include <iostream>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include "cryptcr2.h"
#include "tinyxml2.h"
#include <vector>
#include <dirent.h>
#include <time.h>
#include <sstream>
#include <pthread.h>

using namespace std;

struct file_source{
    string file_name;
    string desk_name;
};
//该结构体最大为256
struct describe_base
{
    uint32_t file_len;
    uint8_t main_versin[4];
    uint8_t brief[120];
    uint16_t fill;  //固定填充0000
    uint16_t check_sum; //程序校验  校验和 硬件程序累加值 + 0x5555
    uint8_t version_sub[4];
    uint16_t modelID; //板卡ID
    uint8_t card_type;  //器件类型
    uint8_t reserve[19]; //保留字段
    uint8_t brief_sub[96];
    uint16_t check_head;    //头文件校验信息
};

#define BRIEF "2021.06.15 E_4xDVI/HDMI_V2.0.0.0.C1"

/*查找node*/
tinyxml2::XMLElement * GetNodeByName(tinyxml2::XMLElement *root,const string &name)
{
    tinyxml2::XMLElement* pNode=root->FirstChildElement(name.c_str());
    if(pNode == NULL)
    {
        cout<<"pNode is NULL"<<endl;
    }
    return pNode;
}
int DirFilter(const struct dirent *pDir)
{        
     if ((pDir->d_type == DT_DIR) && (strcmp (pDir->d_name, ".") != 0) && (strcmp (pDir->d_name, "..") != 0))
     {  
         return 1;
     }
     return 0;
}

int getFiles(string path,vector<string> &v)
{
    struct dirent **namelist;
    int n = scandir(path.c_str(),&namelist,DirFilter,alphasort);
    printf("path is %s file num is %d\n",path.c_str(),n);
    while(n--)
    {
//        printf("file is %s \n",namelist[n]->d_name);
        v.push_back(namelist[n]->d_name);
        free(namelist[n]);
    }
    return 0;
}

//单个文件的加解密操作
class File_Manage :private CryptRc2
{
private:
    file_source file;
    describe_base info;
public:
    void config_file(file_source f,string brief,uint32_t ver,uint16_t model_id)
    {
        file = f;
        cout<<"file name is "<<file.file_name<<endl;
        cout<<"file desk is "<<file.desk_name<<endl;
        memset(&info,0,sizeof(info));
        memcpy(info.brief,brief.c_str(),brief.length());
        memcpy(info.brief_sub,brief.c_str(),brief.length());

        info.main_versin[0] = ver/1000;
        info.main_versin[1] = ver%1000/100;
        info.main_versin[2] = ver%100/10;
        info.main_versin[3] = ver%10;

        info.version_sub[0] = ver/1000;
        info.version_sub[1] = ver%1000/100;
        info.version_sub[2] = ver%100/10;
        info.version_sub[3] = ver%10;

        info.modelID = model_id;
    }
    //加密
    int SaveToDesk()
    {
        char cmd[512];
        //1、检测源文件是否存在
        if(access(file.file_name.c_str(),F_OK) != 0)
        {
            cout<<"file is not exeit "<<file.file_name<<endl;
            return -1;
        }
        //2、检测temp文件是否存在，若存在则先删除
        string temp = file.desk_name + ".temp";
        cout<<"temp file name is "<<temp<<endl;
        if(access(temp.c_str(),F_OK) == 0)
        {
            sprintf(cmd,"rm %s",temp.c_str());
            cout<<cmd<<endl;
            system(cmd);
        }
        sprintf(cmd,"touch %s",temp.c_str());
        cout<<cmd<<endl;
        //3、然后再创建中间文件
        ifstream src;
        //4、分别打开两个文件
        src.open(file.file_name,ios::binary|ios::app);
        if(!src.is_open())
        {
            cout<<"src open error"<<endl;
        }
        src.seekg(0,ios::end);
        int length = src.tellg();
        src.seekg(0,ios::beg);
        cout<<"src len is "<<length<<endl;
        unsigned char data[length+256];
        //5、对源文件进行加密，然后存储到desk中
        info.file_len = length;
        info.card_type = 0;
        //计算校验值
        info.check_sum = 0x5555;
        src.read((char *)data+256,length+256);
        for (size_t i = 0; i < length; i++)
        {
            info.check_sum += data[256+i];
        }
        info.check_head = 0x5555;
        for (size_t i = 0; i < 254; i++)
        {
             info.check_head += *((uint8_t *)(&info)+i);
        }
        cout<<"check head is "<<hex<<info.check_head<<endl;
        memcpy(data,(uint8_t *)(&info),256);
        int len_count = length+256;
        this->RC2_CBC_EncryptEx(data,len_count,temp);
        cout<<"encrpt ok"<<endl;
        src.close();
        cout<<"src close ok"<<endl;
        //temp = file.desk_name + ".temp";
        sprintf(cmd,"mv %s %s",temp.c_str(),file.desk_name.c_str());
        cout<<"cmd is "<<cmd<<endl;
        system(cmd);
    }
    //解密
    int Decrpt()
    {
        char cmd[512];
        //1、检测源文件是否存在
        if(access(file.file_name.c_str(),F_OK) != 0)
        {
            cout<<"file is not exeit "<<file.file_name<<endl;
            return -1;
        }
        //2、检测temp文件是否存在，若存在则先删除
        string temp = file.desk_name + ".temp";
        cout<<"temp file name is "<<temp<<endl;
        if(access(temp.c_str(),F_OK) == 0)
        {
            cout<<"file is not exeit "<<file.file_name<<endl;
            sprintf(cmd,"rm %s",temp.c_str());
            cout<<cmd<<endl;
            system(cmd);
        }
        sprintf(cmd,"touch %s",temp.c_str());
        cout<<cmd<<endl;
        //3、然后再创建中间文件
        ifstream src;
        ofstream desk;
        //4、分别打开两个文件
        src.open(file.file_name,ios::binary|ios::app);
        desk.open(temp,ios::binary|ios::app);
        src.seekg(0,ios::end);
        int length = src.tellg();
        src.seekg(0,ios::beg);
        cout<<"src len is "<<length<<endl;
        unsigned char data[length];
        //5、对源文件进行加密，然后存储到desk中
        src.read((char *)data,length);
        this->RC2_CBC_DecryptEx(data,length);
        desk.write((const char *)data,length);
        //6、关闭文件
        src.close();
        desk.close();
    }
};

int hex_str_to_in(const char *str)
{
    int len = strlen(str);
    int num = 0;
    const char *pos = str;
    char t = *pos;
    while(t != 0)
    {
        if(t >= '0' && t <= '9')
        {
            num *= 16;
            num += t - '0';
            t = *(++pos);
        }
        else if(t <= 'f' && t >= 'a')
        {
            num *= 16;
            num += t - 'a' + 10;
            t = *(++pos);
        }
        else if(t <= 'F' && t >= 'A')
        {
            num *= 16;
            num += t - 'A' + 10;
            t = *(++pos);
        }
        else
        {
            t = 0;
        }
    }
    return num;
}

//按照卡来进行操作
class Bale:private File_Manage
{
private:
    string src; //源文件路径
    string desk;//目标文件路径
    string remark;   //备注信息
    string xml_cfg;  //配置xml 路径
    string xml_save; //配置完成后需要保存的xml路径
    string xml_file_cfg;    //文件描述配置
    int ver;        //版本号
    uint16_t model_id;
    vector<file_source> v_file;
    //配置xml文件
    void config_xml()
    {
        struct tm *local;
        time_t lt;
        lt = time(NULL);
        cout<<"time is "<<lt<<endl;
        local = localtime(&lt);
        char time[30];
        sprintf(time,"%d.%d.%d ",local->tm_year+1900,local->tm_mon+1,local->tm_mday);

        remark = time + remark;

        stringstream over_and_remark;
        over_and_remark<<"0-0-0-0";
        over_and_remark<<"-"<<ver/1000<<"-"<<ver%1000/100<<"-"<<ver%100/10<<"-"<<ver%10;
        for(int i=0;i<remark.length();i++)
        {
            uint8_t num = remark[i];
            char str_num[20];
            sprintf(str_num,"-%d",num);
            over_and_remark << str_num;
        }
        cout<<"over_and_remark is "<<over_and_remark.str()<<endl;

        //配置升级config xml
        tinyxml2::XMLDocument doc;
        if(doc.LoadFile(xml_cfg.c_str()) != 0)
        {
            cout<<"xml load error "<<xml_cfg<<endl;
        }
        else
        {
            cout<<"xml load ok "<<xml_cfg<<endl;
        }
        char ss_versin[8];
        sprintf(ss_versin,"%d.%d.%d.%d",ver/1000,ver%1000/100,ver%100/10,ver%10);

        //处理版本信息
        tinyxml2::XMLElement* root = doc.RootElement();
        tinyxml2::XMLElement* xmlModel_id = GetNodeByName(root,"ModuleID");
        tinyxml2::XMLElement* version = GetNodeByName(root,"Version");
        tinyxml2::XMLElement* BigMarker = GetNodeByName(root,"BigMarker");
        tinyxml2::XMLElement* endSendCmd = GetNodeByName(root,"EndSendCmd");
        const char *s_model_id = xmlModel_id->GetText();
        model_id = hex_str_to_in(s_model_id);
        cout<<"model_id is 0x"<<hex<<model_id<<" str is "<<s_model_id<<endl;
        //修改小备注
        BigMarker->SetText(remark.c_str());
        //修改总版本号
        version->SetText(ss_versin);
        
        tinyxml2::XMLElement* commond = GetNodeByName(endSendCmd,"CommandConfig");
        while(commond)
        {
            tinyxml2::XMLElement *cmd_name = GetNodeByName(commond,"CmdName");
            if(cmd_name)
            {
                if(strcmp(cmd_name->GetText(),"OverallVersionAndRemark")==0)
                {
                    tinyxml2::XMLElement *cmd_data = GetNodeByName(commond,"Data");
                    cmd_data->SetText(over_and_remark.str().c_str());
                    cout<<"strcmp is ok"<<endl;
                    break;
                }
            }
            commond = commond->NextSiblingElement();
        }

        tinyxml2::XMLElement* FileInfo = GetNodeByName(root,"FileInfo");
        //需要处理xml里边所有的文件信息
        while(FileInfo)
        {
            //修改版本号
            tinyxml2::XMLElement *file_version = GetNodeByName(FileInfo,"Version");
            file_version->SetText(ss_versin);
            //修改小备注
            tinyxml2::XMLElement *file_remark = GetNodeByName(FileInfo,"Remark");
            file_remark->SetText(remark.c_str());
            tinyxml2::XMLElement *file_desk_name = GetNodeByName(FileInfo,"FileName");
            string desk_filename = file_desk_name->GetText();
            cout<<"file name is "<<desk_filename<<endl;

            FileInfo = FileInfo->NextSiblingElement();
        }
        doc.SaveFile(xml_save.c_str());
    }
    int file_dell()
    {
        //获取源文件和目标文件信息
        tinyxml2::XMLDocument file;
        if(file.LoadFile(xml_file_cfg.c_str()) != 0)
        {
            cout<<"xml config read error "<<xml_file_cfg<<endl;
            return -1;
        }
        else
        {
            tinyxml2::XMLElement *root_file = file.RootElement();
            tinyxml2::XMLElement *element_remark = GetNodeByName(root_file,"REMARK");
            remark =  element_remark->GetText() + remark;    //获取remark信息
            tinyxml2::XMLElement *element_file = GetNodeByName(root_file,"File");
            while(element_file)
            {
                tinyxml2::XMLElement *temp = GetNodeByName(element_file,"src");
                if(temp)
                {
                    //此处的路径文件需要加上路径
                    file_source file_temp;
                    file_temp.file_name = src + "/" + temp->GetText();
                    temp = GetNodeByName(element_file,"desk");
                    file_temp.desk_name = desk + "/" +temp->GetText();
                    v_file.push_back(file_temp);
                }
                element_file = element_file->NextSiblingElement();
            }

            //校验输出文件夹是否存在，若不存在，则进行创建
            char cmd[512];
            if(access(this->desk.c_str(),F_OK))
            {
                cout<<"path is no exist"<<endl;
                memset(cmd,0,sizeof(cmd));
                sprintf(cmd,"mkdir -p %s",this->desk.c_str());
                system(cmd);
            }
        }
        return 0;
    }
    //文件打包
    void file_encrption()
    {
        //锁所有文件进行加密
        cout<<"file count is "<<v_file.size()<<endl;
        for(vector<file_source>::iterator it = v_file.begin();it!=v_file.end();it++)
        {
            cout<<"encrption src is "<<it->file_name<<" desk is "<<it->desk_name<<endl;
            //先配置文件
            config_file(*it,remark,ver,model_id);
            //进行加密
            SaveToDesk();
        }
    }

public:
    //配置源文件路径和目标文件路径 备注信息  版本号 
    void config(string src,string desk,string remark,int ver)
    {
        this->src = src;
        this->desk = desk;
        this->remark = remark;
        this->ver = ver;
        this->xml_file_cfg = this->src + "/file.xml";
        this->xml_cfg = this->src + "/Config.xml";
        this->xml_save = this->desk + "/Config.xml";
        cout<<"this->src "<<this->src<<endl;
        cout<<"tthis->desk "<<this->desk<<endl;
        cout<<"this->remark "<<this->remark<<endl;
        cout<<"this->ver "<<this->ver<<endl;
        cout<<"this->xml_file_cfg "<<this->xml_file_cfg<<endl;
        cout<<"this->xml_save "<<this->xml_save<<endl;
    }
    //打包
    int pack()
    {
        //判断路径是否有效
        if(file_dell()<0)
        {
            cout<<"file_dell error"<<endl;
            return -1;
        }
        config_xml();
        file_encrption();
    }
};

static vector<string> strSplit(string srcStr, const string& delim)
{
    size_t pos = 0;
    vector<string> vec;
    pos = srcStr.find(delim.c_str());
    while(string::npos != pos)
    {
        string temp = srcStr.substr(0, pos);
        vec.push_back(temp);
        srcStr = srcStr.substr(pos+1);
        pos = srcStr.find(delim.c_str());
    }
    vec.push_back(srcStr);
    return vec;
}

struct pthread_data{
    string src;
    string desk;
    string remark;
    int ver;
};

void* pthread_pack(void* args)
{
    if(args==NULL)
    {
        cout<<"args is NULL"<<endl;
        return 0;
    }
    struct pthread_data * data = (struct pthread_data *)args;
    Bale *pPack = new Bale;
    pPack->config(data->src,data->desk,data->remark,data->ver);
    pPack->pack();
    cout<<"argc pack is ok"<<endl;
    return 0;
}

int main(int argc,char **argv)
{
    cout<<"start pack "<<endl;
    cout<<"argc is "<<argc<<endl;
    string base_src = "./source_file";
    string base_desk = "./";

    vector<string> files;
    getFiles(base_src,files);
    cout<<"0:all pack"<<endl;
    for(int i = 0;i < files.size();i++)
    {
        cout<<i+1<<":"<<files[i]<<endl;
    }
    string s_card;
    string s_brief;
    string s_ver;
    cout<<"please input card  eg 0 all card"<<endl;
    getline(cin,s_card);
    int pack_type = 1;  //打包类型  默认单卡打包
    vector<string> groupStrs = strSplit(s_card," ");
    for(vector<string>::iterator it = groupStrs.begin();it != groupStrs.end();it++)
    {
        //如果检测到有 0 说明需要全部打包
        if(atoi(it->c_str()) == 0)
        {
            pack_type = 0;
            break;
        }
    }
    // int card = atoi(groupStrs[0].c_str());
    // if(card >= files.size()+1)
    // {
    //     cout<<"card "<<card<<" is invaild "<<endl;
    //     return 0;
    // }
    cout<<"please input brief  eg V2.0.0.0.C1"<<endl;
    getline(cin,s_brief);

    cout<<"please input version eg:1000"<<endl;
    getline(cin,s_ver);
    uint32_t n_ver = atoi(s_ver.c_str());
    if(n_ver>9999)
        n_ver = 9999;
    
    //单卡打包
    if(pack_type)
    {
        int card;
        for(vector<string>::iterator it = groupStrs.begin();it != groupStrs.end();it++)
        {
            card = atoi(it->c_str());
            if(card >= files.size()+1 || card == 0)
            {
                cout<<"card "<<card<<"is invaild ";
                continue;
            }
            card--;
            Bale pack_card;
            //根据获取到的文件夹列表来配置完整的文件路径
            string finaly_src = base_src + "/" + files[card];
            string finely_desk = base_desk + "/" + files[card];
            pack_card.config(finaly_src,finely_desk,s_brief,n_ver);
            //是否可以多线程处理
            pack_card.pack();
        }
    }
    else
    {
        if(argc == 2)
        {
            pthread_t tids[files.size()];
            Bale pack_card[files.size()];
        
            int pi=0;
            for(vector<string>::iterator it = files.begin();it != files.end();it++)
            {
                //根据获取到的文件夹列表来配置完整的文件路径
                string finaly_src = base_src + "/" + *it;
                string finely_desk = base_desk + "/" + *it;

                struct pthread_data pdata;
                pdata.desk = finely_desk;
                pdata.src = finaly_src;
                pdata.remark = s_brief;
                pdata.ver = n_ver;
                //是否可以多线程处理
                pthread_create(&tids[pi], NULL, pthread_pack, &pdata);
                //加一个延时是为了等新开的线程将数据 pdata数据处理完成
                sleep(1);
                pi++;
            }
            pthread_exit(NULL);
        }
        else
        {
            for(vector<string>::iterator it = files.begin();it != files.end();it++)
            {
                Bale pack_card;
                //根据获取到的文件夹列表来配置完整的文件路径
                string finaly_src = base_src + "/" + *it;
                string finely_desk = base_desk + "/" + *it;
                pack_card.config(finaly_src,finely_desk,s_brief,n_ver);
                //是否可以多线程处理
                pack_card.pack();
            }
        }
    }
    //f_mcu.Decrpt();   //解密
    return 0;
}
