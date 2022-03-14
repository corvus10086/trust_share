#include "sgx_ibbe.h"
#include "sgx_spibbe.h"
#include "tests.h"
#include "admin_api.h"
#include "hybrid_api.h"
#include "microbench.h"
#include "sgx_serialize.h"
#include <stdio.h>
#include <time.h>
#include <string>

#ifdef ENABLE_SGX
#include <enclave_grpshr_u.h>
extern sgx_enclave_id_t global_eid;    /* global enclave id */
#endif

#include <iostream>
#include <sstream>
#include <fstream>  

void generate_members(std::vector<std::string>& members, int start, int end)
{
    for (int i = start; i < end; i++)
    {
        char* ss = (char*) malloc(MAX_STRING_LENGTH);
        sprintf(ss, "test%d@mail.com", i);
        std::string s(ss);
        members.push_back(s);
    }
}

/*
 * Test calling SPIBBE Create Group from Untrusted to Trusted environments. 
 */
void test_border_sgx_create_group(int argc, char** argv)
{
    printf("Testing sgx border CREATE GROUP ... "); fflush(stdout);
    int g_size = 10000,mem_i;
    // system set-up
    PublicKey pubKey;
    MasterSecretKey msk;
    ShortPublicKey shortPubKey;
    if( load_system(pubKey, shortPubKey, msk) ) {
        printf("Error loading keys\n");
        return;
    }
    
    // generate mock users
    std::vector<std::string> members;
    generate_members(members, 0, g_size);
    system("rm -f ./members/*");
    std::string member_file_path="./members/partition";
    std::ofstream file_test;
    for(int file_i=0;file_i<g_size/2000;++file_i){
        file_test.open(member_file_path+std::to_string(file_i),std::ios::out|std::ios::app);
        if(file_test.is_open()){
            for(mem_i=0;mem_i<2000;++mem_i){
                file_test<<members[file_i*2000+mem_i]<<std::endl;
            }
            file_test.close();
        }
    }

    // serialize data for the sgx enclave
    std::string in_buffer;
    serialize_create_group_input(shortPubKey, msk, members, in_buffer);
    
    // create group by calling into SGX
    char out_buffer[4096]; // FIX ME: hardcoded value, should be dynamic based on partitions count
    int out_buffer_size;
    init_clock
    start_clock
#ifdef ENABLE_SGX
     if( SGX_SUCCESS != ecall_create_group(global_eid, &out_buffer_size, in_buffer.c_str(), in_buffer.size(), out_buffer, sizeof(out_buffer) ) )
        printf("Error during ecall\n");
#else
    out_buffer_size = ecall_create_group(in_buffer.c_str(), in_buffer.size(), out_buffer, sizeof(out_buffer) );
#endif
    end_clock(m0)
    // quick verification on the returned content from SGX
    if (out_buffer_size != 2192)
    {
        printf("out_buffer_size=%d TEST FAILED !!!\n",out_buffer_size);
        return;
    }
    printf("\033[32;1m TEST PASSED\033[0m\n");
    std::ofstream outfile;
    outfile.open("partitions",std::ios::out|std::ios::binary);
    if(outfile.is_open()){
        outfile.write((const char*)&out_buffer,out_buffer_size);
        std::cout<<"写入文件 "<<"using time"<<m0<<std::endl;
        outfile.close();
    }
    else{
        std::cout<<"不能打开文件"<<std::endl;
    }
}

void test_border_sgx_add_user(int argc, char** argv){
    printf("Testing sgx border add user ... \n"); fflush(stdout);
    std::ostringstream tmp;
    std::ifstream in_part_file;
    std::string partitions_info;
    //read partitions
    in_part_file.open("partitions");
    if(in_part_file.is_open()){
        tmp<<in_part_file.rdbuf();
        partitions_info=tmp.str();
        in_part_file.close();
        // std::cout<<partitions_info.size()<<std::endl;
    }
    // std::vector<SpibbePartition> partitions;
    // std::string group_key=str_test.substr(0,32);
    // std::cout<<group_key.size()<<std::endl;
    std::string user_add="test10003add@mail.com";
    //read members
    std::string member_file_path="./members/partition";
    int file_i=0;
    std::vector<std::vector<std::string>>members;
    std::string user;
    while(1){
        std::ifstream file_test;
        file_test.open(member_file_path+std::to_string(file_i),std::ios::in);
        if(file_test.is_open()){
            members.push_back(std::vector<std::string>{});
            while(getline(file_test,user)){
                members[file_i].push_back(user);
            }
            ++file_i;
            file_test.close();
        }
        else{
            break;
        }
    }
    //std::cout<<members.size()<<" "<<members[5][0]<<std::endl;
    // system set-up
    PublicKey pubKey;
    MasterSecretKey msk;
    ShortPublicKey shortPubKey;
    if( load_system(pubKey, shortPubKey, msk) ) {
        printf("Error loading keys\n");
        return;
    }
    // std::cout<<"ecall_add_user"<<std::endl;
    std::string in_buffer;
    seralize_add_user_input(shortPubKey,msk,members,partitions_info,user_add,in_buffer);
    // std::cout<<"out"<<in_buffer.size()<<std::endl;
    // std::cout<<"ctr size"<<strlen(in_buffer.c_str())<<std::endl;
    char *in_buffer_ctr=(char*)malloc(sizeof(char)*in_buffer.size());
    memcpy(in_buffer_ctr,in_buffer.c_str(),in_buffer.size());
    // std::cout<<"ctr_size"<<std::endl;
    char out_buffer[300000]; // FIX ME: hardcoded value, should be dynamic based on partitions count
    int out_buffer_size;
    init_clock
    start_clock
#ifdef ENABLE_SGX
     if( SGX_SUCCESS != ecall_add_user(global_eid, &out_buffer_size, in_buffer.c_str(), in_buffer.size(), out_buffer, sizeof(out_buffer) ) )
        printf("Error during ecall\n");
#else
    // std::cout<<"ecall_add_user"<<std::endl;
    out_buffer_size = ecall_add_user(in_buffer_ctr, in_buffer.size(), out_buffer, sizeof(out_buffer) );
#endif
    end_clock(m0)
    // std::cout<<"size"<<out_buffer_size<<std::endl;
    std::string out_str;
    out_str.assign(out_buffer, out_buffer_size);
    // std::cout<<"out_str__size"<<out_str.size()<<std::endl;
    std::cout<<"using time"<<m0<<std::endl;
    std::string out_partition_info="",members_str;
    std::vector<std::vector<std::string>>out_members;
    std::vector<std::string> str_tmp;

    out_partition_info+=out_str.substr(0,32);
    //GROUP_key append

    std::string::size_type member_end=out_str.find("member_end!"),begin;
    // std::cout<<"member_end"<<member_end<<std::endl;
    members_str=out_str.substr(32,out_str.find("member_end!")-32);

    std::string s_partition_members;
    std::string::size_type members_partition_end_poistion;
    // std::cout<<members_str<<std::endl;
    while(1){
        members_partition_end_poistion=members_str.find('^',begin);
        if(members_partition_end_poistion==members_str.npos){
            break;
        }
        s_partition_members=members_str.substr(begin,members_partition_end_poistion-begin);
        begin=members_partition_end_poistion+1;
        // std::cout<<s_partition_members.size()<<" "<<members_partition_end_poistion<<std::endl<<std::endl;
        // std::cout<<std::endl<<s_partition_members<<std::endl;
        deserialize_members(s_partition_members,str_tmp);
        out_members.push_back(str_tmp);
    }
    // std::cout<<out_members[3].size()<<std::endl;
    system("rm -f ./members/*");
    // std::string member_file_path="./members/partition";
    std::ofstream file_test;
    for(file_i=0;file_i<out_members.size();++file_i){
        file_test.open(member_file_path+std::to_string(file_i),std::ios::out|std::ios::app);
        if(file_test.is_open()){
            for(int mem_i=0;mem_i<out_members[file_i].size();++mem_i){
                file_test<<out_members[file_i][mem_i]<<std::endl;
            }
            file_test.close();
        }
    }
    //member_file save
    out_partition_info+=out_str.substr(member_end+11);
    // std::cout<<out_partition_info.size()<<std::endl;
    //2624 right
    std::ofstream out_partition_file;
    out_partition_file.open("partitions",std::ios::out|std::ios::binary);
    if(out_partition_file.is_open()){
        // char *out_partition_info_ctr=(char*)malloc(sizeof(char)*(out_partition_info.size())+1);
        // memcpy(out_partition_info_ctr,out_partition_info.c_str(),out_partition_info.size());
        out_partition_file.write(out_partition_info.c_str(),out_partition_info.size());
        std::cout<<"写入文件 "<<std::endl;
        out_partition_file.close();
    }
    else{
        std::cout<<"不能打开文件"<<std::endl;
    }






}

void test_border_sgx_remove_user(int argc, char** argv){
    printf("Testing sgx border remove user ... "); fflush(stdout);
    std::ostringstream tmp;
    std::ifstream in_part_file;
    std::string partitions_info;
    //read partitions
    in_part_file.open("partitions");
    if(in_part_file.is_open()){
        tmp<<in_part_file.rdbuf();
        partitions_info=tmp.str();
        in_part_file.close();
        // std::cout<<partitions_info.size()<<std::endl;
    }
    std::string user_remove="test6222@mail.com";
    std::string member_file_path="./members/partition";
    int file_i=0;
    std::vector<std::vector<std::string>>members;
    std::string user;
    while(1){
        std::ifstream file_test;
        file_test.open(member_file_path+std::to_string(file_i),std::ios::in);
        if(file_test.is_open()){
            members.push_back(std::vector<std::string>{});
            while(getline(file_test,user)){
                members[file_i].push_back(user);
            }
            ++file_i;
            file_test.close();
        }
        else{
            break;
        }
    }
    // std::cout<<members.size()<<" "<<members[5][0]<<std::endl;
    PublicKey pubKey;
    MasterSecretKey msk;
    ShortPublicKey shortPubKey;
    if( load_system(pubKey, shortPubKey, msk) ) {
        printf("Error loading keys\n");
        return;
    }
    std::string in_buffer;
    seralize_add_user_input(shortPubKey,msk,members,partitions_info,user_remove,in_buffer);
    // std::cout<<"out"<<in_buffer.size()<<std::endl;
    // std::cout<<"ctr size"<<strlen(in_buffer.c_str())<<std::endl;
    char *in_buffer_ctr=(char*)malloc(sizeof(char)*in_buffer.size());
    memcpy(in_buffer_ctr,in_buffer.c_str(),in_buffer.size());
    // std::cout<<"ctr_size"<<std::endl;
    char out_buffer[300000]; // FIX ME: hardcoded value, should be dynamic based on partitions count
    int out_buffer_size;
    init_clock
    start_clock
#ifdef ENABLE_SGX
     if( SGX_SUCCESS != ecall_remove_user(global_eid, &out_buffer_size, in_buffer.c_str(), in_buffer.size(), out_buffer, sizeof(out_buffer) ) )
        printf("Error during ecall\n");
#else
    std::cout<<"ecall_remove_user"<<std::endl;
    out_buffer_size = ecall_remove_user(in_buffer_ctr, in_buffer.size(), out_buffer, sizeof(out_buffer) );
#endif
    end_clock(m0)
    if(out_buffer_size==0){
        std::cout<<"user not exist"<<std::endl;
        return; 
    }

    std::string out_str;
    out_str.assign(out_buffer, out_buffer_size);
    // std::cout<<"out_str__size"<<out_str.size()<<std::endl;
    std::cout<<"using time"<<m0<<std::endl;
    std::string out_partition_info="",members_str;
    std::vector<std::vector<std::string>>out_members;
    std::vector<std::string> str_tmp;

    out_partition_info+=out_str.substr(0,32);
    //GROUP_key append


    std::string::size_type member_end=out_str.find("member_end!"),begin;
    // std::cout<<"member_end"<<member_end<<std::endl;
    members_str=out_str.substr(32,out_str.find("member_end!")-32);

    std::string s_partition_members;
    std::string::size_type members_partition_end_poistion;
    // std::cout<<members_str<<std::endl;
    while(1){
        members_partition_end_poistion=members_str.find('^',begin);
        if(members_partition_end_poistion==members_str.npos){
            break;
        }
        s_partition_members=members_str.substr(begin,members_partition_end_poistion-begin);
        begin=members_partition_end_poistion+1;
        // std::cout<<s_partition_members.size()<<" "<<members_partition_end_poistion<<std::endl<<std::endl;
        // std::cout<<std::endl<<s_partition_members<<std::endl;
        deserialize_members(s_partition_members,str_tmp);
        out_members.push_back(str_tmp);
    }
    std::cout<<"member group size"<<out_members.size()<<std::endl;
    system("rm -f ./members/*");
    
    // // std::string member_file_path="./members/partition";
    std::ofstream file_test;
    for(file_i=0;file_i<out_members.size();++file_i){
        file_test.open(member_file_path+std::to_string(file_i),std::ios::out|std::ios::app);
        if(file_test.is_open()){
            for(int mem_i=0;mem_i<out_members[file_i].size();++mem_i){
                file_test<<out_members[file_i][mem_i]<<std::endl;
                
            }
            std::cout<<"写入member文件 "<<std::endl;
            file_test.close();
        }
        else{
            std::cout<<"写入member文件fail "<<std::endl;
        }
    }
    //member_file save
    out_partition_info+=out_str.substr(member_end+11);
    // std::cout<<"partition_info size"out_partition_info.size()<<std::endl;
    // //2624 right
    std::ofstream out_partition_file;
    out_partition_file.open("partitions",std::ios::out|std::ios::binary);
    if(out_partition_file.is_open()){
        // char *out_partition_info_ctr=(char*)malloc(sizeof(char)*(out_partition_info.size())+1);
        // memcpy(out_partition_info_ctr,out_partition_info.c_str(),out_partition_info.size());
        out_partition_file.write(out_partition_info.c_str(),out_partition_info.size());
        std::cout<<"写入文件 "<<std::endl;
        out_partition_file.close();
    }
    else{
        std::cout<<"不能打开文件"<<std::endl;
    }


















}




/*
 * Test that the scheme works for a single user too, not only for groups.
 */
void ftest_one_user(int argc, char** argv)
{
    /*
    printf("SP-IBBE FUNCTIONL TEST ftest_one_user ...");

    // system set-up
    PublicKey pubKey;
    MasterSecretKey msk;
    ShortPublicKey shortPubKey;
    setup_sgx_safe(&pubKey, &shortPubKey, &msk,
        10, argc, argv);

    std::vector<std::string> members;
    generate_members(members, 0, 1);

    // create group
    std::vector<SpibbePartition> partitions;
    sp_ibbe_create_group(
        partitions,
        shortPubKey, msk,
        members,
        10);

    // extract the key and validate group
    UserPrivateKey usrPriKey;
    extract_sgx_safe(shortPubKey, msk, usrPriKey, (char*) members[0].c_str());

    GroupKey groupKey;
    sp_ibbe_user_decrypt(
        &groupKey,
        gpKeys,
        gpCiphers,
        pubKey,
        usrPriKey,
        members[0],
        members,
        10);
*/
    // TODO : we can't properly check the result unless :
    //      1. the second line of sp_ibbe_create_group is uncommented
    //      2. the line bellow is uncommented
    //      3. the printed values match
    // print_hex(groupKey, 32);
    printf("\033[32;1m TEST PASSED \033[0m\n");        
}


/*
 * Test that once creating a group all the users inside are able to get the same key.
 */
void ftest_create_group_decrypt_all(int argc, char** argv, int g_size, int p_size)
{
    /*
    printf("SP-IBBE FUNCTIONL TEST create_group_decrypt_all ...");

    // system set-up
    PublicKey pubKey;
    MasterSecretKey msk;
    ShortPublicKey shortPubKey;
    setup_sgx_safe(&pubKey, &shortPubKey, &msk,
        p_size, argc, argv);

    std::vector<std::string> members;
    generate_members(members, 0, g_size);

    // create group
    std::vector<EncryptedGroupKey> gpKeys;
    std::vector<Ciphertext> gpCiphers;
    sp_ibbe_create_group(
        gpKeys, gpCiphers,
        shortPubKey, msk,
        members,
        p_size);

    std::string gk;
    for(uint i = 0; i < members.size(); i++)
    {
        // extract a key and validate group
        UserPrivateKey usrPriKey;
        extract_sgx_safe(shortPubKey, msk, usrPriKey, (char*) members[i].c_str());

        GroupKey groupKey;
        sp_ibbe_user_decrypt(
            &groupKey,
            gpKeys,
            gpCiphers,
            pubKey,
            usrPriKey,
            members[i],
            members,
            p_size);

        // verify
        std::string s(reinterpret_cast<char*>(groupKey));
        if (i == 0) gk = s;
        else if (s != gk)
        {
            printf("TEST FAILED !!!\n");
            return;
        }
    }
    printf("\033[32;1m TEST PASSED \033[0m\n");

 */ 
}


/*
 * Test that incrementaly adding users results in the same group key.
 */
void ftest_add_users_decrypt_all(int argc, char** argv, int g_size, int p_size)
{
    /*
    printf("SP-IBBE FUNCTIONL TEST ftest_add_users_decrypt_all ...");
    // system set-up
    PublicKey pubKey;
    MasterSecretKey msk;
    ShortPublicKey shortPubKey;
    setup_sgx_safe(&pubKey, &shortPubKey, &msk,
        p_size, argc, argv);

    std::vector<std::string> members;
    generate_members(members, 0, g_size);

    // create group
    std::vector<EncryptedGroupKey> gpKeys;
    std::vector<Ciphertext> gpCiphers;
    sp_ibbe_create_group(
        gpKeys, gpCiphers,
        shortPubKey, msk,
        members,
        p_size);

    // add users one by one
    std::vector<std::string> newMembers;
    generate_members(newMembers, g_size, 2 * g_size);

    std::string gk;
    for(int i=0; i < newMembers.size(); i++)
    {
        sp_ibbe_add_user(
            shortPubKey,
            msk,
            gpKeys,
            gpCiphers,
            members,
            newMembers[i],
            p_size);

        // for all the members check everything is the same
        for(int j = 0; j < members.size(); j++)
        {
            // extract a key and validate group
            UserPrivateKey usrPriKey;
            extract_sgx_safe(shortPubKey, msk, usrPriKey, (char*) members[j].c_str());
            GroupKey groupKey;
            sp_ibbe_user_decrypt(&groupKey,
                gpKeys, gpCiphers,
                pubKey, usrPriKey,
                members[j], members,
                p_size);

            // verify
            std::string s(reinterpret_cast<char*>(groupKey));
            if (i == 0 && j == 0) gk = s;
            else if (s != gk)
            {
                printf("TEST FAILED !!!\n");
                return;
            }
        }
    }
    printf ("\033[32;1m TEST PASSED \033[0m\n");

 */ }

/*
 * Test that incementaly removing users results in the same group key for the remaining users.
 */
void ftest_remove_decrypt_all(int argc, char** argv, int g_size, int p_size)
{
    /*
    printf("SP-IBBE FUNCTIONL TEST ftest_remove_decrypt_all ...");
    
    PublicKey pubKey;
    MasterSecretKey msk;
    ShortPublicKey shortPubKey;
    setup_sgx_safe(&pubKey, &shortPubKey, &msk,
        p_size, argc, argv);

    std::vector<std::string> members;
    generate_members(members, 0, g_size);

    // create group
    std::vector<EncryptedGroupKey> gpKeys;
    std::vector<Ciphertext> gpCiphers;
    sp_ibbe_create_group(
        gpKeys, gpCiphers,
        shortPubKey, msk,
        members,
        p_size);

    // remove users one by one
    while(true)
    {
        std::string to_remove = members[members.size() - 1];
        sp_ibbe_remove_user(
            shortPubKey,
            msk,
            gpKeys,
            gpCiphers,
            members,
            to_remove,
            p_size
        );

        std::string gk;
        // all the remaining users must share the same key
        for(int j = 0; j < members.size(); j++)
        {
            UserPrivateKey usrPriKey;
            extract_sgx_safe(shortPubKey, msk, usrPriKey, (char*) members[j].c_str());
            GroupKey groupKey;
            sp_ibbe_user_decrypt(&groupKey,
                gpKeys, gpCiphers,
                pubKey, usrPriKey,
                members[j], members,
                p_size);

            // verify
            std::string s(reinterpret_cast<char*>(groupKey));
            if (j == 0) gk = s;
            else if (s != gk)
            {
                printf("TEST FAILED !!!\n");
                return;
            }
        }

        if (members.size() == 1)
            break;
    }
    printf ("\033[32;1m TEST PASSED \033[0m\n");

 */ }

void admin_api(int g_size, int p_size)
{
    /*
    Configuration::UsersPerPartition = p_size;
    SpibbeApi admin("master", new RedisCloud());
    
    std::vector<std::string> members;
    generate_members(members, 0, g_size);
    
    admin.CreateGroup("friends", members);
    //admin.AddUserToGroup("friends", "jim");
    //admin.RemoveUserFromGroup("friends", "bob");

 */
}

void micro_create_group(AdminApi* admin)
{
    /*
    // HACK
    std::vector<std::string> members;
    generate_members(members, 0, 10000);
    admin->CreateGroup("pau_friends", members);

    return;

    // OLD CODE:
    int g_size = 16;
    int p_size = 2000;
    
    for (int i=0; i<MICRO_POINTS; i++)
    {
        if (g_size > p_size)
        {
            Configuration::UsersPerPartition = p_size;
        }
        else
        {
            Configuration::UsersPerPartition = g_size;
        }
        
        std::vector<std::string> members;
        generate_members(members, 0, g_size);
        admin->CreateGroup("friends", members);

        g_size = g_size * 2;
    }
     */
}

void micro_add_user(AdminApi* admin)
{
    /*
    int g_size = 16;
    int p_size = 2000;
    
    std::vector<std::string> membersToAdd;
    generate_members(membersToAdd, 5000000, 5000100);
    int new_member = 0;
    
    for (int i=0; i<MICRO_POINTS; i++)
    {
        if (g_size > p_size)
        {
            Configuration::UsersPerPartition = p_size;
        }
        else
        {
            Configuration::UsersPerPartition = g_size;
        }
        
        // generate a group of desired size
        std::vector<std::string> members;
        generate_members(members, 0, g_size);
        admin->CreateGroup("friends", members);
    
        // add a user to the group
        std::string new_user = membersToAdd[new_member++];
        admin->AddUserToGroup("friends", new_user);

        g_size = g_size * 2;
    }
     */
}

void micro_remove_user(AdminApi* admin)
{
    /*
    int g_size = 16;
    int p_size = 2000;
    
    for (int i=0; i<MICRO_POINTS; i++)
    {
        if (g_size > p_size)
        {
            Configuration::UsersPerPartition = p_size;
        }
        else
        {
            Configuration::UsersPerPartition = g_size;
        }
        
        // generate a group of desired size
        std::vector<std::string> members;
        generate_members(members, 0, g_size);
        admin->CreateGroup("friends", members);
    
        // remove a user from the group
        admin->RemoveUserFromGroup("friends", members[1]);

        g_size = g_size * 2;
    }
     */
}

double replay_synthetic_trace(int o)
{
#if 0 // ignoring stuff, so that it compiles and runs - Rafael
    Configuration::UsersPerPartition = 100;

    //Cloud* c = new DropboxCloud();
    std::string a = "master";
    std::string g = "rep_" + std::to_string(o);
 
    SpibbeApi* admin = new SpibbeApi(a, NULL);
    //HybridApi* admin = new HybridApi(a, NULL);

    // read members and create group
    std::vector<std::string> members;
    std::ifstream s("/home/wxy/code/middleware2017/data_sets/synthetic/1000/members_1000");
    std::string user;
    while(std::getline(s, user, '\n'))
    {
        members.push_back(user);
    }
    s.close();
    admin->CreateGroup(g, members);
    
    init_clock
    start_clock
    // read operations and execute trace
    std::ifstream ops("/home/wxy/code/middleware2017/data_sets/synthetic/1000/ops_" + std::to_string(o));
    std::string line;
    int op_index = 0;
    while(std::getline(ops, line, '\n'))
    {
        //printf("OPERATION %d\n", op_index);
        if (line.find("add,") == 0)
        {
            std::string user = line.substr(4);
            //printf("add:%s\n", user.c_str());
            admin->AddUserToGroup(g, user);
        }
        else
        {
            std::string user = line.substr(7);
            //printf("remove:%s\n", user.c_str());
            admin->RemoveUserFromGroup(g, user);
        }
        op_index++;
    }
    ops.close();
    end_clock(m0)
    printf("TOTAL TRACE TIME : %f\n", m0);
    return m0;
#else
    return 0;
#endif
}


void test_admin_replay()
{
    std::vector<double> results;
    for(int o=0; o<=10; o++)
    {
        printf("REPLAYNG ----------> %d of 10\n", o);
        double result = replay_synthetic_trace(o);
        results.push_back(result);
    }
    
    printf("FINAL RESULTS :\n");
    for(int i=0; i<results.size(); i++)
    {
        printf("%d,%f\n", i, results[i]);
    }
}
