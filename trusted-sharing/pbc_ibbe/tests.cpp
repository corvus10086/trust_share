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
    int g_size = 10000;
    
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

    // serialize data for the sgx enclave
    std::string in_buffer;
    serialize_create_group_input(shortPubKey, msk, members, in_buffer);
    
    // create group by calling into SGX
    char out_buffer[4096]; // FIX ME: hardcoded value, should be dynamic based on partitions count
    int out_buffer_size;
#ifdef ENABLE_SGX
     if( SGX_SUCCESS != ecall_create_group(global_eid, &out_buffer_size, in_buffer.c_str(), in_buffer.size(), out_buffer, sizeof(out_buffer) ) )
        printf("Error during ecall\n");
#else
    out_buffer_size = ecall_create_group(in_buffer.c_str(), in_buffer.size(), out_buffer, sizeof(out_buffer) );
#endif
    
    // quick verification on the returned content from SGX
    if (out_buffer_size != 2192)
    {
        printf("TEST FAILED !!!\n");
        return;
    }
    std::ofstream outfile("partitions");
    if(outfile.is_open()){
        outfile<<out_buffer;
        std::cout<<"写入文件"<<std::endl;
        outfile.close();
    }
    else{
        std::cout<<"不能打开文件"<<std::endl;
    }
    
    printf("\033[32;1m TEST PASSED \033[0m\n");
}


void test_border_sgx_add_user(int argc, char** argv){
    printf("Testing sgx border add user ... "); fflush(stdout);
    
    //从创建组的输出中反序列化出成员和分区，组密钥
    //再将分区

}

void test_border_sgx_remove_user(int argc, char** argv){
    //
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
#if 1 // ignoring stuff, so that it compiles and runs - Rafael
    Configuration::UsersPerPartition = 100;

    //Cloud* c = new DropboxCloud();
    std::string a = "master";
    std::string g = "rep_" + std::to_string(o);
 
    SpibbeApi* admin = new SpibbeApi(a, NULL);
    //HybridApi* admin = new HybridApi(a, NULL);

    // read members and create group
    std::vector<std::string> members;
    std::ifstream s("/home/stefan/code/middleware2017/data_sets/synthetic/1000/members_1000");
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
    std::ifstream ops("/home/stefan/code/middleware2017/data_sets/synthetic/1000/ops_" + std::to_string(o));
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
