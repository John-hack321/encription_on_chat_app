// this is like the table of contents it tells about what exits in our project without even implementing it in the first place, it acts like a header file for our usage

#ifndef USER_MANAGER_H
#define USER_MANAGER_H

/* for memory purposes we will have to define teh max number of users our program can hold at a time */
#define MAX_USERS 10

/* path to the file where we are saving our suer data */
#define USERS_FILE "data/users.txt"

/* a User has a name and a status (ONLINE or OFFLINE) */
typedef struct {
    char username[50];
    char status[10];
} User;

/* function declarations — implemented in user_manager.c */
int  register_user(const char *username);
void list_users(void);

#endif