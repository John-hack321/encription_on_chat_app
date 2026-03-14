#include <stdio.h>
#include <string.h>
#include "user_manager.h"

/*
 * register_user() justa a simple implementation for now we will make it look better soon
 * Saves a new user to data/users.txt
 * Returns 0 on success, -1 if user already exists
 * 
 * steps 
 * 1) check if user exits
 */
int register_user(const char *username) {
    char line[64];
    char stored_name[50];
    char stored_status[10];

    /* check if the user exists  */
    FILE *fp = fopen(USERS_FILE, "r"); // we create a pointer to the USERS_FILE  first
    if (fp != NULL) { // if file is not present then it means that no user exists
        while (fgets(line, sizeof(line), fp) != NULL) {
            /* each line looks like:  alice:ONLINE  */
            sscanf(line, "%49[^:]:%9s", stored_name, stored_status);
            if (strcmp(stored_name, username) == 0) {
                printf("  [!] username '%s' is already taken.\n", username);
                fclose(fp);
                return -1;
            }
        }
        fclose(fp);
    }

    /* --- step 2: append new user to the file --- */
    fp = fopen(USERS_FILE, "a");
    if (fp == NULL) {
        printf("  [!] error: could not open %s for writing.\n", USERS_FILE);
        return -1;
    }

    fprintf(fp, "%s:ONLINE\n", username);
    fclose(fp);

    printf("  [+] user '%s' registered successfully.\n", username);
    return 0;
}

/*
 * list_users()
 * ------------
 * Reads data/users.txt and prints every registered user
 */
void list_users(void) {
    char line[64];
    int  count = 0;

    FILE *fp = fopen(USERS_FILE, "r");
    if (fp == NULL) {
        printf("  [!] no users registered yet.\n");
        return;
    }

    printf("\n  --- registered users ---\n");
    while (fgets(line, sizeof(line), fp) != NULL) {
        /* strip the newline character at the end of each line */
        line[strcspn(line, "\n")] = 0;
        printf("  %s\n", line);
        count++;
    }

    if (count == 0) {
        printf("  (none)\n");
    }
    printf("  ------------------------\n");

    fclose(fp);
}