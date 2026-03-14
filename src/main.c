#include <stdio.h>
#include <string.h>
#include "common/user_manager.h"

int main(void) {
    int  choice;
    char username[50];

    printf("=================================\n");
    printf("   one-on-one chat — step 1      \n");
    printf("=================================\n");

    /* keep showing the menu until user chooses to quit */
    while (1) {
        printf("\n  1. register a user\n");
        printf("  2. list all users\n");
        printf("  3. quit\n");
        printf("\n  choice: ");

        scanf("%d", &choice);

        /* clear leftover newline from input buffer */
        while (getchar() != '\n');

        switch (choice) {
            case 1:
                printf("  enter username: ");
                fgets(username, sizeof(username), stdin);
                /* we do this to remove the newline that gets inlcued */
                username[strcspn(username, "\n")] = 0;
                register_user(username);
                break;

            case 2:
                list_users();
                break;

            case 3:
                printf("  goodbye.\n");
                return 0;

            default:
                printf("  [!] invalid choice.\n");
        }
    }

    return 0;
}